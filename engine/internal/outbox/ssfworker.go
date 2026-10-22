package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/tokens"
)

// Delivery of Security Event Tokens.
//
// A separate drain from back-channel logout, on the same table and with the same
// retry machinery. Separate because the two fail differently: a logout notice
// that fails has one obvious meaning, whereas a receiver that stops accepting
// events is a subscription going quiet -- and a quiet subscription is
// indistinguishable from a peaceful one unless somebody is counting.

// ssfPending is one queued event.
type ssfPending struct {
	id       int64
	attempts int
	StreamID string `json:"stream_id"`
	ClientID string `json:"client_id"`
	Endpoint string `json:"endpoint"`
	Event    string `json:"event"`
	Subject  string `json:"subject"`
	SID      string `json:"sid"`
	Reason   string `json:"reason"`
	// Status is a stream-updated event's new status; empty for any other.
	Status string `json:"status"`
}

// ssfHoldInterval is how often a paused stream's held events are looked at
// again. Resuming the stream releases them at once (store.SetStreamStatus), so
// this bounds only the case nothing told the queue about.
const ssfHoldInterval = time.Minute

// DrainSSF delivers pending security events (RFC 8935 push).
//
// The transaction boundaries are in drainTopic, shared with logout delivery.
// They were NOT shared before, and the cost was immediate: when the logout
// drain's boundary turned out to be wrong -- every HTTP call made with row
// locks held and a database connection checked out -- the fix went into one
// drain and its twin kept the bug. Duplicated mechanism means a correctness fix
// has to be remembered twice, and this is what it looks like when it is not.
//
// What stays here is this topic's policy: how to decode an event, where to send
// it, and what to say when it fails.
func (w *Worker) DrainSSF(ctx context.Context) (int, error) {
	return w.drainTopic(ctx, drainSpec{
		topic: "ssf_event",
		batch: w.batch,
		deliver: func(ctx context.Context, raw []byte) error {
			var p ssfPending
			if err := json.Unmarshal(raw, &p); err != nil {
				return fmt.Errorf("decoding an ssf outbox row: %w", err)
			}
			return w.deliverSSF(ctx, p)
		},
		backoff: backoffFor,
		onFailure: func(raw []byte, attempts int, err error) {
			var p ssfPending
			_ = json.Unmarshal(raw, &p)
			w.log.Info("security event delivery failed", "client_id", p.ClientID,
				"event", p.Event, "attempt", attempts+1, "err", err)
		},
	})
}

func (w *Worker) deliverSSF(ctx context.Context, p ssfPending) error {
	// The stream's status, read at delivery rather than trusted from when the
	// event was queued (SSF 1.0 §8.1.2.1, specs/ssf-1_0.txt:2584-2611). It was
	// read only when queuing, so an event queued a moment before a stream was
	// paused was still sent: "The Transmitter MUST NOT transmit events over the
	// stream" while paused or disabled. A stream-updated event is the exception,
	// because it is the notice of the change and the specification requires it
	// be sent (§8.1.5).
	if p.StreamID != "" {
		status, err := w.streamStatus(ctx, p.StreamID)
		if err != nil {
			return err
		}
		switch {
		case status == "":
			return &droppedError{reason: "stream deleted"}
		case p.Event == ssf.StreamUpdated:
		case status == "paused":
			// "SHOULD hold any events it would have transmitted while paused, and
			// SHOULD transmit them when the stream's status becomes enabled."
			return &heldError{reason: "held: the stream is paused", wait: ssfHoldInterval}
		case status == "disabled":
			// "will not hold any events for later transmission."
			return &droppedError{reason: "stream disabled"}
		}
	}

	// As the issuer of the stream's client's instance (6.12).
	as, err := w.signerFor(ctx, p.ClientID)
	if err != nil {
		return err
	}
	key, err := as.keys.Active(keys.ES256)
	if err != nil {
		// Any active key will do; the receiver resolves it from our JWKS.
		for _, alg := range as.keys.Algorithms() {
			if k, kerr := as.keys.Active(alg); kerr == nil {
				key, err = k, nil
				break
			}
		}
	}
	if err != nil {
		return fmt.Errorf("no signing key available for a security event")
	}

	jti, err := newJTI()
	if err != nil {
		return err
	}
	// EventTime is time.Now() here rather than the revoke time: push delivers
	// within seconds of the event, so the two are the same moment for a receiver's
	// purposes. Poll, which can hand over an event hours later, passes the queued
	// time instead -- see the shared builder.
	var token string
	if p.Event == ssf.StreamUpdated {
		token, err = ssf.MintStreamUpdated(tokens.NewSigner(key), as.issuer, p.ClientID, jti,
			p.StreamID, p.Status, p.Reason, time.Now())
	} else {
		event := ssf.RevocationEvent(as.issuer, p.Subject, p.Reason, time.Now())
		event.Type = p.Event
		token, err = ssf.Mint(tokens.NewSigner(key), as.issuer, p.ClientID, jti, event, time.Now())
	}
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint,
		bytes.NewReader([]byte(token)))
	if err != nil {
		return err
	}
	// RFC 8935 §2.1 fixes this media type. A receiver that checks it -- and they
	// do -- rejects application/json outright.
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	// # Authenticating US to THEM
	//
	// RFC 8935 push delivery expects the transmitter to authenticate to the
	// receiver, normally with a bearer token the receiver issued when the stream
	// was configured. The column for it existed from the first migration, with a
	// comment saying exactly this, and NOTHING EVER SENT IT -- so a receiver that
	// requires the token answered 401, the outbox retried eight times, and the
	// event was parked. Silently, and looking like a receiver outage.
	//
	// Read at delivery time rather than carried in the payload, and a stream with
	// no token still delivers: the SET is signed, so a receiver that chose not to
	// issue one is not made less safe by its absence.
	if tok, terr := w.streamAuthToken(ctx, p.StreamID); terr != nil {
		return terr
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	// 202 is the specified success. 200 is accepted too, because a good number of
	// receivers answer with it and failing them would mean retrying a delivery
	// that already succeeded -- which looks like a broken receiver and is a
	// broken sender.
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the receiver answered %d", resp.StatusCode)
	}
	return nil
}

// streamStatus reads a stream's status; empty when the stream no longer exists.
func (w *Worker) streamStatus(ctx context.Context, streamID string) (string, error) {
	var status string
	err := w.db.QueryRow(ctx,
		`SELECT status FROM core.ssf_streams WHERE id::text = $1`, streamID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading the stream status: %w", err)
	}
	return status, nil
}

// streamAuthToken unseals the bearer token a receiver issued for this stream.
//
// An empty result means the stream has none, which is a valid configuration. A
// token that will not unseal is an error rather than a silent omission: sending
// the event unauthenticated instead would look like it worked.
func (w *Worker) streamAuthToken(ctx context.Context, streamID string) (string, error) {
	if streamID == "" || w.root == nil {
		return "", nil
	}
	var sealed []byte
	err := w.db.QueryRow(ctx,
		`SELECT auth_token FROM core.ssf_streams WHERE id = $1::uuid`, streamID).Scan(&sealed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The stream was deleted after the event was queued. Nothing to
			// authenticate to; let the delivery fail on its own terms.
			return "", nil
		}
		return "", fmt.Errorf("reading the stream auth token: %w", err)
	}
	if len(sealed) == 0 {
		return "", nil
	}
	raw, err := w.root.Open(sealed, "ssf-stream-token")
	if err != nil {
		return "", fmt.Errorf("unsealing the auth token for stream %s: %w", streamID, err)
	}
	return string(raw), nil
}
