package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
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
}

// DrainSSF delivers queued security events.
func (w *Worker) DrainSSF(ctx context.Context) (int, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id, payload, attempts
		FROM core.outbox
		WHERE topic = 'ssf_event'
		  AND delivered_at IS NULL
		  AND attempts < $1
		  AND next_attempt_at <= now()
		ORDER BY id
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, MaxAttempts, w.batch)
	if err != nil {
		return 0, err
	}
	var batch []ssfPending
	for rows.Next() {
		var p ssfPending
		var raw []byte
		if err := rows.Scan(&p.id, &raw, &p.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			rows.Close()
			return 0, fmt.Errorf("decoding an ssf outbox row: %w", err)
		}
		batch = append(batch, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, tx.Commit(ctx)
	}

	for _, p := range batch {
		derr := w.deliverSSF(ctx, p)
		if derr == nil {
			if _, err := tx.Exec(ctx,
				`UPDATE core.outbox SET delivered_at = now() WHERE id = $1`, p.id); err != nil {
				return 0, err
			}
			continue
		}
		// The same capped exponential backoff as logout delivery, written the same
		// way rather than shared, because the two drains are deliberately
		// independent and a shared helper invites one to be tuned for the other.
		backoff := time.Duration(math.Min(math.Pow(2, float64(p.attempts)), 300)) * time.Second
		if _, err := tx.Exec(ctx, `
			UPDATE core.outbox
			SET attempts = attempts + 1, next_attempt_at = now() + $2::interval,
			    last_error = $3
			WHERE id = $1`, p.id, backoff.String(), derr.Error()); err != nil {
			return 0, err
		}
		w.log.Info("security event delivery failed", "client_id", p.ClientID,
			"event", p.Event, "attempt", p.attempts+1, "err", derr)
	}
	return len(batch), tx.Commit(ctx)
}

func (w *Worker) deliverSSF(ctx context.Context, p ssfPending) error {
	key, err := w.keys.Active(keys.ES256)
	if err != nil {
		// Any active key will do; the receiver resolves it from our JWKS.
		for _, alg := range w.keys.Algorithms() {
			if k, kerr := w.keys.Active(alg); kerr == nil {
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
	token, err := ssf.Mint(tokens.NewSigner(key), w.issuer, p.ClientID, jti, ssf.Event{
		Type: p.Event,
		Subject: ssf.Subject{
			Format: "iss_sub", Issuer: w.issuer, Sub: p.Subject,
		},
		EventTime:        time.Now(),
		ReasonAdmin:      "The session was revoked: " + p.Reason,
		ReasonUser:       "You were signed out.",
		InitiatingEntity: initiatingEntityFor(p.Reason),
	}, time.Now())
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

// initiatingEntityFor maps a termination reason to the CAEP vocabulary.
//
// Reported honestly: a receiver may treat an administrator revoking a session
// differently from a user signing out, and collapsing them into "system" throws
// away the distinction it would act on.
func initiatingEntityFor(reason string) string {
	switch reason {
	case "logout":
		return "user"
	case "admin_revoke", "user_deactivated", "user_deleted":
		return "admin"
	case "password_change", "mfa_reset":
		return "user"
	case "reuse_detected":
		return "policy"
	default:
		return "system"
	}
}
