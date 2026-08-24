package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Poll-based delivery of Security Event Tokens (RFC 8936).
//
// Push (RFC 8935) POSTs each SET to an endpoint the receiver exposes, which a
// receiver behind a firewall -- or an agent with no public address -- cannot
// offer. Poll inverts it: the receiver makes an authenticated request to us and
// pulls the SETs waiting for it, then acknowledges the ones it has stored so we
// can drop them. Same events, same signatures; only the direction differs.

const (
	// maxPollBody caps the request body. A poll body is a few small fields; a
	// large one is a mistake or an attack, not a real request.
	maxPollBody = 16 << 10
	// defaultPollMaxEvents is returned when the receiver does not ask for a
	// specific number.
	defaultPollMaxEvents = 100
	// hardPollMaxEvents caps what a single poll can drain, so one request cannot
	// be made to mint an unbounded number of tokens.
	hardPollMaxEvents = 500

	// pollHold and pollInterval bound the long-poll: when the receiver asks us to
	// wait for an event (returnImmediately=false) and none is queued, we hold the
	// connection for at most pollHold, checking every pollInterval.
	pollHold     = 20 * time.Second
	pollInterval = 1 * time.Second
)

// pollRequest is the RFC 8936 §2.4 poll delivery request.
type pollRequest struct {
	// MaxEvents is a pointer so "absent" is distinct from an explicit 0.
	MaxEvents         *int     `json:"maxEvents"`
	ReturnImmediately *bool    `json:"returnImmediately"`
	Ack               []string `json:"ack"`
	// SetErrs is receiver-reported errors on previously delivered SETs. Accepted
	// and ignored: a receiver that rejected a SET has its own reason, and we have
	// no per-SET retry a report here would change. Parsed only so a body carrying
	// it is not rejected as malformed.
	SetErrs map[string]any `json:"setErrs"`
}

// pollResponse is the RFC 8936 §2.4 poll delivery response.
type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// handleSSFPoll serves the poll delivery endpoint.
func (s *Server) handleSSFPoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authenticate the receiver as the stream's OAuth client, over the
	// Authorization header (Basic) or the connection (mutual-TLS). The poll body
	// is JSON, so the form-carried methods -- client_secret_post, private_key_jwt
	// -- have nowhere to put their parameters and are not offered here; a stream
	// meant for poll is configured on a client that authenticates one of these two
	// ways.
	creds, cerr := oauth.ParseClientCredentials(r.Header, nil)
	if cerr != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", cerr.Description)
		return
	}
	c, err := s.lookupClient(ctx, creds.ClientID)
	if err != nil || c == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if c.Type != "confidential" {
		writeError(w, http.StatusUnauthorized, "invalid_client",
			"polling a security event stream requires a confidential client")
		return
	}
	if aerr := s.authenticateConfidentialClient(ctx, r, c, creds.ClientSecret); aerr != nil {
		s.log.Info("ssf poll authentication failed", "client_id", creds.ClientID, "err", aerr,
			"correlation_id", correlationID(ctx))
		writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	// An empty body is a valid poll -- "give me what you have". A decode failure
	// therefore only matters when a body is actually present.
	var req pollRequest
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxPollBody))
	if len(bytes.TrimSpace(body)) > 0 {
		if jerr := json.Unmarshal(body, &req); jerr != nil {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"the poll request body is not valid JSON")
			return
		}
	}

	maxEvents := defaultPollMaxEvents
	if req.MaxEvents != nil {
		maxEvents = *req.MaxEvents
	}
	if maxEvents < 1 {
		maxEvents = 1
	}
	if maxEvents > hardPollMaxEvents {
		maxEvents = hardPollMaxEvents
	}

	streamID, ok, err := store.PollStreamForClient(ctx, s.db, creds.ClientID)
	if err != nil {
		s.log.Error("locating a poll stream", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if !ok {
		// Authenticated, but this client has no enabled poll stream. 404 rather
		// than an empty 200, so a receiver misconfigured for poll learns it is
		// misconfigured instead of polling an empty queue forever.
		writeError(w, http.StatusNotFound, "invalid_request",
			"this client has no enabled poll stream")
		return
	}

	// Default true, per §2.4: "If this field is omitted... it defaults to a value
	// of true." So a receiver that says nothing gets an immediate answer.
	returnImmediately := req.ReturnImmediately == nil || *req.ReturnImmediately

	sets, more, err := s.pollDeliver(ctx, streamID, creds.ClientID, req.Ack, maxEvents, returnImmediately)
	if err != nil {
		s.log.Error("delivering polled events", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, pollResponse{Sets: sets, MoreAvailable: more})
}

// pollDeliver acknowledges, then returns the SETs waiting for a stream.
//
// Acknowledgement is applied first and on its own, because it is cleanup that
// must happen whether or not any events are then available -- a receiver that
// only acks, with nothing new to collect, still expects its acks to take effect.
func (s *Server) pollDeliver(ctx context.Context, streamID, audience string, ack []string,
	maxEvents int, returnImmediately bool) (map[string]string, bool, error) {

	if len(ack) > 0 {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			return nil, false, err
		}
		if _, err := store.PollAck(ctx, tx, streamID, ack); err != nil {
			_ = tx.Rollback(ctx)
			return nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
	}

	sets, more, err := s.pollFetchAndMint(ctx, streamID, audience, maxEvents)
	if err != nil || len(sets) > 0 || returnImmediately {
		return sets, more, err
	}

	// Long-poll: the receiver asked us to wait for an event. Hold the connection
	// for a bounded time, checking periodically, and return as soon as one is
	// queued -- or empty when the cap elapses or the receiver disconnects.
	timer := time.NewTimer(pollHold)
	defer timer.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return map[string]string{}, false, nil
		case <-timer.C:
			return map[string]string{}, false, nil
		case <-ticker.C:
			sets, more, err = s.pollFetchAndMint(ctx, streamID, audience, maxEvents)
			if err != nil {
				return nil, false, err
			}
			if len(sets) > 0 {
				return sets, more, nil
			}
		}
	}
}

// pollFetchAndMint reads the queued events for a stream and mints a SET for each.
//
// Read-only against the queue: rows leave only when the receiver acknowledges
// them, so a SET handed over but not stored by the receiver is redelivered on the
// next poll rather than lost.
func (s *Server) pollFetchAndMint(ctx context.Context, streamID, audience string, maxEvents int) (
	map[string]string, bool, error) {

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	events, more, err := store.PollFetch(ctx, tx, streamID, maxEvents)
	if err != nil {
		return nil, false, err
	}
	if len(events) == 0 {
		return map[string]string{}, false, nil
	}

	key, err := s.setSigningKey()
	if err != nil {
		return nil, false, err
	}
	signer := tokens.NewSigner(key)
	out := make(map[string]string, len(events))
	for _, e := range events {
		// The same builder the push worker uses, so a receiver gets the same event
		// whichever way it arrives. EventTime is the queue time (when the session
		// was revoked), not now (when the SET is minted) -- for poll the two can be
		// far apart, and a receiver orders by when things happened.
		event := ssf.RevocationEvent(s.cfg.Issuer, e.Subject, e.Reason, e.QueuedAt)
		event.Type = e.EventType
		jws, merr := ssf.Mint(signer, s.cfg.Issuer, audience, e.JTI, event, time.Now())
		if merr != nil {
			return nil, false, merr
		}
		out[e.JTI] = jws
	}
	return out, more, nil
}

// setSigningKey picks a key to sign a SET with, preferring ES256 and falling back
// to any active key -- the receiver resolves whichever it is from our JWKS. It
// mirrors the push worker's selection so a SET is signed the same way on both
// paths.
func (s *Server) setSigningKey() (keys.Key, error) {
	if k, err := s.cfg.Keys.Active(keys.ES256); err == nil {
		return k, nil
	}
	for _, alg := range s.cfg.Keys.Algorithms() {
		if k, err := s.cfg.Keys.Active(alg); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no signing key available for a security event")
}
