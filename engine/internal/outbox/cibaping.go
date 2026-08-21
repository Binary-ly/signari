package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"signari.dev/engine/internal/store"
)

// CIBAPingTopic is the outbox topic for ping-mode notifications.
const CIBAPingTopic = "ciba_ping"

// deliverCIBAPing performs one notification (CIBA Core 1.0 §10).
//
// The body carries the `auth_req_id` and nothing else. Not the token: that is
// what makes this ping rather than push, and it means a notification intercepted
// in transit yields an identifier the interceptor still cannot redeem without the
// client's own credentials.
//
// The `client_notification_token` goes in the Authorization header as a bearer
// credential, per §7.1 — "a bearer token provided by the Client that will be used
// by the OpenID Provider to authenticate the callback request to the Client". The
// direction is worth being careful about: this authenticates US to THEM, which is
// the reverse of every other bearer token in this codebase.
func (w *Worker) deliverCIBAPing(ctx context.Context, p store.CIBAPing) error {
	body, err := json.Marshal(map[string]string{"auth_req_id": p.AuthReqID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint,
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building a CIBA ping for %q: %w", p.ClientID, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Token)

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("delivering a CIBA ping to %q: %w", p.ClientID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// §10 expects 204, and any 2xx is treated as delivered. Everything else is
	// retryable for the same reason as back-channel logout: a client whose
	// notification endpoint is not deployed yet will start answering later, and
	// the request expires on its own if it never does.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("client %q answered %d", p.ClientID, resp.StatusCode)
	}
	return nil
}

// drainCIBAPings sends the notifications that are due.
//
// A parked row (next_attempt_at = 'infinity') is invisible to the claim query, so
// this drains only requests somebody has actually decided.
func (w *Worker) drainCIBAPings(ctx context.Context) (int, error) {
	return w.drainTopic(ctx, drainSpec{
		topic: CIBAPingTopic,
		batch: w.batch,
		deliver: func(ctx context.Context, raw []byte) error {
			var p store.CIBAPing
			if err := json.Unmarshal(raw, &p); err != nil {
				return fmt.Errorf("decoding a CIBA ping: %w", err)
			}
			return w.deliverCIBAPing(ctx, p)
		},
		backoff: backoffFor,
		onFailure: func(raw []byte, attempts int, err error) {
			var p store.CIBAPing
			_ = json.Unmarshal(raw, &p)
			w.log.Warn("CIBA ping delivery failed",
				"client_id", p.ClientID, "attempts", attempts, "err", err)
		},
	})
}
