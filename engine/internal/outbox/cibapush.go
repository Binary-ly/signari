package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"signari.dev/engine/internal/store"
)

// CIBAPushTopic is the outbox topic for push-mode token delivery.
const CIBAPushTopic = store.CIBAPushTopicName

// deliverCIBAPush performs one push callback (CIBA Core 1.0 §10.3).
//
// The body is the token response the OP already minted, plus `auth_req_id`, as
// application/json. The bearer credential in the Authorization header is the
// client's own `client_notification_token`, which authenticates US to THEM --
// the reverse direction from every other bearer token in this codebase, and the
// same as ping.
//
// The difference from ping is what is in the body: tokens. That makes the
// transport requirement load-bearing rather than advisory, which is why the
// endpoint is constrained to https in the schema and checked again here.
func (w *Worker) deliverCIBAPush(ctx context.Context, p store.CIBAPush) error {
	if len(p.Sealed) == 0 {
		// Released with nothing to send. Not retryable: the tokens are minted
		// once, so a row that reached delivery without them will never acquire
		// them, and retrying forever would hide the bug that produced it.
		return fmt.Errorf("a CIBA push for %q was released with no token response",
			p.ClientID)
	}
	// §9: "It MUST be an HTTPS URL and Communication with the Client Notification
	// Endpoint MUST utilize TLS."
	//
	// Checked here as well as in the schema. The schema constrains what can be
	// registered; this constrains what can be SENT, and the payload was parked
	// before now -- a row written by an older build, or by a hand-edit, must not
	// put an access token on a plaintext connection.
	if !strings.HasPrefix(p.Endpoint, "https://") {
		return fmt.Errorf("refusing to push tokens to %q: §9 requires an https "+
			"notification endpoint", p.Endpoint)
	}

	raw, err := w.root.Open(p.Sealed, store.SealContextCIBAPush)
	if err != nil {
		return fmt.Errorf("unsealing a CIBA push for %q: %w", p.ClientID, err)
	}

	// The auth_req_id is added to the minted response rather than being minted
	// with it: §10.3.1 says "a new parameter `auth_req_id` is included in the
	// payload", and the token response type is shared with the token endpoint,
	// where the claim would be meaningless.
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("decoding a sealed CIBA push for %q: %w", p.ClientID, err)
	}
	body["auth_req_id"] = p.AuthReqID
	out, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint,
		bytes.NewReader(out))
	if err != nil {
		return fmt.Errorf("building a CIBA push for %q: %w", p.ClientID, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Token)

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("delivering a CIBA push to %q: %w", p.ClientID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("client %q answered %d", p.ClientID, resp.StatusCode)
	}
	return nil
}

// drainCIBAPushes sends the token deliveries that are due.
//
// Parked rows are invisible to the claim query, so this drains only requests
// somebody has approved and whose tokens have been sealed into the row.
func (w *Worker) drainCIBAPushes(ctx context.Context) (int, error) {
	return w.drainTopic(ctx, drainSpec{
		topic: CIBAPushTopic,
		batch: w.batch,
		deliver: func(ctx context.Context, raw []byte) error {
			var p store.CIBAPush
			if err := json.Unmarshal(raw, &p); err != nil {
				return fmt.Errorf("decoding a CIBA push: %w", err)
			}
			return w.deliverCIBAPush(ctx, p)
		},
	})
}
