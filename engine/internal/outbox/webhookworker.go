package outbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Delivering events to subscribers.
//
// # Signing
//
//	Signari-Signature: t=1786972759,v1=<hex hmac-sha256>
//
// The MAC covers `t.body` -- the timestamp AND the body, joined -- not the body
// alone. Signing only the body means a captured delivery can be replayed
// forever, and a subscriber has no way to tell a live event from last month's.
// With the timestamp inside the MAC, changing it invalidates the signature, so
// a subscriber can refuse anything outside a few minutes and mean it.
//
// The scheme is deliberately the one Stripe uses. A subscriber's engineers have
// almost certainly implemented it before, and a verification routine somebody
// has already got right is worth more than an original one.
//
// # Why 2xx and only 2xx
//
// A 3xx is followed by the client, within limits. Everything else is a failure
// including 410 Gone: a subscriber that means "stop sending" says so by having
// its subscription removed, and treating a status code as an unsubscribe
// instruction lets anyone who can answer that URL turn the events off.

// MaxWebhookAttempts is where we give up and park.
//
// Ten attempts under capped exponential backoff is roughly a day. Long enough to
// ride out an outage, short enough that a subscriber which moved is noticed.
const MaxWebhookAttempts = 10

// SignatureHeader carries the MAC.
const SignatureHeader = "Signari-Signature"

// Sign returns the header value for a body at a time.
//
// Exported because the conformance tester and the subscriber-side example must
// compute it exactly the same way, and two implementations of one MAC is one
// implementation and one bug.
func Sign(secret string, at time.Time, body []byte) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	// t.body -- the separator matters. Without it, (t=1, body="23") and
	// (t=12, body="3") produce the same MAC, and a signature that is ambiguous
	// about what it signed is not a signature.
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// webhookClient is the HTTP client deliveries use.
//
// A variable so a test can exercise delivery against httptest, which listens on
// loopback -- the exact address the real client refuses. Overriding it is
// therefore also a way to disable the guard, so TestTheDefaultClientRefusesLoopback
// asserts that the DEFAULT is the safe one. A hole that only a test uses is
// still a hole unless something checks the door is shut in production.
var webhookClient = func() *http.Client { return safedial.Client(15 * time.Second) }

// DrainWebhooks attempts every event delivery that is due.
func (w *Worker) DrainWebhooks(ctx context.Context) (int, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pending, err := store.ClaimWebhooks(ctx, tx, w.root, 32)
	if err != nil {
		return 0, err
	}
	if len(pending) == 0 {
		return 0, tx.Commit(ctx)
	}

	sent := 0
	for _, p := range pending {
		status, derr := w.deliverWebhook(ctx, p)
		if derr == nil && status >= 200 && status < 300 {
			if err := store.MarkWebhookDelivered(ctx, tx, p, status); err != nil {
				return sent, err
			}
			sent++
			continue
		}

		reason := fmt.Sprintf("HTTP %d", status)
		if derr != nil {
			reason = derr.Error()
		}
		giveUp := p.Attempts+1 >= MaxWebhookAttempts
		if err := store.MarkWebhookFailed(ctx, tx, p, status, reason,
			backoffFor(p.Attempts+1).String(), giveUp); err != nil {
			return sent, err
		}
		if giveUp {
			// The subscription itself is switched off, with the reason. A
			// subscriber that has been unreachable for a day is not going to be
			// reached by the next thousand events, and queueing them is how a
			// table grows until somebody notices for the wrong reason.
			if err := store.DisableSubscription(ctx, tx, p.SubscriptionID,
				"deliveries failed "+strconv.Itoa(MaxWebhookAttempts)+
					" times in a row: "+reason); err != nil {
				return sent, err
			}
			w.log.Warn("event subscription disabled after repeated failures",
				"subscription", p.SubscriptionID, "url", p.URL, "err", reason)
		}
	}
	return sent, tx.Commit(ctx)
}

// deliverWebhook makes one attempt.
func (w *Worker) deliverWebhook(ctx context.Context, p store.PendingWebhook) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL,
		bytes.NewReader(p.Body))
	if err != nil {
		return 0, err
	}
	now := time.Now()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, Sign(p.Secret, now, p.Body))
	// The event id, so a subscriber can be idempotent without parsing the body.
	// At-least-once delivery is the honest guarantee -- a network that eats the
	// response after we sent it is indistinguishable from one that ate the
	// request, and retrying is the only safe reading.
	req.Header.Set("Signari-Event-Id", p.Envelope.ID)
	req.Header.Set("Signari-Event-Type", p.Envelope.Type)
	req.Header.Set("User-Agent", "signari")

	// The SSRF-safe client: every hop is dialled through a Control that refuses
	// private, loopback and link-local addresses. A subscription URL is an
	// address somebody else chose, and without this the identity provider is a
	// proxy into its own network.
	resp, err := webhookClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Drained and discarded. Not read into anything: the response body of a
	// webhook is not an instruction, and treating it as one is how a subscriber
	// starts driving the identity provider.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}
