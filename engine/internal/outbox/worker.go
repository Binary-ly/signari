// Package outbox drains core.outbox and delivers back-channel logout notices.
//
// Back-channel logout is the only logout mechanism that still works in 2026:
// front-channel logout and OIDC Session Management both depend on the OP's
// cookie being readable inside a cross-site iframe, which every major browser now
// blocks. So this is not one of several delivery paths -- it is the path.
//
// It is also the step everyone skips. Queuing the notice is easy; delivering it
// with retries and *visible per-relying-party status* is what separates "logout
// worked in staging" from logout that actually works. A silent delivery failure
// means a user who signed out is still signed in somewhere, and nobody finds out.
package outbox

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// BackchannelLogoutEvent is the event URI required in a logout token's `events`
// claim. Its presence is what distinguishes a logout token from any other JWT.
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// MaxAttempts before a notice is parked. Parked, not deleted: an undelivered
// logout is an operational fact someone needs to be able to see.
const MaxAttempts = 8

// Worker drains the outbox. It is a singleton -- running it on every node would
// deliver each notice N times.
type Worker struct {
	db     *pgxpool.Pool
	keys   *keys.Set
	issuer string
	log    *slog.Logger
	client *http.Client
	batch  int
}

func New(db *pgxpool.Pool, keySet *keys.Set, issuer string, log *slog.Logger) *Worker {
	return &Worker{
		db:     db,
		keys:   keySet,
		issuer: issuer,
		log:    log,
		batch:  25,
		// A relying party's endpoint is a third-party service that may be down,
		// slow, or hostile. The timeout bounds the wait so one bad receiver
		// cannot stall every other delivery.
		client: withNoRedirects(outboundClient(10 * time.Second)),
	}
}

// withNoRedirects stops a receiver bouncing a signed token elsewhere.
//
// The target is configured; following a redirect would let whoever controls that
// endpoint forward a signed logout token or security event to a destination we
// never approved.
func withNoRedirects(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

// Run drains the outbox until the context is cancelled.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := w.drainOnce(ctx); err != nil {
				w.log.Error("draining outbox", "err", err)
			} else if n > 0 {
				w.log.Info("delivered logout notices", "count", n)
			}
			// Security events drain on the same tick and independently: a
			// receiver that is down must not hold up logout delivery to everybody
			// else, and vice versa.
			if n, err := w.DrainSSF(ctx); err != nil {
				w.log.Error("draining security events", "err", err)
			} else if n > 0 {
				w.log.Info("delivered security events", "count", n)
			}
		}
	}
}

type pending struct {
	id       int64
	notice   store.LogoutNotice
	attempts int
}

// drainOnce claims a batch and attempts delivery.
//
// The claim uses FOR UPDATE SKIP LOCKED so that if a second worker is ever
// started by mistake, the two divide the work rather than both delivering the
// same notice. Correctness should not depend on remembering to run only one.
func (w *Worker) drainOnce(ctx context.Context) (int, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id, payload, attempts
		FROM core.outbox
		WHERE topic = 'backchannel_logout'
		  AND delivered_at IS NULL
		  AND attempts < $1
		  AND next_attempt_at <= now()
		ORDER BY id
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, MaxAttempts, w.batch)
	if err != nil {
		return 0, err
	}

	var batch []pending
	for rows.Next() {
		var p pending
		var raw []byte
		if err := rows.Scan(&p.id, &raw, &p.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		if err := json.Unmarshal(raw, &p.notice); err != nil {
			rows.Close()
			return 0, fmt.Errorf("decoding outbox row %d: %w", p.id, err)
		}
		batch = append(batch, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	delivered := 0
	for _, p := range batch {
		err := w.deliver(ctx, p.notice)
		if err == nil {
			if _, e := tx.Exec(ctx,
				`UPDATE core.outbox SET delivered_at = now(), last_error = NULL WHERE id = $1`,
				p.id); e != nil {
				return delivered, e
			}
			delivered++
			continue
		}

		// Exponential backoff, capped. A relying party that is down for an hour
		// should not be retried every second for that hour.
		backoff := time.Duration(math.Min(math.Pow(2, float64(p.attempts)), 300)) * time.Second
		if _, e := tx.Exec(ctx, `
			UPDATE core.outbox
			SET attempts = attempts + 1,
			    next_attempt_at = now() + $2::interval,
			    last_error = $3
			WHERE id = $1`, p.id, backoff.String(), err.Error()); e != nil {
			return delivered, e
		}
		w.log.Warn("back-channel logout delivery failed",
			"client_id", p.notice.ClientID, "attempt", p.attempts+1, "err", err)
	}

	return delivered, tx.Commit(ctx)
}

// deliver POSTs a signed logout token to one relying party.
func (w *Worker) deliver(ctx context.Context, n store.LogoutNotice) error {
	token, err := w.mintLogoutToken(n)
	if err != nil {
		return fmt.Errorf("minting logout token: %w", err)
	}

	form := url.Values{"logout_token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.Endpoint,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Read and discard a bounded amount so the connection can be reused, without
	// letting a hostile RP stream us an unbounded body.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	// The spec expects 200. Treat any 2xx as success and everything else as
	// retryable -- including 4xx, because an RP that has not deployed its logout
	// endpoint yet will start working later.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("relying party returned %d", resp.StatusCode)
	}
	return nil
}

// logoutClaims is the RFC-defined logout token payload.
//
// Note what is ABSENT: `nonce` is prohibited in a logout token. Its presence is
// how a logout token gets mistaken for an ID token, so it must never be emitted.
type logoutClaims struct {
	Issuer   string            `json:"iss"`
	Audience string            `json:"aud"`
	IssuedAt int64             `json:"iat"`
	Expiry   int64             `json:"exp"`
	JTI      string            `json:"jti"`
	Events   map[string]any    `json:"events"`
	Subject  string            `json:"sub,omitempty"`
	SID      string            `json:"sid,omitempty"`
	Extra    map[string]string `json:"-"`
}

func (w *Worker) mintLogoutToken(n store.LogoutNotice) (string, error) {
	// A notice naming neither a session nor a subject produces a valid, signed
	// instruction to end NOTHING. The relying party has no way to act on it, and
	// no way to tell it apart from a logout it handled correctly -- so the
	// delivery is recorded as a success and a session survives that everyone
	// believes was ended.
	//
	// Refused here as well as at the queueing site: this is the last point where
	// the mistake is still cheap, and a signed token is the point after which it
	// is not.
	if n.SessionID == "" && n.Subject == "" {
		return "", fmt.Errorf("refusing to mint a logout token for client %q that names "+
			"neither a sid nor a sub: it would instruct the relying party to end nothing", n.ClientID)
	}

	// Sign with whatever is active. RS256 first: it is the universal floor, and a
	// logout endpoint is exactly the kind of lightly-maintained code path most
	// likely to support only RS256.
	key, err := w.keys.Active(keys.RS256)
	if err != nil {
		if key, err = w.keys.Active(keys.ES256); err != nil {
			return "", fmt.Errorf("no active signing key: %w", err)
		}
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	now := time.Now()

	c := logoutClaims{
		Issuer:   w.issuer,
		Audience: n.ClientID,
		IssuedAt: now.Unix(),
		// Short-lived: a logout token is consumed immediately or not at all, and
		// a long expiry only widens the replay window.
		Expiry: now.Add(2 * time.Minute).Unix(),
		JTI:    jti,
		Events: map[string]any{BackchannelLogoutEvent: map[string]any{}},
		// Exactly one of these is set, decided when the notice was queued:
		// sid ends one session, sub ends all of the user's.
		Subject: n.Subject,
		SID:     n.SessionID,
	}

	return tokens.NewSigner(key).SignJSON(c, tokens.TypLogoutToken)
}

// Parked returns notices that exhausted their attempts, for the admin UI.
// Surfacing these is the difference between logout that works and logout that
// appears to work.
func Parked(ctx context.Context, db *pgxpool.Pool) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT payload->>'client_id', last_error, attempts
		FROM core.outbox
		WHERE topic='backchannel_logout' AND delivered_at IS NULL AND attempts >= $1
		ORDER BY id DESC LIMIT 100`, MaxAttempts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var client, lastErr string
		var attempts int
		if err := rows.Scan(&client, &lastErr, &attempts); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s (%d attempts): %s", client, attempts, lastErr))
	}
	return out, rows.Err()
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(cryptorand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
