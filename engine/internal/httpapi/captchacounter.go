package httpapi

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/captcha"
	"signari.dev/engine/internal/store"
)

// sharedCaptchaCounter counts CAPTCHA pressure where every instance can see it.
//
// The in-memory default in internal/captcha is right for exactly one instance.
// With N behind a load balancer an attacker needs N times the failures before
// any single one escalates, and if the balancer spreads them evenly, none of
// them ever does -- adaptive mode silently stops being adaptive.
type sharedCaptchaCounter struct {
	db  *pgxpool.Pool
	log *slog.Logger
}

func (c *sharedCaptchaCounter) Record(ctx context.Context, key string) {
	// The limit passed here is irrelevant: this call is being made to count,
	// and the decision is taken in Count against the configured threshold.
	if _, err := store.AllowRate(ctx, c.db, "captcha:"+key,
		1<<30, captcha.FailureWindow); err != nil {
		c.log.Error("recording captcha pressure", "err", err)
	}
}

func (c *sharedCaptchaCounter) Count(ctx context.Context, key string) int {
	n, err := store.CountRate(ctx, c.db, "captcha:"+key, captcha.FailureWindow)
	if err != nil {
		// Zero, not "challenge everybody". A database problem should not turn
		// into a CAPTCHA on every sign-in page in the deployment -- the login
		// itself is about to fail for the same reason, and adding a challenge
		// to it helps nobody.
		c.log.Error("reading captcha pressure", "err", err)
		return 0
	}
	return n
}

func (c *sharedCaptchaCounter) Clear(ctx context.Context, key string) {
	if err := store.ClearRate(ctx, c.db, "captcha:"+key); err != nil {
		c.log.Error("clearing captcha pressure", "err", err)
	}
}
