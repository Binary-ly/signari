package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/tokens"
)

// auditHeadSigner signs the audit chain's head with the instance's active
// signing key when one is due (3.20), for the janitor to run on the node that
// holds its lock. The key set is the live one the refresher keeps current, so
// a rotated key signs the next head.
func auditHeadSigner(set *keys.Set, issuer string, interval time.Duration) func(context.Context, pgx.Tx) (bool, error) {
	return func(ctx context.Context, tx pgx.Tx) (bool, error) {
		c, err := audit.HeadToSign(ctx, tx, issuer, time.Now(), interval)
		if err != nil || c == nil {
			return false, err
		}
		key, err := set.Active(keys.ES256)
		if err != nil {
			key, err = set.Active(keys.RS256)
		}
		if err != nil {
			return false, fmt.Errorf("no active signing key to sign the audit head with: %w", err)
		}
		jws, err := tokens.NewSigner(key).SignJSON(c, audit.HeadType)
		if err != nil {
			return false, err
		}
		return true, audit.RecordHead(ctx, tx, c, key.KID(), jws)
	}
}
