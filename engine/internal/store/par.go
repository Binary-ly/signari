package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// SweepExpiredPushedRequests drops handles nobody redeemed.
func SweepExpiredPushedRequests(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.pushed_requests WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
