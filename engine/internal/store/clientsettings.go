package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/tokens"
)

// ClientSettings are a client's per-client token settings. A nil field is left
// as it is, so each surface changes only what it was asked to.
type ClientSettings struct {
	// AccessTokenTTL is how long an access token lives, and so how long one
	// outlives its revocation (ADR-007). A minute to tokens.MaxAccessTokenTTL.
	AccessTokenTTL *time.Duration
	// RefreshTokenTTL is how long a refresh token lives. Five minutes to a year.
	RefreshTokenTTL *time.Duration
}

// The bounds, which migration 0144 enforces in the schema as well.
const (
	MinAccessTokenTTL  = time.Minute
	MinRefreshTokenTTL = 5 * time.Minute
	MaxRefreshTokenTTL = 365 * 24 * time.Hour
)

// ErrInvalidClientSetting wraps every reason a setting is refused.
var ErrInvalidClientSetting = errors.New("invalid client setting")

// SetClientSettings writes a client's token settings. The one writer, behind
// `client set-lifetimes`, the client PATCH and `signari apply`.
//
// Both lifetimes had a column since the first schema and no writer, so every
// client's access tokens lived five minutes and its refresh tokens thirty days
// whatever the console said; the access lifetime was not even read.
func SetClientSettings(ctx context.Context, tx pgx.Tx, clientID string, s ClientSettings) error {
	if err := CheckClientSettings(s); err != nil {
		return err
	}
	if d := s.AccessTokenTTL; d != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET access_token_ttl_s = $2, updated_at = now()
			WHERE client_id = $1`, clientID, int(d.Seconds()))); err != nil {
			return err
		}
	}
	if d := s.RefreshTokenTTL; d != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET refresh_token_ttl_s = $2, updated_at = now()
			WHERE client_id = $1`, clientID, int(d.Seconds()))); err != nil {
			return err
		}
	}
	return nil
}

// CheckClientSettings refuses what SetClientSettings would, without a
// database, so `signari plan` says so before anything is applied.
func CheckClientSettings(s ClientSettings) error {
	if d := s.AccessTokenTTL; d != nil &&
		(*d < MinAccessTokenTTL || *d > tokens.MaxAccessTokenTTL || *d%time.Second != 0) {
		return fmt.Errorf("%w: an access token lifetime must be whole seconds from %s to %s, "+
			"since it is also how long a revoked token goes on working", ErrInvalidClientSetting,
			MinAccessTokenTTL, tokens.MaxAccessTokenTTL)
	}
	if d := s.RefreshTokenTTL; d != nil &&
		(*d < MinRefreshTokenTTL || *d > MaxRefreshTokenTTL || *d%time.Second != 0) {
		return fmt.Errorf("%w: a refresh token lifetime must be whole seconds from %s to %s",
			ErrInvalidClientSetting, MinRefreshTokenTTL, MaxRefreshTokenTTL)
	}
	return nil
}

// clientUpdated turns an UPDATE that matched no client into ErrClientNotFound.
func clientUpdated(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// ClientSettingsView is what SetClientSettings writes, read back.
type ClientSettingsView struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// ClientSettingsOf reads a client's token settings.
func ClientSettingsOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (ClientSettingsView, error) {
	var v ClientSettingsView
	var access, refresh int
	err := q.QueryRow(ctx, `SELECT access_token_ttl_s, refresh_token_ttl_s FROM core.clients
		WHERE client_id = $1`, clientID).Scan(&access, &refresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrClientNotFound
	}
	v.AccessTokenTTL = time.Duration(access) * time.Second
	v.RefreshTokenTTL = time.Duration(refresh) * time.Second
	return v, err
}
