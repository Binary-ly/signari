package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// IDTokenAlg signs the client's ID and access tokens: ES256 (the default),
	// RS256, PS256 or EdDSA, and only one the client's instance holds an active
	// key for, since a token endpoint asked to sign with a key it does not have
	// answers every request with an error.
	IDTokenAlg *string
	// RequirePAR refuses any authorization the client did not push first (RFC
	// 9126 §6, require_pushed_authorization_requests).
	RequirePAR *bool
	// FirstParty skips the consent screen for the client (migration 0010). An
	// operator's decision only; dynamic registration never sets it.
	FirstParty *bool
	// IssuerAlias pins the client to a legacy issuer its instance claims, so
	// its tokens are minted under that `iss` during a migration. Only a live
	// alias of the client's own instance; empty clears it.
	IssuerAlias *string
	// MinimumACR is the weakest authentication the client accepts: "1" a
	// single factor, "2" multi-factor (migration 0166), "3" multi-factor with
	// a WebAuthn assertion, "4" with a device-bound key (0174).
	MinimumACR *string
}

// ClientACRs are the floors a client may be given, the schema's own CHECK.
var ClientACRs = []string{"1", "2", "3", "4"}

// ClientAlgorithms are the JWS algorithms a client may be set to sign with,
// the schema's own CHECK. No symmetric algorithm, ever.
var ClientAlgorithms = []string{"ES256", "RS256", "PS256", "EdDSA"}

// The bounds, which migration 0144 enforces in the schema as well.
const (
	MinAccessTokenTTL  = time.Minute
	MinRefreshTokenTTL = 5 * time.Minute
	MaxRefreshTokenTTL = 365 * 24 * time.Hour
)

// ErrInvalidClientSetting wraps every reason a setting is refused.
var ErrInvalidClientSetting = errors.New("invalid client setting")

// SetClientSettings writes a client's token settings. The one writer, behind
// `client set-lifetimes` and `client set-alg`, the client PATCH, `signari
// apply` and, for the algorithm alone, dynamic registration.
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
	if a := s.IDTokenAlg; a != nil {
		var held bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM core.signing_keys k
			                 JOIN core.organizations o ON o.instance_id = k.instance_id
			                 JOIN core.clients c ON c.org_id = o.id
			                WHERE c.client_id = $1 AND k.algorithm = $2
			                  AND k.state = 'active' AND k.purpose = 'oidc')`,
			clientID, *a).Scan(&held); err != nil {
			return err
		}
		if !held {
			return fmt.Errorf("%w: this instance holds no active %s signing key, so every token "+
				"for the client would fail to sign; publish one with `signari keys rotate -alg %s` "+
				"and promote it with the same command after the dwell", ErrInvalidClientSetting, *a, *a)
		}
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET id_token_signed_alg = $2, updated_at = now()
			WHERE client_id = $1`, clientID, *a)); err != nil {
			return err
		}
	}
	if v := s.RequirePAR; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET require_pushed_authorization = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.FirstParty; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET first_party = $2, updated_at = now()
			WHERE client_id = $1`, clientID, *v)); err != nil {
			return err
		}
	}
	if v := s.IssuerAlias; v != nil {
		alias := strings.TrimSpace(*v)
		if alias != "" {
			// The schema's trigger (0015) checks registration; liveness too, here,
			// since a client pinned to a retired alias would mint under the
			// instance's own issuer from the first token.
			var live bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM core.instance_issuer_aliases a
				                 JOIN core.organizations o ON o.instance_id = a.instance_id
				                 JOIN core.clients c ON c.org_id = o.id
				                WHERE c.client_id = $1 AND a.issuer = $2
				                  AND (a.retire_after IS NULL OR a.retire_after > now()))`,
				clientID, alias).Scan(&live); err != nil {
				return err
			}
			if !live {
				return fmt.Errorf("%w: %s is not an alias this client's instance claims now; register "+
					"it with `signari instance add-alias`", ErrInvalidClientSetting, alias)
			}
		}
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET issuer_alias = NULLIF($2, ''),
			updated_at = now() WHERE client_id = $1`, clientID, alias)); err != nil {
			return err
		}
	}
	if v := s.MinimumACR; v != nil {
		if err := clientUpdated(tx.Exec(ctx, `UPDATE core.clients SET minimum_acr = $2,
			updated_at = now() WHERE client_id = $1`, clientID, *v)); err != nil {
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
	if a := s.IDTokenAlg; a != nil && !slices.Contains(ClientAlgorithms, *a) {
		return fmt.Errorf("%w: %q is not a signing algorithm a client may use (%s)",
			ErrInvalidClientSetting, *a, strings.Join(ClientAlgorithms, ", "))
	}
	if a := s.MinimumACR; a != nil && !slices.Contains(ClientACRs, *a) {
		return fmt.Errorf("%w: %q is not an acr a client may require: 1, a single factor; 2, "+
			"multi-factor; 3, with a passkey or security key; or 4, with a key bound to its device",
			ErrInvalidClientSetting, *a)
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
	IDTokenAlg      string
	RequirePAR      bool
	FirstParty      bool
	IssuerAlias     string
	MinimumACR      string
}

// ClientSettingsOf reads a client's token settings.
func ClientSettingsOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, clientID string) (ClientSettingsView, error) {
	var v ClientSettingsView
	var access, refresh int
	err := q.QueryRow(ctx, `SELECT access_token_ttl_s, refresh_token_ttl_s, id_token_signed_alg,
		       require_pushed_authorization, first_party, COALESCE(issuer_alias, ''), minimum_acr
		FROM core.clients WHERE client_id = $1`, clientID).
		Scan(&access, &refresh, &v.IDTokenAlg, &v.RequirePAR, &v.FirstParty, &v.IssuerAlias,
			&v.MinimumACR)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrClientNotFound
	}
	v.AccessTokenTTL = time.Duration(access) * time.Second
	v.RefreshTokenTTL = time.Duration(refresh) * time.Second
	return v, err
}
