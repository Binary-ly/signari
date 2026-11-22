package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/scim"
)

// A SCIM target that takes the authorization code grant (7.14): the authorization
// somebody has started and not finished, and the refresh token a finished one left.
// The protocol is in internal/scim and the steps in internal/provision.

var (
	// ErrSCIMAuthorizationUnknown is a state no authorization waits with: never
	// started, already finished, past its ten minutes, or for another target.
	ErrSCIMAuthorizationUnknown = errors.New("no authorization of this target is waiting with that state; it " +
		"was finished already, has expired, or was never started")
	// ErrSCIMGrantChanged is a target whose grant changed while somebody was
	// signing in: the refresh token is for the grant they agreed to, which is gone.
	ErrSCIMGrantChanged = errors.New("the target's grant changed while the authorization was made, so the " +
		"refresh token it left is for a grant the target no longer takes; authorize it again")
)

// SCIMTargetForAuthorization is one target, enabled or not, its secret unsealed:
// a target may be authorized before it is switched on.
func SCIMTargetForAuthorization(ctx context.Context, conn Querier, root *keys.RootKey, orgID,
	slug string) (scim.Target, error) {
	if orgID == "" || slug == "" {
		return scim.Target{}, ErrSCIMTargetUnknown
	}
	got, err := loadSCIMTargets(ctx, conn, root, orgID, slug, false)
	if err != nil {
		return scim.Target{}, err
	}
	if len(got) == 0 {
		return scim.Target{}, ErrSCIMTargetUnknown
	}
	return got[0], nil
}

// StartSCIMAuthorization records an authorization of a target, replacing one that
// was waiting: somebody who starts again has given up on the first, and only the
// latest can be finished. The state is held only as its hash and the PKCE verifier
// sealed, since together with a code they are what a refresh token is issued for.
func StartSCIMAuthorization(ctx context.Context, q Execer, targetID string, stateHash, sealedVerifier []byte,
	redirectURI string, until time.Time) error {
	tag, err := q.Exec(ctx, `
		UPDATE core.scim_targets SET oauth_pending_state = $2, oauth_pending_verifier = $3,
		       oauth_pending_redirect = $4, oauth_pending_until = $5
		 WHERE id = $1::uuid AND oauth_authorize_url IS NOT NULL`,
		targetID, stateHash, sealedVerifier, redirectURI, until)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSCIMTargetUnknown
	}
	return nil
}

// SpendSCIMAuthorization ends the authorization waiting at a target when stateHash
// is the hash of its state and it has not expired, and answers its sealed verifier
// and the redirect URI it was started with. One statement, so of two attempts with
// one state only one gets them: for a code used twice the authorization server
// "SHOULD revoke (when possible) all tokens previously issued based on that
// authorization code" (specs/rfc6749.txt:1463-1466).
// Anything else is ErrSCIMAuthorizationUnknown, and an authorization still waiting
// is left as it is, so a stray request cannot cancel somebody's sign-in.
func SpendSCIMAuthorization(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, targetID string, stateHash []byte) (sealedVerifier []byte, redirectURI string, err error) {
	err = q.QueryRow(ctx, `
		UPDATE core.scim_targets t SET oauth_pending_state = NULL, oauth_pending_verifier = NULL,
		       oauth_pending_redirect = NULL, oauth_pending_until = NULL
		  FROM core.scim_targets waiting
		 WHERE t.id = waiting.id AND t.id = $1::uuid AND t.oauth_pending_state = $2
		   AND t.oauth_pending_until > now()
		RETURNING waiting.oauth_pending_verifier, waiting.oauth_pending_redirect`,
		targetID, stateHash).Scan(&sealedVerifier, &redirectURI)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrSCIMAuthorizationUnknown
	}
	return sealedVerifier, redirectURI, err
}

// KeepSCIMGrant holds the refresh token an authorization left, sealed, and answers
// when, if the target still takes the grant that authorization was made for.
func KeepSCIMGrant(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, t scim.Target, sealedRefresh []byte) (time.Time, error) {
	var at time.Time
	err := q.QueryRow(ctx, `
		UPDATE core.scim_targets SET oauth_refresh_token = $5, oauth_authorized_at = now()
		 WHERE id = $1::uuid AND oauth_authorize_url = $2 AND oauth_token_url = $3 AND oauth_client_id = $4
		RETURNING oauth_authorized_at`,
		t.ID, t.OAuthAuthorizeURL, t.OAuthTokenURL, t.OAuthClientID, sealedRefresh).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrSCIMGrantChanged
	}
	return at, err
}

// scimRefresh keeps a target's refresh token in its row (scim.RefreshTokens).
type scimRefresh struct {
	db       beginner
	root     *keys.RootKey
	targetID string
}

// refreshLockWait is how long a pass waits for another's refresh of the same
// target: longer than a token endpoint is given to answer.
const refreshLockWait = "60s"

// Rotate holds the target's row for as long as use runs, so a pass waits for
// another's refresh and then reads the token it left, rather than spending the one
// it spent. The replacement is written whatever use says went wrong after it, and
// under a context of its own: a token endpoint that has issued one has, with an
// authorization server that rotates them, revoked the one held.
func (r scimRefresh) Rotate(ctx context.Context, use func(current string) (string, error)) error {
	if r.root == nil {
		return fmt.Errorf("the refresh token is sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	keep, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	defer func() { _ = tx.Rollback(keep) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, refreshLockWait); err != nil {
		return err
	}
	var sealed []byte
	if err := tx.QueryRow(ctx, `SELECT oauth_refresh_token FROM core.scim_targets WHERE id = $1::uuid FOR UPDATE`,
		r.targetID).Scan(&sealed); err != nil {
		return fmt.Errorf("reading the target's refresh token: %w", err)
	}
	current := ""
	if len(sealed) > 0 {
		plain, err := r.root.Open(sealed, "scim_refresh_token")
		if err != nil {
			return fmt.Errorf("unsealing the target's refresh token: %w", err)
		}
		current = string(plain)
	}
	next, useErr := use(current)
	if next != "" && next != current {
		resealed, err := r.root.Seal([]byte(next), "scim_refresh_token")
		if err != nil {
			return fmt.Errorf("sealing the target's new refresh token: %w", err)
		}
		if _, err := tx.Exec(keep, `UPDATE core.scim_targets SET oauth_refresh_token = $2 WHERE id = $1::uuid`,
			r.targetID, resealed); err != nil {
			return fmt.Errorf("keeping the target's new refresh token: %w", err)
		}
	}
	if err := tx.Commit(keep); err != nil {
		return fmt.Errorf("keeping the target's new refresh token: %w", err)
	}
	return useErr
}
