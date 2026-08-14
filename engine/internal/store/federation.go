package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
)

// ErrProviderUnknown is returned when no external provider matches a slug.
var ErrProviderUnknown = errors.New("no identity provider with that name")

// LoadIdentityProvider fetches an external provider by its URL slug.
func LoadIdentityProvider(ctx context.Context, db *pgxpool.Pool, root *keys.RootKey, slug string) (*federation.Config, error) {
	var (
		c            federation.Config
		kind         string
		secretSealed []byte
		enabled      bool
	)
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, slug, display_name, kind, client_id,
		       client_secret, COALESCE(issuer,''), COALESCE(authorize_url,''),
		       COALESCE(token_url,''), COALESCE(userinfo_url,''), COALESCE(jwks_url,''),
		       scopes, allow_signup, allow_linking, require_verified_email, enabled
		FROM core.identity_providers
		WHERE slug = $1`, slug).Scan(
		&c.ID, &c.OrgID, &c.Slug, &c.DisplayName, &kind, &c.ClientID,
		&secretSealed, &c.IssuerOverride, &c.AuthorizeOverride,
		&c.TokenOverride, &c.UserinfoOverride, &c.JWKSOverride,
		&c.Scopes, &c.Policy.AllowSignup, &c.Policy.AllowLinking,
		&c.Policy.RequireVerifiedEmail, &enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderUnknown
		}
		return nil, fmt.Errorf("loading the identity provider: %w", err)
	}
	if !enabled {
		return nil, fmt.Errorf("identity provider %q is disabled", slug)
	}

	c.Kind = federation.Kind(kind)
	preset, err := federation.PresetFor(c.Kind)
	if err != nil {
		return nil, err
	}
	c.Preset = preset
	// The provider's own verification policy comes from the preset, not the
	// database: it is a property of how that provider actually behaves, not
	// something an operator should be able to talk themselves into.
	c.Policy.TrustsEmailVerification = preset.TrustsEmailVerification

	if len(secretSealed) > 0 {
		plain, err := root.Open(secretSealed, "idp_client_secret")
		if err != nil {
			return nil, fmt.Errorf("unsealing the provider's client secret: %w", err)
		}
		c.ClientSecret = string(plain)
	}
	return &c, nil
}

// PendingLogin is the server-side state of an external login in flight.
type PendingLogin struct {
	ProviderID   string
	OrgID        string
	Nonce        string
	CodeVerifier string
	LinkUserID   string
	ReturnTo     string
}

// BeginFederatedLogin records an in-flight login and returns state and the
// browser-binding value.
//
// Two secrets, not one. `state` travels to the provider and back, so it is
// visible to the provider and to anything that sees the redirect. `binding`
// goes into a cookie and never leaves this browser. The callback must present
// both, which is what stops an attacker completing their own login in a
// victim's browser -- the login-CSRF shape of this flow, where the victim ends
// up silently signed in to the ATTACKER's account and everything they then do
// lands in it.
func BeginFederatedLogin(ctx context.Context, tx pgx.Tx, p PendingLogin) (state, binding string, err error) {
	state, err = newOpaqueID()
	if err != nil {
		return "", "", err
	}
	binding, err = newOpaqueID()
	if err != nil {
		return "", "", err
	}
	stateHash := sha256.Sum256([]byte(state))
	bindingHash := sha256.Sum256([]byte(binding))

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.federated_logins
			(state_hash, provider_id, org_id, nonce, code_verifier, binding_hash,
			 link_user_id, return_to)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, NULLIF($7,'')::uuid, NULLIF($8,''))`,
		stateHash[:], p.ProviderID, p.OrgID, p.Nonce, p.CodeVerifier, bindingHash[:],
		p.LinkUserID, p.ReturnTo); err != nil {
		return "", "", fmt.Errorf("recording the pending login: %w", err)
	}
	return state, binding, nil
}

// ConsumeFederatedLogin validates and destroys the pending login.
//
// SINGLE USE, enforced by deleting in the same statement that reads. A state
// that can be presented twice is a code that can be replayed, and the delete
// has to be atomic with the read or two concurrent callbacks both succeed.
func ConsumeFederatedLogin(ctx context.Context, tx pgx.Tx, state, binding string) (*PendingLogin, error) {
	stateHash := sha256.Sum256([]byte(state))
	bindingHash := sha256.Sum256([]byte(binding))

	var p PendingLogin
	var storedBinding []byte
	err := tx.QueryRow(ctx, `
		DELETE FROM core.federated_logins
		WHERE state_hash = $1 AND expires_at > now()
		RETURNING provider_id::text, org_id::text, nonce, code_verifier,
		          binding_hash, COALESCE(link_user_id::text,''), COALESCE(return_to,'')`,
		stateHash[:]).Scan(&p.ProviderID, &p.OrgID, &p.Nonce, &p.CodeVerifier,
		&storedBinding, &p.LinkUserID, &p.ReturnTo)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("this sign-in link has already been used or has expired")
		}
		return nil, err
	}

	// Compared AFTER the row is destroyed, so a wrong binding still burns the
	// state rather than leaving it for another attempt.
	if len(storedBinding) != len(bindingHash) || !constantTimeEqual(storedBinding, bindingHash[:]) {
		return nil, fmt.Errorf("this sign-in was started in a different browser")
	}
	return &p, nil
}

// FindFederatedIdentity looks up a link by (provider, external subject).
//
// The ONLY lookup used to identify a returning user. There is deliberately no
// function here that finds a user by external email.
func FindFederatedIdentity(ctx context.Context, tx pgx.Tx, providerID, subject string) (userID string, err error) {
	err = tx.QueryRow(ctx, `
		SELECT user_id::text FROM core.federated_identities
		WHERE provider_id = $1::uuid AND subject = $2`, providerID, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return userID, err
}

// FindLocalUserByEmail finds a local account with this address.
//
// Used ONLY to refuse helpfully -- to tell somebody an account already exists
// and they should sign in to it first. It is never a reason to link, and the
// decision function in internal/federation treats its result as a refusal
// trigger rather than a match.
func FindLocalUserByEmail(ctx context.Context, tx pgx.Tx, orgID, email string) (userID string, err error) {
	if email == "" {
		return "", nil
	}
	err = tx.QueryRow(ctx, `
		SELECT id::text FROM core.users
		WHERE org_id = $1::uuid AND lower(email) = lower($2) AND status = 'active'`,
		orgID, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return userID, err
}

// LinkFederatedIdentity attaches an external account to a local user.
func LinkFederatedIdentity(ctx context.Context, tx pgx.Tx, providerID, userID, orgID string, ext federation.ExternalIdentity, verified bool) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.federated_identities
			(provider_id, user_id, org_id, subject, email, email_verified, last_login_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, NULLIF($5,''), $6, now())
		ON CONFLICT (provider_id, subject) DO UPDATE
			SET email = EXCLUDED.email, email_verified = EXCLUDED.email_verified,
			    last_login_at = now()`,
		providerID, userID, orgID, ext.Subject, ext.Email, verified)
	if err != nil {
		return fmt.Errorf("linking the external account: %w", err)
	}
	return nil
}

// CreateUserFromExternal creates a local account for a new external identity.
func CreateUserFromExternal(ctx context.Context, tx pgx.Tx, orgID string, ext federation.ExternalIdentity, verified bool) (string, error) {
	var userID string
	// No password credential is written. This account can only be reached
	// through the external provider until its owner sets one, which is correct:
	// inventing a password nobody chose would be a credential nobody controls.
	err := tx.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle, status)
		VALUES ($1::uuid, NULLIF($2,''),
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
		        'active')
		RETURNING id::text`, orgID, ext.Email).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("creating a user from the external identity: %w", err)
	}
	return userID, nil
}

// SweepExpiredFederatedLogins drops abandoned external logins.
func SweepExpiredFederatedLogins(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.federated_logins WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// constantTimeEqual compares without leaking where the difference is.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
