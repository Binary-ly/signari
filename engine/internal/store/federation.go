package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
)

// ErrProviderUnknown is returned when no external provider matches a slug.
var ErrProviderUnknown = errors.New("no identity provider with that name")

// SetIdentityProviderEnabled turns an upstream provider off or on: its sign-in
// and link routes, its SAML assertions and its jwt-bearer assertions, which
// every one of those paths reads per request. Audited, and the configuration
// version moves in the same transaction (ADR-008). Returns the organisation,
// or ErrProviderUnknown for a slug nobody registered.
//
// The column and its readers existed from the start, and nothing could set it
// to false: an operator whose upstream was compromised had no way to stop
// sign-ins through it short of SQL.
func SetIdentityProviderEnabled(ctx context.Context, db interface {
	Begin(context.Context) (pgx.Tx, error)
}, slug string, enabled bool) (string, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := LockConfigVersion(ctx, tx); err != nil {
		return "", err
	}
	var orgID string
	if err := tx.QueryRow(ctx, `
		UPDATE core.identity_providers SET enabled = $2, updated_at = now()
		 WHERE slug = $1 RETURNING org_id::text`, slug, enabled).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrProviderUnknown
		}
		return "", err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.identity_provider_updated", OrgID: orgID,
		Detail: map[string]any{"provider": slug, "enabled": enabled, "via": "cli"},
	}); err != nil {
		return "", fmt.Errorf("auditing the change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.config_version SET version = version + 1, bumped_at = now()
		 WHERE id = true`); err != nil {
		return "", fmt.Errorf("bumping the configuration version: %w", err)
	}
	return orgID, tx.Commit(ctx)
}

// UpstreamLogout is the end-session address and client id of the named provider,
// when the session came through a provider at all and this one is in its
// organisation, in service and has an address. Otherwise both are empty.
func UpstreamLogout(ctx context.Context, q Querier, sid, slug string) (endSession, clientID string, err error) {
	rows, err := q.Query(ctx, `
		SELECT p.end_session_url, p.client_id
		  FROM core.identity_providers p
		  JOIN core.sessions s ON s.org_id = p.org_id
		 WHERE s.sid = $1 AND 'fed' = ANY(s.amr)
		   AND p.slug = $2 AND p.enabled AND p.end_session_url IS NOT NULL`, sid, slug)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&endSession, &clientID); err != nil {
			return "", "", err
		}
	}
	return endSession, clientID, rows.Err()
}

// LoadIdentityProvider fetches an external provider by its URL slug.
func LoadIdentityProvider(ctx context.Context, db *pgxpool.Pool, root *keys.RootKey, slug string) (*federation.Config, error) {
	var (
		c            federation.Config
		kind         string
		secretSealed []byte
		keySealed    []byte
		certificate  string
		enabled      bool
		trustEmail   bool
	)
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, slug, display_name, kind, client_id,
		       client_secret, COALESCE(issuer,''), COALESCE(authorize_url,''),
		       COALESCE(token_url,''), COALESCE(userinfo_url,''), COALESCE(jwks_url,''),
		       scopes, allow_signup, allow_linking, require_verified_email, enabled,
		       trust_email_verification, mfa_amr, mfa_acr, COALESCE(end_session_url, ''),
		       token_auth_method, client_key, COALESCE(client_certificate, ''), forward_parameters,
		       userinfo_subject, userinfo_email, userinfo_email_verified, userinfo_name
		FROM core.identity_providers
		WHERE slug = $1`, slug).Scan(
		&c.ID, &c.OrgID, &c.Slug, &c.DisplayName, &kind, &c.ClientID,
		&secretSealed, &c.IssuerOverride, &c.AuthorizeOverride,
		&c.TokenOverride, &c.UserinfoOverride, &c.JWKSOverride,
		&c.Scopes, &c.Policy.AllowSignup, &c.Policy.AllowLinking,
		&c.Policy.RequireVerifiedEmail, &enabled, &trustEmail, &c.MFAAMR, &c.MFAACR, &c.EndSessionURL,
		&c.TokenAuth.Method, &keySealed, &certificate, &c.Forward,
		&c.Userinfo.Subject, &c.Userinfo.Email, &c.Userinfo.EmailVerified, &c.Userinfo.Name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderUnknown
		}
		return nil, fmt.Errorf("loading the identity provider: %w", err)
	}
	if !enabled {
		return nil, fmt.Errorf("identity provider %q is disabled", slug)
	}
	// An assertion issuer is not a sign-in provider and must never be reachable
	// as one.
	//
	// It has no authorization endpoint, so /login/with/<slug> would build a
	// redirect to the empty string -- a broken login button produced as a side
	// effect of configuring a machine-to-machine trust. The schema also refuses
	// allow_signup and allow_linking on this kind; this is the other half, at the
	// one function the interactive path loads providers through.
	if kind == string(federation.KindAssertion) {
		return nil, fmt.Errorf("identity provider %q publishes assertion signing keys "+
			"only and cannot be signed in through", slug)
	}

	c.Kind = federation.Kind(kind)
	preset, err := federation.PresetFor(c.Kind)
	if err != nil {
		return nil, err
	}
	c.Preset = preset
	// For a NAMED provider the policy comes from the preset, not the database:
	// it describes how that provider actually behaves and what this package does
	// about it, which is not something an operator should be able to talk
	// themselves out of.
	//
	// For a generic OIDC provider there is nothing to know in advance, so the
	// operator's setting is the only available answer -- off unless they say so.
	if c.Kind == federation.KindOIDC || c.Kind == federation.KindOAuth2 {
		c.Policy.TrustsEmailVerification = trustEmail
	} else {
		c.Policy.TrustsEmailVerification = preset.TrustsEmailVerification
	}

	if len(secretSealed) > 0 {
		plain, err := root.Open(secretSealed, "idp_client_secret")
		if err != nil {
			return nil, fmt.Errorf("unsealing the provider's client secret: %w", err)
		}
		c.ClientSecret = string(plain)
	}
	if len(keySealed) > 0 {
		plain, err := root.Open(keySealed, sealContextIdPClientKey)
		if err != nil {
			return nil, fmt.Errorf("unsealing the provider's client key: %w", err)
		}
		if c.TokenAuth.Key, c.TokenAuth.Certificate, err = federation.ParseClientKey(plain, []byte(certificate)); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

const sealContextIdPClientKey = "idp_client_key"

// IdPTokenAuth is how this engine proves itself at a provider's token endpoint.
// ClientKey and ClientCertificate are PEM; absent, what is held is kept.
type IdPTokenAuth struct {
	Method                       string
	ClientKey, ClientCertificate []byte
}

// SetIdPTokenAuth records it, refusing a method the provider would refuse on
// somebody's first sign-in: one with nothing held to prove it with.
func SetIdPTokenAuth(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, slug string, a IdPTokenAuth) error {
	var kind string
	var secret, heldKey []byte
	var heldCert string
	err := q.QueryRow(ctx, `SELECT kind, client_secret, client_key, COALESCE(client_certificate, '')
		FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`, orgID, slug).
		Scan(&kind, &secret, &heldKey, &heldCert)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrProviderUnknown
	}
	if err != nil {
		return err
	}
	if kind == "saml" || kind == "assertion" {
		return idpInvalid{fmt.Sprintf("%s is a %s provider, which has no token endpoint to sign in to", slug, kind)}
	}

	certificate := heldCert
	if len(a.ClientCertificate) > 0 {
		certificate = string(a.ClientCertificate)
	}
	var sealed any
	switch {
	case len(a.ClientKey) > 0:
		if _, _, err := federation.ParseClientKey(a.ClientKey, []byte(certificate)); err != nil {
			return idpInvalid{err.Error()}
		}
		if root == nil {
			return errors.New("sealing a client key needs the root key")
		}
		s, err := root.Seal(a.ClientKey, sealContextIdPClientKey)
		if err != nil {
			return fmt.Errorf("sealing the client key: %w", err)
		}
		sealed = s
	case len(heldKey) > 0 && len(a.ClientCertificate) > 0:
		if root == nil {
			return errors.New("checking the certificate against the held key needs the root key")
		}
		plain, err := root.Open(heldKey, sealContextIdPClientKey)
		if err != nil {
			return fmt.Errorf("unsealing the provider's client key: %w", err)
		}
		if _, _, err := federation.ParseClientKey(plain, a.ClientCertificate); err != nil {
			return idpInvalid{err.Error()}
		}
	}

	hasKey := sealed != nil || len(heldKey) > 0
	switch a.Method {
	case federation.AuthSecretPost:
		// With no secret this is the public client it has always been able to be.
	case federation.AuthSecretBasic:
		if len(secret) == 0 {
			return idpInvalid{fmt.Sprintf("%s has no client secret to send", slug)}
		}
	case federation.AuthPrivateKeyJWT:
		if !hasKey {
			return idpInvalid{"private_key_jwt needs a client key"}
		}
	case federation.AuthTLS:
		if !hasKey || certificate == "" {
			return idpInvalid{"tls_client_auth needs a client key and its certificate"}
		}
	default:
		return idpInvalid{fmt.Sprintf("%q is not a token authentication method: use %s, %s, %s or %s", a.Method,
			federation.AuthSecretPost, federation.AuthSecretBasic, federation.AuthPrivateKeyJWT, federation.AuthTLS)}
	}
	_, err = q.Exec(ctx, `UPDATE core.identity_providers
		   SET token_auth_method = $3, client_key = COALESCE($4::bytea, client_key),
		       client_certificate = NULLIF($5, ''), updated_at = now()
		 WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, a.Method, sealed, certificate)
	return err
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
func FindLocalUserByEmail(ctx context.Context, q rowQuerier, orgID, email string) (userID string, err error) {
	if email == "" {
		return "", nil
	}
	err = q.QueryRow(ctx, `
		SELECT id::text FROM core.users
		WHERE org_id = $1::uuid AND email_fold = lower($2) AND status = 'active'`,
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
	// The provider vouching for the address this account holds proves it, as a
	// link followed from that mailbox does. Another address proves nothing here.
	if verified && ext.Email != "" {
		tag, err := tx.Exec(ctx, `UPDATE core.users SET email_verified_at = now()
			WHERE id = $1::uuid AND org_id = $2::uuid AND email_verified_at IS NULL AND email_fold = lower($3)`,
			userID, orgID, ext.Email)
		if err != nil {
			return fmt.Errorf("recording the address the provider vouched for: %w", err)
		}
		if tag.RowsAffected() > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM core.email_verifications WHERE user_id = $1::uuid`, userID); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateUserFromExternal creates a local account for a new external identity.
func CreateUserFromExternal(ctx context.Context, tx pgx.Tx, orgID string, ext federation.ExternalIdentity) (string, error) {
	var userID string
	// No password credential is written. This account can only be reached
	// through the external provider until its owner sets one, which is correct:
	// inventing a password nobody chose would be a credential nobody controls.
	err := tx.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, display_name, user_handle, status)
		VALUES ($1::uuid, NULLIF($2,''), NULLIF(btrim($3), ''),
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
		        'active')
		RETURNING id::text`, orgID, ext.Email, ext.Name).Scan(&userID)
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
