package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// Authorizing a target that takes the authorization code grant (7.14), as
// `signari scim authorize` and the Admin API's authorization routes do: one copy,
// so the two cannot come to mean different things by "authorized".
//
// Two steps with a person between them. BeginAuthorization records what the code
// must come back with and answers where to send them; they sign in at the target
// and agree; ExchangeAuthorization redeems the code that comes back for a refresh
// token, which Grant.Keep holds. Every pass afterwards asks for an access token
// with it (scim.RefreshTokens).

// AuthorizationWait is how long a started authorization waits for its code: long
// enough to sign in somewhere with a second factor, short enough that a state
// found later in a browser's history opens nothing.
const AuthorizationWait = 10 * time.Minute

// Authorization is one started: where to send the person, the state their code
// comes back with, and until when.
type Authorization struct {
	URL   string
	State string
	Until time.Time
}

// Grant is a refresh token an authorization left, sealed, waiting to be kept.
type Grant struct {
	target scim.Target
	sealed []byte
}

func noAuthorizationCode(slug string) error {
	return targetInvalid{fmt.Sprintf("target %q takes no authorization code grant: give it an authorization "+
		"URL, where somebody signs in, with its token URL and client id", slug)}
}

// authorizableTarget is the target slug names, any kind refused but one that takes
// the authorization code grant.
func authorizableTarget(ctx context.Context, db DB, root *keys.RootKey, orgID, slug string) (scim.Target, error) {
	if root == nil {
		return scim.Target{}, fmt.Errorf("the target's secret and what an authorization leaves are sealed " +
			"under SIGNARI_ROOT_KEY, which is not loaded")
	}
	t, err := store.SCIMTargetForAuthorization(ctx, db, root, orgID, slug)
	if errors.Is(err, store.ErrSCIMTargetUnknown) {
		return scim.Target{}, ErrTargetUnknown
	}
	if err != nil {
		return scim.Target{}, err
	}
	if t.OAuthAuthorizeURL == "" {
		return scim.Target{}, noAuthorizationCode(slug)
	}
	return t, nil
}

// BeginAuthorization starts an authorization of a target, for its code to come back
// to redirectURI, replacing one that was waiting. The PKCE verifier (RFC 7636) stays
// here, sealed: the code comes back through a browser, and a code taken there is
// worth nothing without it.
func BeginAuthorization(ctx context.Context, db DB, root *keys.RootKey, orgID, slug,
	redirectURI string) (Authorization, error) {
	if err := scim.CheckRedirectURI(redirectURI); err != nil {
		return Authorization{}, targetInvalid{err.Error()}
	}
	t, err := authorizableTarget(ctx, db, root, orgID, slug)
	if err != nil {
		return Authorization{}, err
	}
	state, err := randomValue()
	if err != nil {
		return Authorization{}, err
	}
	verifier, err := randomValue()
	if err != nil {
		return Authorization{}, err
	}
	sealed, err := root.Seal([]byte(verifier), "scim_pkce_verifier")
	if err != nil {
		return Authorization{}, fmt.Errorf("sealing the PKCE verifier: %w", err)
	}
	to, err := scim.AuthorizationURL(t, redirectURI, state, verifier)
	if err != nil {
		return Authorization{}, targetInvalid{err.Error()}
	}
	until := time.Now().Add(AuthorizationWait)
	if err := store.StartSCIMAuthorization(ctx, db, t.ID, stateHash(state), sealed, redirectURI, until); err != nil {
		if errors.Is(err, store.ErrSCIMTargetUnknown) {
			// Its grant changed since it was read.
			return Authorization{}, noAuthorizationCode(slug)
		}
		return Authorization{}, err
	}
	return Authorization{URL: to, State: state, Until: until}, nil
}

// ExchangeAuthorization finishes an authorization with the state and code its
// sign-in sent back. The authorization is spent first, whatever happens after, so a
// code is never redeemed twice; one the token endpoint refuses means starting again.
func ExchangeAuthorization(ctx context.Context, db DB, root *keys.RootKey, hc *http.Client, orgID, slug, state,
	code string) (Grant, error) {
	if state == "" || code == "" {
		return Grant{}, targetInvalid{"give the state and the code the sign-in at the target sent back"}
	}
	t, err := authorizableTarget(ctx, db, root, orgID, slug)
	if err != nil {
		return Grant{}, err
	}
	sealedVerifier, redirectURI, err := store.SpendSCIMAuthorization(ctx, db, t.ID, stateHash(state))
	if err != nil {
		return Grant{}, err
	}
	verifier, err := root.Open(sealedVerifier, "scim_pkce_verifier")
	if err != nil {
		return Grant{}, fmt.Errorf("unsealing the PKCE verifier: %w", err)
	}
	refresh, err := scim.ExchangeCode(ctx, hc, t, code, redirectURI, string(verifier))
	if err != nil {
		return Grant{}, err
	}
	sealed, err := root.Seal([]byte(refresh), "scim_refresh_token")
	if err != nil {
		return Grant{}, fmt.Errorf("sealing the refresh token: %w", err)
	}
	return Grant{target: t, sealed: sealed}, nil
}

// Keep holds the refresh token for the target's passes and answers when it was
// given, or store.ErrSCIMGrantChanged when the grant changed meanwhile.
func (g Grant) Keep(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (time.Time, error) {
	return store.KeepSCIMGrant(ctx, q, g.target, g.sealed)
}

// randomValue is 32 random octets, base64url: a state nobody can guess, and a PKCE
// verifier of the 43 characters RFC 7636 asks for at least (specs/rfc7636.txt:406-408).
func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// stateHash is what is kept of a state: enough to recognise it, not to forge it.
func stateHash(state string) []byte {
	sum := sha256.Sum256([]byte(state))
	return sum[:]
}
