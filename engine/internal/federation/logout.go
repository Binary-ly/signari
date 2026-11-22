package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// A provider telling us somebody signed out there (8.19). The endpoint takes this from
// anybody on the internet and ends a person's sessions on it, so the token is the whole
// of the authentication: there is no setting that skips the signature, and nothing in
// it is read until a key from the provider's own JWKS has verified it.
//
// OpenID Connect Back-Channel Logout is not in specs/. The claims required here are the
// ones this deployment's own outbound logout tokens carry and those the implementation
// read for this row refuses without (see ROADMAP 8.19).

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// MaxLogoutTokenAge is how old a logout token may be. Past it the replay record of its
// jti could be swept, so an old token must not get as far as being checked against one.
const MaxLogoutTokenAge = 5 * time.Minute

// LogoutClaims is a verified logout token.
type LogoutClaims struct {
	Subject, SessionID string
	ID                 string
	IssuedAt           time.Time
}

type logoutTokenClaims struct {
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	IssuedAt  int64           `json:"iat"`
	Expiry    int64           `json:"exp"`
	ID        string          `json:"jti"`
	Subject   string          `json:"sub"`
	SessionID string          `json:"sid"`
	Nonce     *string         `json:"nonce"`
	Events    json.RawMessage `json:"events"`
}

// VerifyLogoutToken checks a logout token from this provider. A provider whose issuer
// is not fixed cannot have one checked against it, and is refused. Keys come through
// cache, because an open endpoint that fetched them per request would let anybody make
// this engine call the provider as fast as they could post.
func (c Config) VerifyLogoutToken(ctx context.Context, hc *http.Client, cache *JWKSCache, raw string,
	now time.Time) (*LogoutClaims, error) {

	want := c.issuer()
	if want == "" {
		return nil, errors.New("this provider has no fixed issuer, so a logout token cannot be tied to it")
	}
	sig, err := parseSignedToken(raw, "logout token")
	if err != nil {
		return nil, err
	}
	kid := ""
	if len(sig.Signatures) == 1 {
		kid = sig.Signatures[0].Header.KeyID
	}
	jwks, err := cache.Get(ctx, hc, c.jwksURL(), kid)
	if err != nil {
		return nil, err
	}
	payload, err := verifiedBy(sig, jwks, "logout token")
	if err != nil {
		return nil, err
	}
	var claims logoutTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("the logout token's claims did not parse: %w", err)
	}
	var events map[string]json.RawMessage
	if len(claims.Events) > 0 {
		if err := json.Unmarshal(claims.Events, &events); err != nil {
			return nil, fmt.Errorf("the logout token's events did not parse: %w", err)
		}
	}
	issued := time.Unix(claims.IssuedAt, 0)
	switch {
	case claims.Issuer != want:
		return nil, fmt.Errorf("the logout token's issuer is %q, expected %q", claims.Issuer, want)
	case !audienceContains(claims.Audience, c.ClientID):
		return nil, errors.New("the logout token was issued for a different application")
	case claims.IssuedAt == 0:
		return nil, errors.New("the logout token has no iat")
	case claims.ID == "":
		return nil, errors.New("the logout token has no jti, so a replay could not be told from a retry")
	case claims.Subject == "" && claims.SessionID == "":
		return nil, errors.New("the logout token names neither a subject nor a session")
	case claims.Nonce != nil:
		// What tells it from an ID token, which must never be accepted as one.
		return nil, errors.New("the logout token carries a nonce")
	case events[backchannelLogoutEvent] == nil:
		return nil, errors.New("the logout token does not carry the back-channel logout event")
	case issued.After(now.Add(federationClockSkew)):
		return nil, errors.New("the logout token is issued in the future")
	case now.Sub(issued) > MaxLogoutTokenAge:
		return nil, errors.New("the logout token is too old")
	case claims.Expiry != 0 && now.After(time.Unix(claims.Expiry, 0).Add(federationClockSkew)):
		return nil, errors.New("the logout token has expired")
	}
	return &LogoutClaims{Subject: claims.Subject, SessionID: claims.SessionID, ID: claims.ID, IssuedAt: issued}, nil
}
