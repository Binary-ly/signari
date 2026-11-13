package scim

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// A target that takes the authorization code grant: somebody who administers the
// target signs in there once and agrees, and the refresh token that leaves is how
// every pass afterwards asks for an access token. The client credentials grant has
// no person in it, and some targets issue tokens only to one.

// RefreshTokens keeps an authorization code target's refresh token between passes.
type RefreshTokens interface {
	// Rotate calls use with the refresh token held now, "" when there is none, and
	// keeps what use returns in its place when that is not empty. The target is held
	// while use runs, so two passes never spend one refresh token: an authorization
	// server that rotates them takes the second use of one as a stolen token and
	// ends the grant (specs/draft-ietf-oauth-v2-1-17.txt:2660-2672).
	Rotate(ctx context.Context, use func(current string) (next string, err error)) error
}

// ErrNotAuthorized is a target that takes the authorization code grant and has no
// refresh token yet, or no longer has one.
var ErrNotAuthorized = errors.New("nobody has authorized this target yet: sign in at it with " +
	"`signari scim authorize`, or the Admin API's authorization route")

// refresh asks for an access token with the refresh token held, and keeps the one
// the token endpoint issues in its place, since "the client MUST discard the old
// refresh token and replace it with the new refresh token" (specs/rfc6749.txt:2656-2658).
// One a token endpoint does not replace is still good, and stays.
func (c *Client) refresh(ctx context.Context) (issuedToken, error) {
	if c.target.Refresh == nil {
		return issuedToken{}, errors.New("this target's refresh token is kept in the database, and this " +
			"client was given no way to reach it")
	}
	var issued issuedToken
	err := c.target.Refresh.Rotate(ctx, func(current string) (string, error) {
		if current == "" {
			return "", ErrNotAuthorized
		}
		// No scope: one left out is the scope the grant was given with (:2597-2602),
		// which is what a person agreed to.
		got, err := requestToken(ctx, c.http, c.target, url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {current}})
		if err != nil {
			return "", err
		}
		// Kept before the answer is checked further: once issued, the new refresh
		// token is the only one, whatever else is wrong with the response.
		issued = got
		return got.RefreshToken, nil
	})
	var refused *Error
	if errorsAs(err, &refused) && refused.OAuthError == "invalid_grant" {
		// The refresh token was revoked or has expired (:2500-2505), or a response
		// carrying its replacement never arrived; nothing here can renew it.
		return issuedToken{}, fmt.Errorf("%w; the grant has ended, so the target must be authorized again "+
			"with `signari scim authorize`", err)
	}
	return issued, err
}

// CheckAuthorizeURL refuses where a person could not safely be sent to sign in.
func CheckAuthorizeURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return fmt.Errorf("the authorization URL %q is not an absolute URL", raw)
	case u.Scheme != "https":
		// Somebody signs in there, and the code comes back through it.
		return errors.New("the authorization URL must be https: a person signs in there")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		// "The endpoint URI MUST NOT include a fragment component" (specs/rfc6749.txt:994-995).
		return errors.New("the authorization URL must not have a fragment")
	}
	return nil
}

// CheckRedirectURI refuses where a code may not be sent back to: https, or http to
// a loopback address, the one exception OAuth 2.1 makes
// (specs/draft-ietf-oauth-v2-1-17.txt:915-917), and no fragment (specs/rfc6749.txt:1052-1057).
func CheckRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return fmt.Errorf("the redirect URI %q is not an absolute URL", raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("the redirect URI must not have a fragment")
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && Loopback(u):
		return nil
	}
	return errors.New("the redirect URI must be https, or http to 127.0.0.1 or [::1]: the code arrives " +
		"there, and the code is what a refresh token is issued for")
}

// Loopback says whether u names the loopback interface by its address. Not the name
// localhost, which OAuth 2.1 calls NOT RECOMMENDED since it can resolve elsewhere
// (specs/draft-ietf-oauth-v2-1-17.txt:4394-4402).
func Loopback(u *url.URL) bool {
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// Challenge is a PKCE verifier's S256 challenge,
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) (specs/rfc7636.txt:434).
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizationURL is where a person is sent to sign in at t and agree, for the
// code to come back to redirectURI with state. The query the authorization URL
// already has "MUST be retained" (specs/rfc6749.txt:992-994), and anything in it
// this request sets is set as this request says.
func AuthorizationURL(t Target, redirectURI, state, verifier string) (string, error) {
	if err := CheckAuthorizeURL(t.OAuthAuthorizeURL); err != nil {
		return "", err
	}
	u, err := url.Parse(t.OAuthAuthorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", t.OAuthClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	// "If the client is capable of using "S256", it MUST use "S256"" (specs/rfc7636.txt:436-437).
	q.Set("code_challenge", Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	if t.OAuthScope != "" {
		q.Set("scope", t.OAuthScope)
	} else {
		q.Del("scope")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode redeems the code a person's sign-in sent back, with the redirect URI
// the request named, which must be "identical" (specs/rfc6749.txt:1600-1603), and the
// PKCE verifier, and answers the refresh token it was issued. An answer with none is
// refused: a pass could then ask for nothing once the access token ran out, so the
// authorization would look done and stop working within the hour.
func ExchangeCode(ctx context.Context, hc *http.Client, t Target, code, redirectURI, verifier string) (string, error) {
	issued, err := requestToken(ctx, hc, t, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}})
	if err != nil {
		return "", err
	}
	if err := issued.usable(); err != nil {
		return "", err
	}
	if issued.RefreshToken == "" {
		return "", errors.New("the token endpoint issued no refresh token, so no pass could ask for an access " +
			"token after this one expires; the target may give one only for a scope such as offline_access")
	}
	return issued.RefreshToken, nil
}
