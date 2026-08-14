package oauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/clients"
)

// TokenRequest is a parsed POST to /oauth2/token.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Scope        string
	Resources    []string

	// Client credentials, from wherever they were presented.
	ClientID     string
	ClientSecret string
	// ClientAssertion is a private_key_jwt proof (RFC 7523). Parsed here only so
	// the authentication gate can see that a credential was presented; it is
	// verified elsewhere, against the client's registered keys.
	ClientAssertion     string
	ClientAssertionType string
	AuthMethod          string // client_secret_basic | client_secret_post | none
}

// TokenError is an RFC 6749 §5.2 token endpoint error.
type TokenError struct {
	Code        string
	Description string
	// Status is the HTTP status. invalid_client is 401, everything else 400.
	Status int
}

func (e *TokenError) Error() string { return e.Code + ": " + e.Description }

func tokenErr(code, desc string) *TokenError {
	status := http.StatusBadRequest
	if code == "invalid_client" {
		status = http.StatusUnauthorized
	}
	return &TokenError{Code: code, Description: desc, Status: status}
}

// ParseTokenRequest reads the form body and the Authorization header.
//
// Credentials may arrive in exactly one place. Accepting them in both and
// preferring one silently lets a caller present a valid header alongside a
// different body client_id, which is a confusion primitive -- so presenting both
// is an error rather than a precedence question.
func ParseTokenRequest(header http.Header, form url.Values) (TokenRequest, *TokenError) {
	r := TokenRequest{
		GrantType:    form.Get("grant_type"),
		Code:         form.Get("code"),
		RedirectURI:  form.Get("redirect_uri"),
		CodeVerifier: form.Get("code_verifier"),
		RefreshToken: form.Get("refresh_token"),
		Scope:        form.Get("scope"),
		Resources:    form["resource"],
	}

	basicID, basicSecret, hasBasic := parseBasic(header.Get("Authorization"))
	bodyID, bodySecret := form.Get("client_id"), form.Get("client_secret")
	r.ClientAssertion = form.Get("client_assertion")
	r.ClientAssertionType = form.Get("client_assertion_type")

	// A client assertion and a secret are two credentials for one request, and
	// accepting both leaves which one authenticated the caller up to whichever
	// check happens to run first. Refused rather than resolved by precedence.
	if r.ClientAssertion != "" && (bodySecret != "" || hasBasic) {
		return r, tokenErr("invalid_request",
			"present either a client assertion or a client secret, not both")
	}

	switch {
	case hasBasic && bodySecret != "":
		return r, tokenErr("invalid_request",
			"client credentials presented both in the Authorization header and the body")
	case hasBasic:
		if bodyID != "" && bodyID != basicID {
			return r, tokenErr("invalid_request",
				"client_id in the body does not match the Authorization header")
		}
		r.ClientID, r.ClientSecret, r.AuthMethod = basicID, basicSecret, "client_secret_basic"
	case bodySecret != "":
		r.ClientID, r.ClientSecret, r.AuthMethod = bodyID, bodySecret, "client_secret_post"
	case r.ClientAssertion != "":
		r.ClientID, r.AuthMethod = bodyID, "private_key_jwt"
	default:
		// A public client authenticates with PKCE, not a secret.
		r.ClientID, r.AuthMethod = bodyID, "none"
	}
	return r, nil
}

// parseBasic decodes RFC 6749 §2.3.1 client_secret_basic. The userid and password
// are form-urlencoded before base64, which implementations routinely forget --
// a secret containing a '+' or a space is silently wrong without it.
func parseBasic(h string) (id, secret string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, prefix))
	if err != nil {
		return "", "", false
	}
	id, secret, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	uid, err1 := url.QueryUnescape(id)
	pw, err2 := url.QueryUnescape(secret)
	if err1 != nil || err2 != nil {
		return "", "", false
	}
	return uid, pw, true
}

// GrantRecord is the stored authorization code, as read back at redemption.
type GrantRecord struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce binds the ID token to the client's own authorization request. Without
	// it an ID token can be replayed into a different session, which is the whole
	// reason OIDC requires the claim to be echoed verbatim.
	Nonce      string
	Scopes     []string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// ValidateCodeRedemption checks a code exchange.
//
// The four rules that matter, each of which has been a real vulnerability:
//
//  1. The code is bound to the client it was issued to. A code issued to client A
//     must not be redeemable by client B even with valid credentials for B.
//  2. redirect_uri must equal the one used at the authorization request
//     (RFC 6749 §4.1.3), not merely be *a* registered URI for the client.
//  3. The code is single use. A second redemption is treated as theft: the caller
//     gets an error AND the whole grant is revoked, because either the code
//     leaked or the client is broken, and both warrant killing the tokens.
//  4. PKCE is verified before anything is minted.
//
// `alreadyConsumed` is returned separately from the error so the caller knows it
// must revoke the token family, not merely reject the request.
func ValidateCodeRedemption(req TokenRequest, c *clients.Client, g *GrantRecord, now time.Time) (alreadyConsumed bool, e *TokenError) {
	if c == nil {
		return false, tokenErr("invalid_client", "unknown client")
	}
	if !c.Enabled {
		return false, tokenErr("invalid_client", "client is disabled")
	}
	if !c.AllowsGrantType("authorization_code") {
		return false, tokenErr("unauthorized_client", "client may not use the authorization_code grant")
	}
	if req.Code == "" {
		return false, tokenErr("invalid_request", "code is required")
	}
	if g == nil {
		return false, tokenErr("invalid_grant", "authorization code is unknown or expired")
	}

	// 1. Binding. Checked before expiry so a leaked code cannot be probed against
	// other clients to learn whether it is still live.
	if g.ClientID != req.ClientID {
		return false, tokenErr("invalid_grant", "authorization code was not issued to this client")
	}

	// 3. Reuse. Checked early: once we know the code was already spent, the only
	// correct outcome is rejection plus revocation, whatever else is wrong.
	if g.ConsumedAt != nil {
		return true, tokenErr("invalid_grant", "authorization code has already been used")
	}

	if !now.Before(g.ExpiresAt) {
		return false, tokenErr("invalid_grant", "authorization code has expired")
	}

	// 2. Exactly the URI used at authorization. Not "any registered URI" -- that
	// weaker check lets a code obtained via one callback be redeemed through
	// another, which is the classic code-injection setup.
	if req.RedirectURI == "" {
		return false, tokenErr("invalid_request", "redirect_uri is required")
	}
	if req.RedirectURI != g.RedirectURI {
		return false, tokenErr("invalid_grant",
			"redirect_uri does not match the one used in the authorization request")
	}

	// 4. PKCE.
	if g.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return false, tokenErr("invalid_request", "code_verifier is required")
		}
		if err := VerifyPKCE(g.CodeChallengeMethod, g.CodeChallenge, req.CodeVerifier); err != nil {
			return false, tokenErr("invalid_grant", "code_verifier is invalid")
		}
	} else if c.RequirePKCE {
		// A stored grant with no challenge for a PKCE-required client means the
		// authorization endpoint let something through it should not have.
		return false, tokenErr("invalid_grant", "authorization code was issued without PKCE")
	}

	return false, nil
}

// RequireClientAuth reports whether this client must present a secret.
//
// Confidential clients always authenticate. Public clients must NOT send a
// secret: a public client with a secret is a secret embedded in a distributable
// binary, and accepting it would legitimise that.
func RequireClientAuth(c *clients.Client, req TokenRequest) *TokenError {
	switch c.Type {
	case "confidential":
		// A client assertion IS client authentication (RFC 7523 §2.2). This gate
		// predates private_key_jwt and demanded a secret, so a correctly
		// authenticated client was refused before its assertion was ever looked
		// at -- and the error said "authentication is required" to a caller that
		// had supplied it.
		//
		// Only the PRESENCE is checked here. Whether the assertion is any good is
		// decided later, against the client's registered keys, by code that can
		// read them.
		if req.ClientAssertion != "" {
			return nil
		}
		if req.AuthMethod == "none" || req.ClientSecret == "" {
			return tokenErr("invalid_client", "client authentication is required")
		}
	case "public":
		if req.ClientSecret != "" {
			return tokenErr("invalid_client", "public clients must not present a client secret")
		}
	default:
		return tokenErr("invalid_client", fmt.Sprintf("unknown client type %q", c.Type))
	}
	return nil
}

// ValidateGrantType rejects everything we do not implement, before any lookup.
func ValidateGrantType(gt string) *TokenError {
	switch gt {
	case "authorization_code", "refresh_token", "client_credentials",
		GrantTypeTokenExchange:
		return nil
	case "":
		return tokenErr("invalid_request", "grant_type is required")
	case "password":
		// Removed by OAuth 2.1. Named explicitly so the error is actionable
		// rather than a generic "unsupported".
		return tokenErr("unsupported_grant_type",
			"the resource owner password credentials grant is not supported and will not be")
	case "implicit":
		return tokenErr("unsupported_grant_type", "the implicit flow is not supported")
	default:
		return tokenErr("unsupported_grant_type", fmt.Sprintf("grant_type %q is not supported", gt))
	}
}
