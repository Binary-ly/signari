// Package oauth implements the authorization endpoint's request validation.
package oauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/sulimanbenhalim/idp/engine/internal/clients"
)

// AuthzRequest is a parsed, not-yet-validated /oauth2/authorize request.
type AuthzRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseMode        string
	Prompt              string
	Resources           []string // RFC 8707 `resource`, repeatable
}

// ParseAuthz reads the query parameters. It does no validation: parsing and
// validating are separate so the validator can decide, per failure, whether the
// error may be redirected at all.
func ParseAuthz(q url.Values) AuthzRequest {
	return AuthzRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		ResponseMode:        q.Get("response_mode"),
		Prompt:              q.Get("prompt"),
		Resources:           q["resource"],
	}
}

// Disposition says how an authorization error must reach the user agent.
type Disposition int

const (
	// DispositionDirect renders an error page on the provider. Used when the
	// request cannot be trusted enough to redirect anywhere.
	DispositionDirect Disposition = iota
	// DispositionRedirect sends the error back to the client's registered
	// redirect_uri as OAuth error parameters.
	DispositionRedirect
)

// AuthzError carries the OAuth error code plus how it may be delivered.
type AuthzError struct {
	Code        string
	Description string
	Disposition Disposition
}

func (e *AuthzError) Error() string { return e.Code + ": " + e.Description }

func direct(code, desc string) *AuthzError {
	return &AuthzError{Code: code, Description: desc, Disposition: DispositionDirect}
}

func redirectErr(code, desc string) *AuthzError {
	return &AuthzError{Code: code, Description: desc, Disposition: DispositionRedirect}
}

// ValidateAuthz checks an authorization request against the registered client.
//
// THE ORDER OF THESE CHECKS IS THE SECURITY PROPERTY, not a style choice.
//
// Everything that runs before the redirect_uri is confirmed to be registered
// must fail DIRECTLY -- rendering an error on the provider -- because redirecting
// to an unverified URI turns the authorization endpoint into an open redirector,
// which is both an RFC 9700 violation and a phishing primitive. Only once the
// redirect target is known-registered may errors be sent to it.
//
// The sequence is therefore:
//
//  1. client_id present            -> direct
//  2. client exists                -> direct
//  3. client enabled               -> direct   (read live from the DB, never cached)
//  4. redirect_uri present + exact -> direct
//     --- redirect_uri is now trusted; everything below may redirect ---
//  5. response_type
//  6. PKCE
//  7. scope
//  8. response_mode
func ValidateAuthz(req AuthzRequest, c *clients.Client, lookupErr error) *AuthzError {
	// 1-2. Without a known client there is no registered redirect URI, so there
	// is nowhere safe to send anything.
	if strings.TrimSpace(req.ClientID) == "" {
		return direct("invalid_request", "client_id is required")
	}
	if lookupErr != nil || c == nil {
		return direct("invalid_client", "unknown client")
	}

	if !c.Enabled {
		return direct("unauthorized_client", "client is disabled")
	}

	// 4. Exact match against the registered set. No default-if-only-one-registered
	// shortcut: that convenience has produced redirect bypasses elsewhere, and it
	// makes the request's meaning depend on registry state.
	if req.RedirectURI == "" {
		return direct("invalid_request", "redirect_uri is required")
	}
	if !c.HasRedirectURI(req.RedirectURI) {
		return direct("invalid_request", "redirect_uri is not registered for this client")
	}

	// --- From here the redirect target is trusted. ---

	// 5. Code flow only. Implicit and hybrid are removed by OAuth 2.1 and we do
	// not advertise them, so anything else is invalid rather than unsupported.
	if req.ResponseType == "" {
		return redirectErr("invalid_request", "response_type is required")
	}
	if req.ResponseType != "code" {
		return redirectErr("unsupported_response_type",
			fmt.Sprintf("response_type %q is not supported; only \"code\" is", req.ResponseType))
	}
	if !c.AllowsResponseType(req.ResponseType) {
		return redirectErr("unauthorized_client", "client may not use this response_type")
	}
	if !c.AllowsGrantType("authorization_code") {
		return redirectErr("unauthorized_client", "client may not use the authorization_code grant")
	}

	// 6. PKCE. Required for every client, public and confidential alike, per
	// RFC 9700 and OAuth 2.1.
	if c.RequirePKCE || req.CodeChallenge != "" {
		if req.CodeChallenge == "" {
			return redirectErr("invalid_request", "code_challenge is required")
		}
		method := req.CodeChallengeMethod
		if method == "" {
			// RFC 7636 defaults an absent method to "plain". We do not accept
			// plain, and silently upgrading the request to S256 would verify a
			// challenge the client never computed, so this must be explicit.
			return redirectErr("invalid_request",
				"code_challenge_method is required and must be S256")
		}
		if method != "S256" {
			return redirectErr("invalid_request",
				fmt.Sprintf("code_challenge_method %q is not supported; use S256", method))
		}
		if !c.AllowsPKCEMethod(method) {
			return redirectErr("invalid_request", "client may not use this code_challenge_method")
		}
		if !validChallenge(req.CodeChallenge) {
			return redirectErr("invalid_request",
				"code_challenge must be 43-128 characters of base64url without padding")
		}
	}

	// 7. Scope.
	scopes := strings.Fields(req.Scope)
	if len(scopes) == 0 {
		return redirectErr("invalid_scope", "at least the openid scope is required")
	}
	if !containsStr(scopes, "openid") {
		return redirectErr("invalid_scope", "the openid scope is required")
	}
	if bad := c.UnknownScopes(scopes); len(bad) > 0 {
		return redirectErr("invalid_scope",
			"client is not registered for scope(s): "+strings.Join(bad, ", "))
	}

	// 8. response_mode.
	//
	// `query` only. `fragment` is for front-channel token delivery, which this
	// server does not do.
	//
	// form_post is REFUSED rather than accepted-and-ignored. It used to be
	// accepted here and then silently treated as `query`, which is worse than
	// not supporting it: a client asking for form_post is usually doing so to
	// keep the response out of URLs, referrers and browser history, and getting
	// `query` back defeats exactly that. It has since been removed from
	// discovery too -- with `code` as the only response type there is nothing
	// sensitive in the redirect that form_post would protect, so it buys the
	// caller nothing and costs a SameSite=None cookie to implement.
	switch req.ResponseMode {
	case "", "query":
	case "form_post":
		return redirectErr("invalid_request",
			"response_mode form_post is not supported; the authorization code is returned in the query")
	default:
		return redirectErr("invalid_request",
			fmt.Sprintf("response_mode %q is not supported", req.ResponseMode))
	}

	return nil
}

// ErrorRedirect builds the URL an authorization error is sent to.
//
// `state` is echoed exactly as received, and `iss` is always included (RFC 9207)
// so a client can tell which provider answered -- the mix-up attack defence.
func ErrorRedirect(redirectURI, issuer, state string, e *AuthzError) (string, error) {
	if e.Disposition != DispositionRedirect {
		return "", fmt.Errorf("refusing to redirect a %s error: it has no verified redirect target", e.Code)
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("error", e.Code)
	if e.Description != "" {
		q.Set("error_description", e.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validChallenge checks the RFC 7636 shape: 43-128 characters drawn from the
// unreserved set. A challenge outside that range is malformed, and accepting a
// short one would weaken the binding it exists to provide.
func validChallenge(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}

func containsStr(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
