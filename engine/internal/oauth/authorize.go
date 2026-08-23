// Package oauth implements the authorization endpoint's request validation.
package oauth

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"signari.dev/engine/internal/rar"
	"sort"
	"strconv"
	"strings"

	"signari.dev/engine/internal/clients"
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
	ACRValues           string
	MaxAge              *int
	Resources           []string // RFC 8707 `resource`, repeatable
	// RawAuthorizationDetails is RFC 9396 `authorization_details` as sent.
	RawAuthorizationDetails string
	// AuthorizationDetails is the same thing parsed and validated against the
	// registered types. Carried on the request rather than re-parsed downstream,
	// so exactly one place decides what was asked for.
	AuthorizationDetails []rar.Detail

	// DPoPJKT is RFC 9449 §10's `dpop_jkt`: the JWK Thumbprint of the key the
	// issued code may be redeemed with.
	//
	// It closes the flow end to end in a way PKCE does not. PKCE binds the code
	// to a secret the client generated; this binds it to the KEY the resulting
	// token will be bound to, so a code intercepted in the front channel cannot
	// be redeemed by an attacker's own DPoP key.
	//
	// OPTIONAL per §10. A code issued without one is redeemable by any
	// correctly-proofed key, which is the behaviour that existed before.
	DPoPJKT string
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
		DPoPJKT:             q.Get("dpop_jkt"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		ResponseMode:        q.Get("response_mode"),
		Prompt:              q.Get("prompt"),
		ACRValues:           q.Get("acr_values"),
		// A POINTER, so "absent" and "max_age=0" stay distinguishable. They mean
		// opposite things: absent is "reuse whatever you have", zero is
		// "authenticate right now".
		MaxAge:    parseMaxAge(q.Get("max_age")),
		Resources: q["resource"],
		// The RAW parameter. Parsing it needs the registered types, which are a
		// database read, so it happens in the handler -- and this field keeps the
		// unparsed text so nothing downstream has to fetch it from the query
		// again and risk reading a different value than the one validated.
		RawAuthorizationDetails: q.Get(rar.Param),
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

	// 5. Code flow, and hybrid `code id_token` where a client is explicitly
	// permitted it.
	//
	// Never `token` in any combination. Those put an ACCESS token in the
	// browser's address bar, where it lands in history, referrers and every log
	// between here and there -- which is why OAuth 2.1 removes them. `code
	// id_token` is a different proposition: the id_token asserts who signed in
	// and is bound to the code by c_hash, and the access token still only ever
	// crosses the back channel.
	if req.ResponseType == "" {
		return redirectErr("invalid_request", "response_type is required")
	}
	switch NormaliseResponseType(req.ResponseType) {
	case "code":
	case "code id_token":
		if c == nil || !c.AllowHybrid {
			return redirectErr("unsupported_response_type",
				"response_type \"code id_token\" is off for this client. It exists for "+
					"applications being migrated in that cannot be changed first; enable "+
					"it deliberately with `signari client set-hybrid`")
		}
		// The nonce is what ties the id_token to this browser session. Optional
		// for the code flow, where the token arrives over the back channel;
		// mandatory here, because without it a front-channel id_token can be
		// replayed into somebody else's session.
		if req.Nonce == "" {
			return redirectErr("invalid_request",
				"nonce is required with response_type \"code id_token\": it is what "+
					"stops the id_token being replayed into another session")
		}
	default:
		return redirectErr("unsupported_response_type",
			fmt.Sprintf("response_type %q is not supported. \"code\" always; "+
				"\"code id_token\" where a client is permitted it. Anything containing "+
				"\"token\" is refused: an access token must never cross the front channel",
				req.ResponseType))
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

	// dpop_jkt is a SHA-256 JWK Thumbprint (RFC 7638), so base64url of 32 bytes
	// -- 43 characters, unpadded. Checked here rather than at redemption
	// because a malformed value can never match any real thumbprint, and
	// discovering that at the token endpoint means the person has already
	// signed in and been redirected before anything says the request was wrong.
	if req.DPoPJKT != "" && !validThumbprint(req.DPoPJKT) {
		return redirectErr("invalid_request",
			"dpop_jkt must be the base64url SHA-256 JWK Thumbprint of the "+
				"proof-of-possession key: 43 characters, unpadded")
	}

	// §3.1.2.1's prompt exclusivity. Checked here, with the other request
	// parameters, because it is a property of the request rather than of the
	// session -- a client asking for "none login" has a bug whether or not
	// anybody is signed in, and discovering that only when a session happens to
	// be missing would make the error intermittent.
	if err := ValidatePrompt(req.Prompt); err != nil {
		return redirectErr("invalid_request", err.Error())
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

	// 7b. RFC 8707 resource indicators.
	//
	// Validated because the requested resources BECOME the access token's
	// audience. Unchecked, a client could name any audience it liked -- including
	// another service's identifier -- and mint a token that service would accept.
	// The parameter exists to NARROW a token, and it must not be usable to widen
	// one.
	if err := validateResources(req.Resources); err != nil {
		return redirectErr("invalid_target", err.Error())
	}

	// 8. response_mode: query, fragment or form_post.
	//
	// This comment used to say "query only" and "form_post is REFUSED" -- true
	// before the hybrid flow landed (commit 4bd9436) and false ever since, which
	// is the stale-comment-contradicting-the-code hazard this codebase treats as
	// worse than no comment. The current rules:
	//
	//   - The DEFAULT differs by response type, as OIDC specifies: `query` for a
	//     bare code, `fragment` for anything carrying a token to the browser.
	//   - `query` is REFUSED for a hybrid response: an id_token in a query string
	//     is written to the far end's access log, to every proxy in between, and
	//     to browser history. OIDC forbids it and so do we.
	//   - `fragment` and `form_post` are accepted. form_post exists because the
	//     hybrid flow puts a signed, non-single-use assertion in the front
	//     channel, and form_post is what keeps it out of URLs -- see
	//     responsemode.go for the nonce-guarded auto-submitting form.
	//   - Anything else is refused rather than accepted-and-ignored, because a
	//     client that asked for form_post and silently got query loses exactly
	//     the protection it asked for.
	hybrid := NormaliseResponseType(req.ResponseType) == "code id_token"
	switch req.ResponseMode {
	case "":
		// The default differs by response type, as OIDC specifies: `query` for
		// code, `fragment` for anything carrying a token to the browser.
	case "query":
		if hybrid {
			// An id_token in a query string is written to the server's access log
			// at the far end, to any proxy in between, and to browser history. The
			// specification forbids it and so does this.
			return redirectErr("invalid_request",
				"response_mode \"query\" cannot carry an id_token; use \"fragment\" "+
					"or \"form_post\"")
		}
	case "fragment", "form_post":
	default:
		return redirectErr("invalid_request",
			fmt.Sprintf("response_mode %q is not supported; use query, fragment or form_post",
				req.ResponseMode))
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

// parseMaxAge reads the max_age parameter, ignoring anything malformed.
//
// A negative or unparsable value is treated as absent rather than as an error:
// OIDC does not define a failure for it, and refusing the whole authorization
// request over a malformed optional hint is worse for the user than ignoring it.
func parseMaxAge(s string) *int {
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

// validateResources checks RFC 8707 §2 resource indicators.
//
// Each must be an absolute URI with no fragment. The spec says so, and the
// reason matters here: the value ends up as an `aud` claim that a resource
// server compares against its own identifier, and a relative or fragment-bearing
// value cannot be compared reliably by anyone.
func validateResources(resources []string) error {
	if len(resources) == 0 {
		return nil
	}
	// Bounded: an audience list is compared by resource servers on every request,
	// and an unbounded one is a cheap way to inflate every token we issue.
	if len(resources) > 8 {
		return fmt.Errorf("at most 8 resource indicators may be requested")
	}
	for _, r := range resources {
		u, err := url.Parse(r)
		if err != nil || !u.IsAbs() {
			return fmt.Errorf("resource %q must be an absolute URI", r)
		}
		if u.Fragment != "" || strings.Contains(r, "#") {
			return fmt.Errorf("resource %q must not contain a fragment", r)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			// Not a spec requirement, but an audience nobody can reach is one
			// nobody can verify, and it is nearly always a typo.
			return fmt.Errorf("resource %q must be an http or https URI", r)
		}
	}
	return nil
}

// NormaliseResponseType sorts the space-separated values.
//
// response_type is a SET, not a string: "id_token code" and "code id_token" are
// the same request, and a server that compares the raw string accepts one and
// refuses the other for no reason a client can discover.
func NormaliseResponseType(rt string) string {
	parts := strings.Fields(rt)
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	// Sorted order puts "code" before "id_token", which is also the canonical
	// spelling, so the comparison reads naturally at the call site.
	return strings.Join(parts, " ")
}

// validThumbprint reports whether s could be a SHA-256 JWK Thumbprint.
//
// RFC 7638 thumbprints with SHA-256 are 32 bytes, which is 43 base64url
// characters without padding -- the same shape as a PKCE S256 challenge, and
// checked the same way.
func validThumbprint(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}
