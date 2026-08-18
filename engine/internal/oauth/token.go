package oauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/abca"
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

	creds, cerr := ParseClientCredentials(header, form)
	if cerr != nil {
		return r, cerr
	}
	r.ClientID = creds.ClientID
	r.ClientSecret = creds.ClientSecret
	r.ClientAssertion = creds.ClientAssertion
	r.ClientAssertionType = creds.ClientAssertionType
	r.AuthMethod = creds.AuthMethod
	return r, nil
}

// ClientCredentials is how a client identified itself on a direct request.
type ClientCredentials struct {
	ClientID            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
	// AuthMethod is one of client_secret_basic, client_secret_post,
	// private_key_jwt, or none.
	AuthMethod string
}

// ParseClientCredentials resolves how a client authenticated on a direct
// request, from the Authorization header and the form body.
//
// ONE resolver, for every endpoint a client calls directly. That is not tidiness
// -- it is a requirement each specification states about its own endpoint:
//
//	RFC 9126 §2 (PAR): "The rules for client authentication as defined in
//	[RFC6749] for token endpoint requests, including the applicable
//	authentication methods, apply for the PAR endpoint as well."
//	RFC 8628 §3.1 (device authorization): a confidential client authenticates
//	as described in RFC 6749 §3.2.1, which is the token endpoint's rule.
//
// This logic lived inside ParseTokenRequest, so only the token endpoint had it.
// PAR and the device authorization endpoint each read `client_secret` from the
// form and nothing else, which meant:
//
//   - A client registered for client_secret_basic -- the one method RFC 6749
//     §2.3.1 says a server MUST support, and the most widely deployed -- could
//     not use either endpoint at all. We advertise it in
//     token_endpoint_auth_methods_supported, which RFC 9126 §2 says also governs
//     PAR, so we advertised a method and then refused it.
//   - Credentials in both the header and the body went undetected.
//   - A body client_id naming a different client than the header went unchecked.
func ParseClientCredentials(header http.Header, form url.Values) (ClientCredentials, *TokenError) {
	var c ClientCredentials

	basicID, basicSecret, hasBasic := parseBasic(header.Get("Authorization"))
	bodyID, bodySecret := form.Get("client_id"), form.Get("client_secret")
	c.ClientAssertion = form.Get("client_assertion")
	c.ClientAssertionType = form.Get("client_assertion_type")

	// A client assertion and a secret are two credentials for one request, and
	// accepting both leaves which one authenticated the caller up to whichever
	// check happens to run first. Refused rather than resolved by precedence.
	if c.ClientAssertion != "" && (bodySecret != "" || hasBasic) {
		return c, tokenErr("invalid_request",
			"present either a client assertion or a client secret, not both")
	}

	switch {
	case hasBasic && bodySecret != "":
		return c, tokenErr("invalid_request",
			"client credentials presented both in the Authorization header and the body")
	case hasBasic:
		if bodyID != "" && bodyID != basicID {
			return c, tokenErr("invalid_request",
				"client_id in the body does not match the Authorization header")
		}
		c.ClientID, c.ClientSecret, c.AuthMethod = basicID, basicSecret, "client_secret_basic"
	case bodySecret != "":
		c.ClientID, c.ClientSecret, c.AuthMethod = bodyID, bodySecret, "client_secret_post"
	case c.ClientAssertion != "":
		c.ClientID, c.AuthMethod = bodyID, "private_key_jwt"
	default:
		// A public client authenticates with PKCE, not a secret.
		c.ClientID, c.AuthMethod = bodyID, "none"
	}
	return c, nil
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
	// DPoPJKT is the thumbprint the authorization request bound this code to,
	// empty when `dpop_jkt` was not used. See ValidateCodeRedemption.
	DPoPJKT             string
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
func ValidateCodeRedemption(req TokenRequest, c *clients.Client, g *GrantRecord,
	presentedJKT string, now time.Time) (alreadyConsumed bool, e *TokenError) {
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

	// 2. Code injection defence, of which there are two and at least one must be
	// present.
	//
	// OAuth 2.1 REMOVED redirect_uri from the token request. Section 10.2: "In
	// OAuth 2.1, authorization code injection is prevented by the code_challenge
	// and code_verifier parameters, making the inclusion of the redirect_uri
	// parameter serve no purpose in the token request. As such, it has been
	// removed." It then warns, in a sentence that described this function until
	// today: "A client following only the OAuth 2.1 recommendations will not
	// send the redirect_uri in the token request, and therefore will not be
	// compatible with an authorization server that expects the parameter."
	//
	// We demanded it, so a correctly written OAuth 2.1 client could not redeem a
	// code here at all. Now: enforced when sent -- section 10.2 makes that a MUST
	// for any server supporting both revisions -- and required only when PKCE is
	// absent, so no code is ever redeemable with neither defence in place.
	if req.RedirectURI != "" {
		// Exactly the URI used at authorization. Not "any registered URI" -- that
		// weaker check lets a code obtained via one callback be redeemed through
		// another, which is the classic code-injection setup.
		if req.RedirectURI != g.RedirectURI {
			return false, tokenErr("invalid_grant",
				"redirect_uri does not match the one used in the authorization request")
		}
	} else if g.CodeChallenge == "" {
		return false, tokenErr("invalid_request",
			"redirect_uri is required for an authorization code issued without PKCE")
	}

	// RFC 9449 §10, and it is a MUST:
	//
	//	"When a token request is received, the authorization server computes the
	//	JWK Thumbprint of the proof-of-possession public key in the DPoP proof and
	//	verifies that it matches the dpop_jkt parameter value in the authorization
	//	request. If they do not match, it MUST reject the request."
	//
	// This is what makes the binding end to end. PKCE binds the code to a secret
	// the client generated; dpop_jkt binds it to the KEY the resulting token
	// will carry, so a code intercepted in the front channel cannot be redeemed
	// by an attacker's own DPoP key even if they can produce a valid proof for
	// it.
	//
	// Checked BEFORE the PKCE block, not after.
	//
	// That block returns early when a challenge is present, so a dpop_jkt check
	// placed after it never ran for any code that used PKCE -- which is every
	// code by default. The test caught it immediately; reading the function did
	// not, because the early return is four lines below where the eye stops.
	//
	// The two are independent countermeasures and §10 notes they are
	// complementary, so ordering them this way is also the honest arrangement:
	// neither is a special case of the other.
	if g.DPoPJKT != "" {
		if presentedJKT == "" {
			return false, tokenErr("invalid_dpop_proof",
				"this authorization code is bound to a DPoP key (dpop_jkt) and the "+
					"token request carried no DPoP proof")
		}
		if presentedJKT != g.DPoPJKT {
			return false, tokenErr("invalid_dpop_proof",
				"the DPoP proof is for a different key than the authorization "+
					"request bound this code to")
		}
	}

	// 3. PKCE. Section 4.1.3 requires the server to "verify that the
	// code_verifier parameter is present if and only if a code_challenge
	// parameter was present in the authorization request" -- a biconditional,
	// so both halves are failures.
	if g.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return false, tokenErr("invalid_request", "code_verifier is required")
		}
		if err := VerifyPKCE(g.CodeChallengeMethod, g.CodeChallenge, req.CodeVerifier); err != nil {
			return false, tokenErr("invalid_grant", "code_verifier is invalid")
		}
		return false, nil
	}

	// The other half of the biconditional. Section 3.2.4 names this case in the
	// definition of invalid_request: a request that "contains a code_verifier
	// although no code_challenge was sent in the authorization request".
	//
	// Ignoring it -- which we did -- hides a downgrade: a client that believes it
	// is using PKCE, whose challenge was stripped somewhere between the browser
	// and the authorization endpoint, gets a token and no indication that its
	// binding was silently discarded.
	if req.CodeVerifier != "" {
		return false, tokenErr("invalid_request",
			"code_verifier was sent but the authorization request carried no "+
				"code_challenge; the request may have been downgraded")
	}
	if c.RequirePKCE {
		// Section 4.1.3, unconditionally: "If there was no code_challenge in the
		// authorization request associated with the authorization code in the
		// token request, the authorization server MUST reject the token request."
		//
		// RequirePKCE defaults to true in the schema, so this is the default path
		// and we are OAuth 2.1 conformant out of the box. Clearing the flag is a
		// deliberate per-client fallback to RFC 6749 behaviour for a legacy
		// application -- and the branch above then makes redirect_uri mandatory
		// for it, which is the defence OAuth 2.0 relied on.
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
		// And a registered mutual-TLS client authenticates with the certificate
		// on the connection (RFC 8705 §2), which is not in the request body at
		// all. This gate caught private_key_jwt the same way once; the lesson is
		// that "authentication" here means "some method applies", not "a secret
		// was posted".
		//
		// Eligibility only. Whether the certificate actually matches is decided
		// later, by code that can see the TLS state -- and a client registered
		// for mTLS that presents nothing is refused there, not waved through.
		if c.TLSSubjectDN != "" || c.TLSSANDNS != "" || c.TLSSANURI != "" ||
			len(c.TLSThumbprint) > 0 {
			return nil
		}
		// And a client registered for attestation-based authentication
		// authenticates with two HTTP headers, which are not in the request body
		// either. This gate has now caught three methods the same way --
		// private_key_jwt, mutual TLS, and this -- so the rule is worth stating
		// plainly rather than rediscovering a fourth time: **anything that adds a
		// client authentication method must add it here too**, because this
		// decides whether the method is ever reached.
		//
		// Presence of the registration, not validity of the headers: whether the
		// attestation verifies is decided later by code that can read the
		// organisation's trusted attesters, and a client registered for this that
		// sends nothing is refused there rather than waved through.
		if c.TokenEndpointAuthMethod == abca.MethodPoP {
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
		GrantTypeTokenExchange, GrantTypeDeviceCode, GrantTypePreAuthorizedCode:
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
