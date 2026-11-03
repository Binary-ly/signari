package oauth

import (
	"errors"
	"strings"
	"testing"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/tokens"
)

const goodChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func testClient() *clients.Client {
	return &clients.Client{
		ClientID:      "app",
		Enabled:       true,
		Type:          "public",
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
		RequirePKCE:   true,
		RedirectURIs:  []string{"https://app.example.com/cb"},
	}
}

func goodRequest() AuthzRequest {
	return AuthzRequest{
		ClientID:            "app",
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		Scope:               "openid profile",
		State:               "xyz",
		CodeChallenge:       goodChallenge,
		CodeChallengeMethod: "S256",
	}
}

func TestValidRequestPasses(t *testing.T) {
	if err := ValidateAuthz(goodRequest(), testClient(), nil); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

// Anything that fails before the redirect_uri is verified MUST NOT redirect.
// Redirecting to an unverified URI is an open redirector and a phishing primitive.
func TestErrorsBeforeRedirectVerificationAreDirect(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AuthzRequest)
		client  *clients.Client
		lookErr error
		want    string
	}{
		{
			name:   "missing client_id",
			mutate: func(r *AuthzRequest) { r.ClientID = "" },
			client: testClient(),
			want:   "invalid_request",
		},
		{
			name:    "unknown client",
			mutate:  func(r *AuthzRequest) {},
			client:  nil,
			lookErr: clients.ErrNotFound,
			want:    "invalid_client",
		},
		{
			name:   "disabled client",
			mutate: func(r *AuthzRequest) {},
			client: func() *clients.Client { c := testClient(); c.Enabled = false; return c }(),
			want:   "unauthorized_client",
		},
		{
			name:   "missing redirect_uri",
			mutate: func(r *AuthzRequest) { r.RedirectURI = "" },
			client: testClient(),
			want:   "invalid_request",
		},
		{
			name:   "unregistered redirect_uri",
			mutate: func(r *AuthzRequest) { r.RedirectURI = "https://evil.example.com/cb" },
			client: testClient(),
			want:   "invalid_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := goodRequest()
			tc.mutate(&req)
			err := ValidateAuthz(req, tc.client, tc.lookErr)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Code != tc.want {
				t.Errorf("code = %q, want %q", err.Code, tc.want)
			}
			if err.Disposition != DispositionDirect {
				t.Errorf("disposition = redirect; this error must NOT be redirected")
			}
		})
	}
}

// Redirect URIs are compared byte for byte. Every one of these near-misses has
// been a redirect-bypass somewhere.
func TestRedirectURIMatchingIsExact(t *testing.T) {
	near := []string{
		"https://app.example.com/cb/",          // trailing slash
		"https://app.example.com/cb?x=1",       // extra query
		"https://APP.example.com/cb",           // host case
		"https://app.example.com/cb#frag",      // fragment
		"https://app.example.com:443/cb",       // explicit default port
		"https://app.example.com/cb/../cb",     // traversal that normalises equal
		"https://app.example.com/CB",           // path case
		"http://app.example.com/cb",            // downgraded scheme
		"https://app.example.com.evil.test/cb", // suffix attack
		"https://app.example.com/cb%2f",        // encoded slash
		" https://app.example.com/cb",          // leading space
	}
	c := testClient()
	for _, uri := range near {
		t.Run(uri, func(t *testing.T) {
			if c.HasRedirectURI(uri) {
				t.Fatalf("%q matched the registered URI; matching must be exact", uri)
			}
			req := goodRequest()
			req.RedirectURI = uri
			err := ValidateAuthz(req, c, nil)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if err.Disposition != DispositionDirect {
				t.Fatal("an unregistered redirect_uri must never be redirected to")
			}
		})
	}
}

func TestPKCE(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthzRequest)
		want   string
	}{
		{
			name:   "missing challenge",
			mutate: func(r *AuthzRequest) { r.CodeChallenge = "" },
			want:   "invalid_request",
		},
		{
			// RFC 7636 defaults an absent method to "plain". Silently treating it
			// as S256 would verify a challenge the client never computed.
			name:   "absent method is not silently upgraded to S256",
			mutate: func(r *AuthzRequest) { r.CodeChallengeMethod = "" },
			want:   "invalid_request",
		},
		{
			name:   "plain is rejected",
			mutate: func(r *AuthzRequest) { r.CodeChallengeMethod = "plain" },
			want:   "invalid_request",
		},
		{
			name:   "challenge too short",
			mutate: func(r *AuthzRequest) { r.CodeChallenge = "tooshort" },
			want:   "invalid_request",
		},
		{
			name:   "challenge with illegal characters",
			mutate: func(r *AuthzRequest) { r.CodeChallenge = strings.Repeat("a", 42) + "+/=" },
			want:   "invalid_request",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := goodRequest()
			tc.mutate(&req)
			err := ValidateAuthz(req, testClient(), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Code != tc.want {
				t.Errorf("code = %q, want %q", err.Code, tc.want)
			}
			// The redirect target was verified before PKCE was checked, so these
			// errors are deliverable to the client.
			if err.Disposition != DispositionRedirect {
				t.Errorf("disposition = direct, want redirect")
			}
		})
	}
}

func TestResponseTypeAndScope(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthzRequest)
		want   string
	}{
		{"implicit rejected", func(r *AuthzRequest) { r.ResponseType = "token" }, "unsupported_response_type"},
		{"hybrid rejected", func(r *AuthzRequest) { r.ResponseType = "code id_token" }, "unsupported_response_type"},
		{"missing response_type", func(r *AuthzRequest) { r.ResponseType = "" }, "invalid_request"},
		{"missing scope", func(r *AuthzRequest) { r.Scope = "" }, "invalid_scope"},
		{"scope without openid", func(r *AuthzRequest) { r.Scope = "profile" }, "invalid_scope"},
		{"unregistered scope", func(r *AuthzRequest) { r.Scope = "openid admin" }, "invalid_scope"},
		// fragment and form_post are supported now; an invented mode is not.
		{"unknown response_mode", func(r *AuthzRequest) { r.ResponseMode = "web_message" }, "invalid_request"},
		// The access token must never cross the front channel, in any combination.
		{"code token", func(r *AuthzRequest) { r.ResponseType = "code token" }, "unsupported_response_type"},
		{"bare token", func(r *AuthzRequest) { r.ResponseType = "token" }, "unsupported_response_type"},
		{"id_token token", func(r *AuthzRequest) { r.ResponseType = "id_token token" }, "unsupported_response_type"},
		// Hybrid is off unless a client is explicitly permitted it.
		{"hybrid without permission", func(r *AuthzRequest) {
			r.ResponseType = "code id_token"
			r.Nonce = "n"
		}, "unsupported_response_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := goodRequest()
			tc.mutate(&req)
			err := ValidateAuthz(req, testClient(), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Code != tc.want {
				t.Errorf("code = %q, want %q", err.Code, tc.want)
			}
		})
	}
}

// How a response travels decides what a person's browser, and a log, gets to see.
func TestEachResponseModeSaysHowItTravels(t *testing.T) {
	for _, tc := range []struct {
		mode, responseType string
		encoding           string
		signed             bool
	}{
		{"", "code", "query", false},
		{"", "code id_token", "fragment", false},
		{"", "id_token code", "fragment", false},
		// Refused here, and refused where the client that asked is listening.
		{"", "code token", "fragment", false},
		{"", "code id_token token", "fragment", false},
		{"", "token", "fragment", false},
		{"", "id_token", "fragment", false},
		{"", "", "query", false},
		{"", "banana", "query", false},
		{"query", "code", "query", false},
		{"fragment", "code", "fragment", false},
		{"form_post", "code id_token", "form_post", false},
		{"query.jwt", "code", "query", true},
		{"fragment.jwt", "code", "fragment", true},
		{"form_post.jwt", "code", "form_post", true},
		// JARM §2.3.4: the default encoding for the requested response type.
		{"jwt", "code", "query", true},
		{"jwt", "code id_token", "fragment", true},
		// Its refusal has to get there, and the mode it named means nothing.
		{"carrier-pigeon", "code", "query", false},
		{"carrier-pigeon.jwt", "code", "query", false},
	} {
		req := AuthzRequest{ResponseMode: tc.mode, ResponseType: tc.responseType}
		encoding, signed := req.ResponseEncoding()
		if encoding != tc.encoding || signed != tc.signed {
			t.Errorf("mode %q, type %q: got %s signed=%v, want %s signed=%v",
				tc.mode, tc.responseType, encoding, signed, tc.encoding, tc.signed)
		}
	}
}

// A signature does not make a query string a safe place for an assertion.
func TestAnIDTokenCannotGoInASignedQuery(t *testing.T) {
	req := goodRequest()
	req.ResponseType, req.ResponseMode, req.Nonce = "code id_token", "query.jwt", "n-0S6_WzA2Mj"
	c := testClient()
	c.AllowHybrid = true
	c.ResponseTypes = []string{"code", "code id_token"}
	err := ValidateAuthz(req, c, nil)
	if err == nil || err.Code != "invalid_request" || !strings.Contains(err.Description, "query.jwt") {
		t.Fatalf("query.jwt with an id_token: %+v, want it refused by name", err)
	}
	req.ResponseMode = "jwt"
	if err := ValidateAuthz(req, c, nil); err != nil {
		t.Errorf("jwt with an id_token is a fragment and should pass: %+v", err)
	}
}

// An encrypted response is signed first, so a client that asked for one alone has asked
// for both, and a plain mode would give it neither.
func TestAskingForAnEncryptedResponseHoldsAClientToo(t *testing.T) {
	c := testClient()
	c.AuthorizationEncryption = tokens.Encryption{Alg: "ECDH-ES", Enc: "A256GCM"}
	if err := ValidateAuthz(goodRequest(), c, nil); err == nil || err.Code != "invalid_request" {
		t.Errorf("no mode at all for a client that encrypts: %+v", err)
	}
	req := goodRequest()
	req.ResponseMode = "jwt"
	if err := ValidateAuthz(req, c, nil); err != nil {
		t.Errorf("jwt for a client that encrypts: %+v", err)
	}
}

// With an algorithm set, an unsigned response is what a changed URL would get, so
// one is refused however it is asked for, by the mode or by leaving the mode out.
func TestAClientWithAResponseAlgorithmTakesOnlySignedResponses(t *testing.T) {
	c := testClient()
	c.AuthorizationResponseAlg = "ES256"
	for _, mode := range []string{"", "query", "fragment", "form_post"} {
		req := goodRequest()
		req.ResponseMode = mode
		err := ValidateAuthz(req, c, nil)
		if err == nil || err.Disposition != DispositionRedirect || err.Code != "invalid_request" {
			t.Errorf("mode %q for a client held to signing: %+v, want invalid_request back to it", mode, err)
		}
	}
	for _, mode := range []string{"jwt", "query.jwt", "fragment.jwt", "form_post.jwt"} {
		req := goodRequest()
		req.ResponseMode = mode
		if err := ValidateAuthz(req, c, nil); err != nil {
			t.Errorf("mode %q for a client held to signing: %+v", mode, err)
		}
	}
}

func TestLookupErrorIsInvalidClient(t *testing.T) {
	err := ValidateAuthz(goodRequest(), nil, errors.New("db down"))
	if err == nil || err.Disposition != DispositionDirect {
		t.Fatal("a failed client lookup must fail directly, never redirect")
	}
}

// Hybrid, for a client that IS permitted it.
//
// The rules that only bite once the response type is allowed: a nonce is
// mandatory, and the response must not go back in a query string. Both are what
// make a front-channel ID token safe to issue at all, so both are worth pinning
// separately from the "is it allowed" check.
func TestHybridRulesForAPermittedClient(t *testing.T) {
	permitted := func() *clients.Client {
		c := testClient()
		c.AllowHybrid = true
		c.ResponseTypes = append(c.ResponseTypes, "code id_token")
		return c
	}

	t.Run("nonce is required", func(t *testing.T) {
		req := goodRequest()
		req.ResponseType = "code id_token"
		req.Nonce = ""
		err := ValidateAuthz(req, permitted(), nil)
		if err == nil || err.Code != "invalid_request" {
			t.Fatalf("a hybrid request without a nonce was accepted: %v", err)
		}
		if !strings.Contains(err.Description, "nonce") {
			t.Errorf("the error does not mention the nonce: %q", err.Description)
		}
	})

	t.Run("query cannot carry an id_token", func(t *testing.T) {
		req := goodRequest()
		req.ResponseType = "code id_token"
		req.Nonce = "n"
		req.ResponseMode = "query"
		err := ValidateAuthz(req, permitted(), nil)
		if err == nil || err.Code != "invalid_request" {
			t.Fatalf("an id_token was allowed into a query string: %v", err)
		}
	})

	for _, mode := range []string{"", "fragment", "form_post"} {
		t.Run("accepted with response_mode "+mode, func(t *testing.T) {
			req := goodRequest()
			req.ResponseType = "code id_token"
			req.Nonce = "n"
			req.ResponseMode = mode
			if err := ValidateAuthz(req, permitted(), nil); err != nil {
				t.Fatalf("refused: %s — %s", err.Code, err.Description)
			}
		})
	}
}

// TestResponseTypeIsASet: "id_token code" and "code id_token" are the same
// request. A server comparing the raw string accepts one and refuses the other
// for no reason a client can discover from the error.
func TestResponseTypeIsASet(t *testing.T) {
	c := testClient()
	c.AllowHybrid = true
	c.ResponseTypes = append(c.ResponseTypes, "code id_token")

	req := goodRequest()
	req.ResponseType = "id_token code" // the other order
	req.Nonce = "n"
	if err := ValidateAuthz(req, c, nil); err != nil {
		t.Fatalf("the reversed spelling was refused: %s — %s", err.Code, err.Description)
	}
}

// ASVS 5.0 V10.4.4: "only the grants that client needs" — enforced at the
// AUTHORIZE endpoint, not merely at redemption.
//
// Both of these guards survived mutation against the whole test suite: setting
// either to `if false` broke nothing, anywhere. The restriction was implemented
// and unconstrained.
//
// It matters here rather than only at the token endpoint because by the time a
// code is issued the damage is partly done: the person has been shown a consent
// screen for a client that was never permitted this flow, and has approved it.
// Refusing at redemption would mean the authorization server asked a user to
// agree to something it was always going to refuse.
func TestAClientMayNotUseAFlowItIsNotRegisteredFor(t *testing.T) {
	t.Run("the authorization_code grant", func(t *testing.T) {
		c := testClient()
		c.GrantTypes = []string{"refresh_token"} // registered, but not for the code grant

		err := ValidateAuthz(goodRequest(), c, nil)
		if err == nil {
			t.Fatal("a client not registered for authorization_code was allowed to " +
				"start the code flow; a consent screen would be shown for a grant " +
				"this client may not use")
		}
		if err.Code != "unauthorized_client" {
			t.Errorf("code = %q, want unauthorized_client", err.Code)
		}
	})

	t.Run("the response_type", func(t *testing.T) {
		c := testClient()
		c.ResponseTypes = []string{"code id_token"} // not plain "code"

		err := ValidateAuthz(goodRequest(), c, nil)
		if err == nil {
			t.Fatal("a client used a response_type it is not registered for")
		}
		if err.Code != "unauthorized_client" {
			t.Errorf("code = %q, want unauthorized_client", err.Code)
		}
	})

	// The positive case, so the test cannot pass by refusing everything.
	t.Run("a properly registered client still works", func(t *testing.T) {
		if err := ValidateAuthz(goodRequest(), testClient(), nil); err != nil {
			t.Fatalf("a correctly registered client was refused: %v", err)
		}
	})
}
