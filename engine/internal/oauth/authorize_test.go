package oauth

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/sulimanbenhalim/signari/engine/internal/clients"
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
		PKCEMethods:   []string{"S256"},
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
		{"bad response_mode", func(r *AuthzRequest) { r.ResponseMode = "fragment" }, "invalid_request"},
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

// The disposition is load-bearing, so the builder must enforce it rather than
// relying on every caller to remember.
func TestErrorRedirectRefusesDirectErrors(t *testing.T) {
	e := direct("invalid_client", "unknown client")
	if _, err := ErrorRedirect("https://evil.example.com/cb", "https://id.test", "s", e); err == nil {
		t.Fatal("ErrorRedirect built a URL for a direct-only error")
	}
}

func TestErrorRedirectShape(t *testing.T) {
	e := redirectErr("invalid_scope", "the openid scope is required")
	got, err := ErrorRedirect("https://app.example.com/cb?keep=1", "https://id.test", "st4te", e)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	q := u.Query()

	if q.Get("error") != "invalid_scope" {
		t.Errorf("error = %q", q.Get("error"))
	}
	if q.Get("state") != "st4te" {
		t.Errorf("state must be echoed exactly, got %q", q.Get("state"))
	}
	// RFC 9207: the issuer identifies which provider answered, closing the
	// mix-up attack.
	if q.Get("iss") != "https://id.test" {
		t.Errorf("iss = %q, want the issuer", q.Get("iss"))
	}
	if q.Get("keep") != "1" {
		t.Error("pre-existing query parameters on the registered URI were dropped")
	}
}

func TestLookupErrorIsInvalidClient(t *testing.T) {
	err := ValidateAuthz(goodRequest(), nil, errors.New("db down"))
	if err == nil || err.Disposition != DispositionDirect {
		t.Fatal("a failed client lookup must fail directly, never redirect")
	}
}
