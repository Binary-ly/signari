package duo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testClientID = "DIABCDEFGHIJKLMNOPQR"                     // 20
	testSecret   = "0123456789abcdef0123456789abcdef01234567" // 40
)

func testConfig(host string) *Config {
	return &Config{
		ClientID: testClientID, ClientSecret: testSecret,
		APIHost:     "api-1234abcd.duosecurity.com",
		RedirectURI: "https://signari.test/duo/callback",
		HTTP:        &http.Client{Timeout: 2 * time.Second},
	}
}

// mint builds an id_token the way Duo would.
func mint(t *testing.T, c *Config, claims map[string]any) string {
	t.Helper()
	base := map[string]any{
		"iss":                c.baseURL() + "/oauth/v1/token",
		"aud":                c.ClientID,
		"exp":                time.Now().Add(5 * time.Minute).Unix(),
		"iat":                time.Now().Unix(),
		"auth_time":          time.Now().Unix(),
		"preferred_username": "alice@corp.test",
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	tok, err := signHS512(base, c.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestUsernameMustMatch is the first test in this file on purpose.
//
// Duo returns a token saying who IT authenticated. An integration that checks
// the signature, issuer, audience and expiry -- and stops there -- accepts a
// successful Duo authentication of somebody else as proof for the account being
// signed into.
func TestUsernameMustMatch(t *testing.T) {
	c := testConfig("")
	tok := mint(t, c, map[string]any{"preferred_username": "attacker@corp.test"})

	if _, err := c.VerifyIDToken(tok, "alice@corp.test", time.Now()); err == nil {
		t.Fatal("a Duo authentication of a DIFFERENT user was accepted as proof " +
			"for this account")
	}

	// The honest case still works, and case differences are not a mismatch:
	// Duo normalises usernames and a directory may not.
	ok := mint(t, c, map[string]any{"preferred_username": "Alice@Corp.test"})
	if _, err := c.VerifyIDToken(ok, "alice@corp.test", time.Now()); err != nil {
		t.Fatalf("a matching username differing only in case was refused: %v", err)
	}
}

func TestVerifyIDTokenRefuses(t *testing.T) {
	c := testConfig("")
	other := &Config{ClientID: c.ClientID, ClientSecret: strings.Repeat("f", 40),
		APIHost: c.APIHost, RedirectURI: c.RedirectURI}

	cases := []struct {
		name  string
		token func() string
		want  string
	}{
		{
			name:  "signed with the wrong secret",
			token: func() string { return mint(t, other, nil) },
			want:  "signature does not verify",
		},
		{
			name: "alg none",
			token: func() string {
				parts := strings.Split(mint(t, c, nil), ".")
				return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."
			},
			want: "only HS512 is accepted",
		},
		{
			name: "issued by another Duo tenant",
			token: func() string {
				return mint(t, c, map[string]any{"iss": "https://api-9999.duosecurity.com/oauth/v1/token"})
			},
			want: "issued by",
		},
		{
			name:  "addressed to another integration",
			token: func() string { return mint(t, c, map[string]any{"aud": "DIZZZZZZZZZZZZZZZZZZ"}) },
			want:  "addressed to",
		},
		{
			name:  "expired",
			token: func() string { return mint(t, c, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}) },
			want:  "expired",
		},
		{
			name:  "no expiry at all",
			token: func() string { return mint(t, c, map[string]any{"exp": nil}) },
			want:  "no expiry",
		},
		{
			name:  "names nobody",
			token: func() string { return mint(t, c, map[string]any{"preferred_username": nil}) },
			want:  "names no user",
		},
		{
			name: "Duo said deny",
			token: func() string {
				return mint(t, c, map[string]any{
					"auth_result": map[string]any{"status": "deny", "status_msg": "Denied by policy"},
				})
			},
			want: "did not allow",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.VerifyIDToken(tc.token(), "alice@corp.test", time.Now())
			if err == nil {
				t.Fatal("accepted a token that should be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	base := testConfig("")
	if err := base.Validate(); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}

	bad := []struct {
		name string
		edit func(*Config)
	}{
		{"short client id", func(c *Config) { c.ClientID = "DIABC" }},
		{"short secret", func(c *Config) { c.ClientSecret = "abc" }},
		{"host with a scheme", func(c *Config) { c.APIHost = "https://api-1.duosecurity.com" }},
		{"host that is not Duo", func(c *Config) { c.APIHost = "api.attacker.test" }},
		{"no redirect uri", func(c *Config) { c.RedirectURI = "" }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := *base
			tc.edit(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestAuthorizeURLCarriesTheUsernameSigned: the username must not be editable
// between here and Duo.
func TestAuthorizeURLCarriesTheUsernameSigned(t *testing.T) {
	c := testConfig("")
	state, _ := NewState()
	raw, err := c.AuthorizeURL(state, "alice@corp.test")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	req := u.Query().Get("request")
	if req == "" {
		t.Fatal("no signed request parameter")
	}
	if strings.Contains(u.RawQuery, "duo_uname") {
		t.Fatal("the username is in the query string, where a browser can edit it")
	}
	claims, err := verifyHS512(req, c.ClientSecret)
	if err != nil {
		t.Fatalf("the request JWT does not verify: %v", err)
	}
	if claims["duo_uname"] != "alice@corp.test" {
		t.Fatalf("duo_uname = %v", claims["duo_uname"])
	}
	if claims["state"] != state {
		t.Fatal("the state is not inside the signed request")
	}

	// A short state is refused: it is what ties the answer to this browser.
	if _, err := c.AuthorizeURL("short", "alice@corp.test"); err == nil {
		t.Fatal("a state below Duo's floor was accepted")
	}
	if _, err := c.AuthorizeURL(state, ""); err == nil {
		t.Fatal("an empty username was accepted; Duo would choose who to challenge")
	}
}

func TestHealthCheck(t *testing.T) {
	var gotAssertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAssertion = r.PostForm.Get("client_assertion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stat":"OK","response":{"time":1}}`))
	}))
	defer srv.Close()

	c := testConfig("")
	c.HTTP = srv.Client()
	c.APIHost = strings.TrimPrefix(srv.URL, "http://")
	// The test server is plaintext; point baseURL at it directly.
	c.testBase = srv.URL

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("a healthy Duo was reported unhealthy: %v", err)
	}
	if gotAssertion == "" {
		t.Fatal("no client assertion was sent")
	}
	if _, err := verifyHS512(gotAssertion, c.ClientSecret); err != nil {
		t.Fatalf("the client assertion does not verify: %v", err)
	}
}

func TestHealthCheckReportsTheReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"stat":"FAIL","code":40103,"message":"invalid_client","message_detail":"Failed to verify signature."}`))
	}))
	defer srv.Close()

	c := testConfig("")
	c.HTTP = srv.Client()
	c.testBase = srv.URL

	err := c.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("a failing health check was reported as healthy")
	}
	// A wrong secret key and an expired integration need different actions.
	if !strings.Contains(err.Error(), "Failed to verify signature") {
		t.Fatalf("the detail an operator needs was dropped: %v", err)
	}
}

func TestExchange(t *testing.T) {
	var c *Config
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("client_assertion_type") !=
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			t.Errorf("client_assertion_type = %q", r.PostForm.Get("client_assertion_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": mint(t, c, nil)})
	}))
	defer srv.Close()

	c = testConfig("")
	c.HTTP = srv.Client()
	c.testBase = srv.URL

	res, err := c.Exchange(context.Background(), "code-123", "alice@corp.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Username != "alice@corp.test" {
		t.Fatalf("username = %q", res.Username)
	}

	// And the same exchange for a different account is refused.
	if _, err := c.Exchange(context.Background(), "code-123", "bob@corp.test"); err == nil {
		t.Fatal("a Duo result for alice proved a second factor for bob")
	}
}
