package oauth

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"signari.dev/engine/internal/clients"
)

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func grant(now time.Time) *GrantRecord {
	return &GrantRecord{
		ClientID:            "app",
		RedirectURI:         "https://app.example.com/cb",
		CodeChallenge:       Challenge(verifier),
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid"},
		ExpiresAt:           now.Add(time.Minute),
	}
}

func tokenReq() TokenRequest {
	return TokenRequest{
		GrantType:    "authorization_code",
		Code:         "abc",
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
		ClientID:     "app",
		AuthMethod:   "none",
	}
}

func TestValidRedemption(t *testing.T) {
	now := time.Now()
	reused, err := ValidateCodeRedemption(tokenReq(), testClient(), grant(now), now)
	if err != nil {
		t.Fatalf("valid redemption rejected: %v", err)
	}
	if reused {
		t.Error("fresh code reported as reused")
	}
}

// A code issued to one client must not be redeemable by another, even when that
// other client authenticates correctly.
func TestCodeIsBoundToItsClient(t *testing.T) {
	now := time.Now()
	req := tokenReq()
	req.ClientID = "other"
	other := testClient()
	other.ClientID = "other"

	_, err := ValidateCodeRedemption(req, other, grant(now), now)
	if err == nil {
		t.Fatal("a code issued to `app` was redeemed by `other`")
	}
	if err.Code != "invalid_grant" {
		t.Errorf("code = %q, want invalid_grant", err.Code)
	}
}

// Reuse is theft until proven otherwise: reject AND tell the caller to revoke.
func TestCodeReuseIsReportedForRevocation(t *testing.T) {
	now := time.Now()
	g := grant(now)
	consumed := now.Add(-time.Second)
	g.ConsumedAt = &consumed

	reused, err := ValidateCodeRedemption(tokenReq(), testClient(), g, now)
	if err == nil {
		t.Fatal("a consumed code was accepted")
	}
	if !reused {
		t.Fatal("reuse was not signalled; the token family would survive a stolen code")
	}
}

// redirect_uri must equal the one used at authorization, not merely be some
// registered URI for the client. The weaker check enables code injection.
func TestRedirectURIMustMatchTheAuthorizationRequest(t *testing.T) {
	now := time.Now()
	c := testClient()
	c.RedirectURIs = append(c.RedirectURIs, "https://app.example.com/other")

	req := tokenReq()
	req.RedirectURI = "https://app.example.com/other" // registered, but not the one used

	_, err := ValidateCodeRedemption(req, c, grant(now), now)
	if err == nil {
		t.Fatal("redemption succeeded through a different registered redirect_uri")
	}
	if err.Code != "invalid_grant" {
		t.Errorf("code = %q, want invalid_grant", err.Code)
	}
}

func TestRedemptionFailures(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		req    func(*TokenRequest)
		grant  func(*GrantRecord)
		client func(*clients.Client)
		want   string
	}{
		{"expired code", nil, func(g *GrantRecord) { g.ExpiresAt = now.Add(-time.Second) }, nil, "invalid_grant"},
		{"missing code", func(r *TokenRequest) { r.Code = "" }, nil, nil, "invalid_request"},
		// A missing redirect_uri is NOT a failure -- OAuth 2.1 section 10.2
		// removed the parameter from this request. See
		// TestAnOAuth21ClientNeedNotSendRedirectURI, and
		// TestACodeIsNeverRedeemableWithNeitherDefence for when it is still
		// mandatory.
		{"missing verifier", func(r *TokenRequest) { r.CodeVerifier = "" }, nil, nil, "invalid_request"},
		{"wrong verifier", func(r *TokenRequest) { r.CodeVerifier = "0000000000000000000000000000000000000000000" }, nil, nil, "invalid_grant"},
		{"disabled client", nil, nil, func(c *clients.Client) { c.Enabled = false }, "invalid_client"},
		{"grant not allowed", nil, nil, func(c *clients.Client) { c.GrantTypes = []string{"refresh_token"} }, "unauthorized_client"},
		{
			// The authorization endpoint should never have issued this. If it did,
			// the token endpoint must not paper over it.
			// The client sends no verifier either -- with one, this is instead
			// the downgrade case of section 3.2.4 and the answer is
			// invalid_request. See TestAVerifierAgainstACodeWithNoChallengeIsRefused.
			name:  "PKCE-required client with a challenge-less grant",
			req:   func(r *TokenRequest) { r.CodeVerifier = "" },
			grant: func(g *GrantRecord) { g.CodeChallenge = "" },
			want:  "invalid_grant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, g, c := tokenReq(), grant(now), testClient()
			if tc.req != nil {
				tc.req(&req)
			}
			if tc.grant != nil {
				tc.grant(g)
			}
			if tc.client != nil {
				tc.client(c)
			}
			_, err := ValidateCodeRedemption(req, c, g, now)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Code != tc.want {
				t.Errorf("code = %q, want %q", err.Code, tc.want)
			}
		})
	}
}

func TestUnknownCodeIsInvalidGrant(t *testing.T) {
	_, err := ValidateCodeRedemption(tokenReq(), testClient(), nil, time.Now())
	if err == nil || err.Code != "invalid_grant" {
		t.Fatalf("err = %v, want invalid_grant", err)
	}
}

func TestClientAuthRules(t *testing.T) {
	pub := testClient() // public
	conf := testClient()
	conf.Type = "confidential"

	if err := RequireClientAuth(conf, TokenRequest{AuthMethod: "none"}); err == nil {
		t.Error("a confidential client was allowed to skip authentication")
	}
	// A public client presenting a secret means a secret shipped inside a
	// distributable binary; accepting it would legitimise that.
	if err := RequireClientAuth(pub, TokenRequest{AuthMethod: "client_secret_post", ClientSecret: "s"}); err == nil {
		t.Error("a public client was allowed to present a secret")
	}
	if err := RequireClientAuth(pub, TokenRequest{AuthMethod: "none"}); err != nil {
		t.Errorf("a public client using PKCE alone was rejected: %v", err)
	}
	if err := RequireClientAuth(conf, TokenRequest{AuthMethod: "client_secret_basic", ClientSecret: "s"}); err != nil {
		t.Errorf("a properly authenticated confidential client was rejected: %v", err)
	}
}

func TestGrantTypeGate(t *testing.T) {
	for _, gt := range []string{"password", "implicit", "urn:ietf:params:oauth:grant-type:saml2-bearer", ""} {
		if err := ValidateGrantType(gt); err == nil {
			t.Errorf("grant_type %q was accepted", gt)
		}
	}
	for _, gt := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		if err := ValidateGrantType(gt); err != nil {
			t.Errorf("grant_type %q was rejected: %v", gt, err)
		}
	}
}

func TestParseClientCredentials(t *testing.T) {
	basic := func(id, secret string) http.Header {
		h := http.Header{}
		raw := url.QueryEscape(id) + ":" + url.QueryEscape(secret)
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(raw)))
		return h
	}

	t.Run("basic is form-urldecoded", func(t *testing.T) {
		// A secret containing '+' or a space is silently wrong without decoding.
		r, err := ParseTokenRequest(basic("app", "s3cr3t with+plus"), url.Values{})
		if err != nil {
			t.Fatal(err)
		}
		if r.ClientID != "app" || r.ClientSecret != "s3cr3t with+plus" {
			t.Errorf("got id=%q secret=%q", r.ClientID, r.ClientSecret)
		}
		if r.AuthMethod != "client_secret_basic" {
			t.Errorf("auth method = %q", r.AuthMethod)
		}
	})

	t.Run("credentials in two places is an error, not a precedence question", func(t *testing.T) {
		form := url.Values{"client_id": {"app"}, "client_secret": {"other"}}
		if _, err := ParseTokenRequest(basic("app", "s"), form); err == nil {
			t.Fatal("accepted credentials in both the header and the body")
		}
	})

	t.Run("mismatched client_id between header and body", func(t *testing.T) {
		form := url.Values{"client_id": {"different"}}
		if _, err := ParseTokenRequest(basic("app", "s"), form); err == nil {
			t.Fatal("accepted a body client_id that contradicts the header")
		}
	})

	t.Run("public client sends no secret", func(t *testing.T) {
		form := url.Values{"client_id": {"app"}, "code_verifier": {verifier}}
		r, err := ParseTokenRequest(http.Header{}, form)
		if err != nil {
			t.Fatal(err)
		}
		if r.AuthMethod != "none" || r.ClientSecret != "" {
			t.Errorf("auth method = %q secret = %q", r.AuthMethod, r.ClientSecret)
		}
	})
}

// OAuth 2.1 section 4.1.3: the server must "verify that the code_verifier
// parameter is present if and only if a code_challenge parameter was present in
// the authorization request".
//
// Both halves of a biconditional are failures. We enforced one and ignored the
// other for as long as this function has existed.

// An OAuth 2.1 client does not send redirect_uri. Section 10.2 removed it
// because PKCE now does the job it was there for, and warns that a server
// expecting it is incompatible with such a client. We were that server.
func TestAnOAuth21ClientNeedNotSendRedirectURI(t *testing.T) {
	now := time.Now()
	req := tokenReq()
	req.RedirectURI = "" // exactly what a conformant OAuth 2.1 client sends

	if _, err := ValidateCodeRedemption(req, testClient(), grant(now), now); err != nil {
		t.Fatalf("a conformant OAuth 2.1 redemption was rejected: %v", err)
	}
}

// Removed from the request is not the same as unchecked. Section 10.2: a server
// supporting both revisions "MUST allow clients to send the redirect_uri
// parameter in the token request, and MUST enforce the parameter as described
// in [RFC6749]".
func TestARedirectURIThatIsSentIsStillEnforced(t *testing.T) {
	now := time.Now()
	req := tokenReq()
	req.RedirectURI = "https://app.example.com/other"

	_, err := ValidateCodeRedemption(req, testClient(), grant(now), now)
	if err == nil {
		t.Fatal("a code was redeemed through a callback it was not issued for")
	}
	if err.Code != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", err.Code)
	}
}

// The invariant the two rules above combine into: a code is never redeemable
// with neither injection defence present. Dropping the redirect_uri requirement
// is only safe because PKCE is mandatory; for a client that has opted out of
// PKCE, the older defence becomes mandatory again.
func TestACodeIsNeverRedeemableWithNeitherDefence(t *testing.T) {
	now := time.Now()

	g := grant(now)
	g.CodeChallenge, g.CodeChallengeMethod = "", "" // legacy code, no PKCE

	c := testClient()
	c.RequirePKCE = false // the deliberate per-client OAuth 2.0 fallback

	req := tokenReq()
	req.CodeVerifier = ""
	req.RedirectURI = "" // ...and now neither defence is in play

	_, err := ValidateCodeRedemption(req, c, g, now)
	if err == nil {
		t.Fatal("a code with no PKCE challenge was redeemed without a " +
			"redirect_uri: nothing at all bound that code to the client that " +
			"started the flow")
	}
	if err.Code != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", err.Code)
	}

	// The same client sending redirect_uri is fine -- that is RFC 6749.
	req.RedirectURI = "https://app.example.com/cb"
	if _, err := ValidateCodeRedemption(req, c, g, now); err != nil {
		t.Fatalf("a legacy OAuth 2.0 redemption was rejected: %v", err)
	}
}

// The half we ignored: a verifier arriving against a code that has no
// challenge. Section 3.2.4 names this case in the definition of
// invalid_request -- a request that "contains a code_verifier although no
// code_challenge was sent in the authorization request".
//
// The client believes it is using PKCE. If its challenge was stripped before
// the authorization endpoint, accepting the verifier tells it everything
// worked while the binding it relied on is gone.
func TestAVerifierAgainstACodeWithNoChallengeIsRefused(t *testing.T) {
	now := time.Now()

	g := grant(now)
	g.CodeChallenge, g.CodeChallengeMethod = "", "" // the challenge never arrived

	c := testClient()
	c.RequirePKCE = false // so only the biconditional can reject this

	req := tokenReq() // still carrying the verifier the client computed

	_, err := ValidateCodeRedemption(req, c, g, now)
	if err == nil {
		t.Fatal("a code_verifier was accepted against a code carrying no " +
			"challenge; a downgraded request was served as a successful one")
	}
	if err.Code != "invalid_request" {
		t.Errorf("error = %q, want invalid_request (section 3.2.4 names this "+
			"exact case)", err.Code)
	}
}

// Section 4.1.3, unconditionally: "If there was no code_challenge in the
// authorization request associated with the authorization code in the token
// request, the authorization server MUST reject the token request."
//
// RequirePKCE defaults to true in the schema, so this is the default path.
func TestPKCEIsRequiredByDefault(t *testing.T) {
	now := time.Now()

	g := grant(now)
	g.CodeChallenge, g.CodeChallengeMethod = "", ""

	req := tokenReq()
	req.CodeVerifier = ""

	// testClient has RequirePKCE true, matching the column default.
	if _, err := ValidateCodeRedemption(req, testClient(), g, now); err == nil {
		t.Fatal("a code issued without PKCE was redeemed by a client whose " +
			"policy requires it")
	}
}
