package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// RFC 9449 §6.2, on the introspection response specifically:
//
//	"For a DPoP-bound access token, the hash of the public key to which the
//	token is bound is conveyed to the protected resource as metainformation in
//	a token introspection response. The hash is conveyed using the same cnf
//	content with jkt member structure ... as a top-level member of the
//	introspection response JSON."
//
//	"If the token_type member is included in the introspection response, it
//	MUST contain the value DPoP."
//
// We minted `cnf.jkt` into the token and then told introspection callers
// `token_type: "Bearer"`, hardcoded, with no `cnf` field on the response struct
// at all. A resource server that validates by introspection -- the caller RFC
// 7662 exists for, per §2.1 -- was therefore told affirmatively that a
// sender-constrained token was an ordinary bearer token, and given nothing to
// check a proof against.
//
// §6 puts the consequence in the RS's own terms: "Resource servers MUST be able
// to reliably identify whether an access token is DPoP-bound". Ours could not,
// and the wrong answer is worse than no answer: an RS that believes `Bearer`
// will not ask for a proof, so a stolen token is accepted from whoever presents
// it. That is exactly the theft DPoP exists to make useless.
//
// The same rule was found and fixed at the token endpoint in an earlier pass --
// `bearerOrDPoP` exists for it, and three call sites use it. Introspection is
// the fourth site, in a different file, and §6.2 states the requirement
// separately for it.
func TestIntrospectionTellsAResourceServerTheTokenIsDPoPBound(t *testing.T) {
	f := newTokenFixture(t)
	key := newProofKey(t)

	const verifier = "verifier-introspect-dpop-aaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}, key.proof(t, "jti-introspect-dpop-1"))
	if status != http.StatusOK {
		t.Fatalf("redemption under DPoP gave %d: %v", status, body)
	}
	if got := body["token_type"]; got != "DPoP" {
		t.Fatalf("the token endpoint did not treat this as sender-constrained "+
			"(token_type=%v), so the test proves nothing", got)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", body)
	}

	secret := revocableClient(t, f)
	form := url.Values{"token": {access}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.clientID, secret)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("introspection body: %v", err)
	}
	if got["active"] != true {
		t.Fatalf("the token was reported inactive, so nothing below is meaningful: %v", got)
	}

	if got["token_type"] != "DPoP" {
		t.Errorf("token_type is %v, want \"DPoP\". RFC 9449 §6.2: \"If the "+
			"token_type member is included in the introspection response, it MUST "+
			"contain the value DPoP.\" A resource server told \"Bearer\" will not "+
			"ask for a proof, and will honour this token for whoever stole it",
			got["token_type"])
	}

	cnf, _ := got["cnf"].(map[string]any)
	if cnf == nil {
		t.Fatalf("no cnf in the introspection response. RFC 9449 §6.2 conveys the "+
			"binding to the resource server here, and §6 makes it a MUST that a "+
			"resource server can \"reliably identify whether an access token is "+
			"DPoP-bound\": %v", got)
	}
	if want := key.thumbprint(t); cnf["jkt"] != want {
		t.Errorf("cnf.jkt is %v, want the thumbprint of the key the token was "+
			"bound to (%s); a resource server compares this against the proof",
			cnf["jkt"], want)
	}
}

// introspect asks the endpoint about a token as the owner client.
func (f *tokenFixture) introspect(t *testing.T, token, clientID, secret string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("introspection body: %v", err)
	}
	return got
}

// The boundary of the DPoP rule, which is easy to overshoot in exactly the
// direction that breaks clients.
//
// RFC 8705 conveys a certificate binding through `cnf.x5t#S256` and never
// redefines the token type: such a token is still presented with the Bearer
// scheme over a mutually-authenticated connection. Reporting "DPoP" here would
// tell a resource server to demand a proof that does not exist, and the token
// would be refused everywhere it was used.
func TestACertificateBoundTokenIsStillReportedAsBearer(t *testing.T) {
	f := newTokenFixture(t)
	f.enableBoundTokens(t)
	cert := testCert(t, "introspect-mtls")

	const verifier = "verifier-introspect-mtls-aaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	status, body := f.postCert(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}, cert)
	if status != http.StatusOK {
		t.Fatalf("redemption over mTLS gave %d: %v", status, body)
	}
	access, _ := body["access_token"].(string)
	want := certConfirmationIn(t, access)
	if want == "" {
		t.Fatalf("the token carries no cnf.x5t#S256, so the test proves nothing")
	}

	secret := revocableClient(t, f)
	got := f.introspect(t, access, f.clientID, secret)
	if got["active"] != true {
		t.Fatalf("token reported inactive: %v", got)
	}
	if got["token_type"] != "Bearer" {
		t.Errorf("token_type is %v, want \"Bearer\". RFC 8705 signals a certificate "+
			"binding with cnf.x5t#S256, not the token type; calling it DPoP would "+
			"make a resource server demand a proof the client cannot produce",
			got["token_type"])
	}
	cnf, _ := got["cnf"].(map[string]any)
	if cnf == nil || cnf["x5t#S256"] != want {
		t.Errorf("cnf is %v, want x5t#S256 = %s. RFC 8705 §3.2 conveys the "+
			"certificate hash here so the resource server can compare it against "+
			"the client certificate on its own connection", cnf, want)
	}
}

// `aud` is a fact about the token, not about whoever is asking.
//
// RFC 7662 §2.2 defines it as "the intended audience for this token". We
// answered with the caller's own client id, so the client that fetched a token
// audienced to a resource server was told the token was audienced to itself.
//
// That is wrong in the one case introspection is reached for -- working out why
// a token is being refused at the resource server it was meant for -- and it
// makes an RS's audience check vacuous, because the answer is always the asker.
func TestIntrospectionReportsTheTokensAudienceNotTheCallers(t *testing.T) {
	f := newTokenFixture(t)

	const rsName = "https://api.example.test/orders"
	const verifier = "verifier-introspect-aud-aaaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeForResource(t, verifier, rsName)
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", body)
	}

	secret := revocableClient(t, f)
	got := f.introspect(t, access, f.clientID, secret)
	if got["active"] != true {
		t.Fatalf("token reported inactive: %v", got)
	}
	if got["aud"] != rsName {
		t.Errorf("aud is %v, want %q — the resource server the token was minted "+
			"for. Echoing the caller back tells the client its token is addressed "+
			"to itself, which is exactly the question it came here to ask",
			got["aud"], rsName)
	}
	if got["aud"] == got["client_id"] {
		t.Errorf("aud equals client_id (%v); the caller is being reported as the "+
			"audience rather than the token's own", got["aud"])
	}
}

func TestADPoPRefusalChallengeCarriesTheAcceptableAlgorithms(t *testing.T) {
	f := newTokenFixture(t)
	key := newProofKey(t)

	const verifier = "verifier-dpop-challenge-aaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}, key.proof(t, "jti-dpop-challenge-1"))
	if status != http.StatusOK {
		t.Fatalf("redemption under DPoP gave %d: %v", status, body)
	}
	access, _ := body["access_token"].(string)

	// §7.2's downgrade: a bound token presented under the Bearer scheme. It is
	// refused, and the refusal is a DPoP challenge.
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a DPoP-bound token presented as Bearer gave %d, want 401", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(ch, "DPoP") {
		t.Fatalf("the challenge is not a DPoP challenge: %q", ch)
	}
	if !strings.Contains(ch, "algs=") {
		t.Errorf("the refusal challenge carries no algs parameter: %q — RFC 9449 "+
			"§7.1 SHOULD include it, and Figure 16 shows it on exactly this case", ch)
	}
	// It must name algorithms we actually accept, not a hardcoded list that can
	// drift from what Verify enforces.
	if !strings.Contains(ch, "ES256") {
		t.Errorf("algs does not include ES256, which this server accepts: %q", ch)
	}
	if strings.Contains(ch, "none") || strings.Contains(ch, "HS256") {
		t.Errorf("algs advertises a symmetric or none algorithm, which would let a "+
			"caller mint a proof for any key: %q", ch)
	}
}
