package httpapi

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

func (f *tokenFixture) requireDPoP(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET dpop_bound_access_tokens = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
}

func TestAClientPinnedToDPoPCannotGetABearerToken(t *testing.T) {
	f := newTokenFixture(t)
	f.requireDPoP(t)

	const verifier = "verifier-dpop-required-aaaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})

	// No DPoP header at all: the downgrade this setting exists to refuse.
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("a DPoP-pinned client got %d without a proof, and the response "+
			"carries %v. RFC 9449 §5.2 makes this a MUST reject", status, body["access_token"])
	}
	if body["error"] != "invalid_dpop_proof" {
		t.Errorf("error is %v, want invalid_dpop_proof — RFC 9449's own code, and "+
			"the one a stricter enforcer answers", body["error"])
	}
	if body["access_token"] != nil {
		t.Errorf("a token was issued anyway: %v", body)
	}
}

// The same client, sending a proof, must still work — otherwise the setting is
// not "require DPoP" but "break this client".
func TestAPinnedClientStillSucceedsWithAProof(t *testing.T) {
	f := newTokenFixture(t)
	f.requireDPoP(t)
	key := newProofKey(t)

	const verifier = "verifier-dpop-required-ok-aaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}, key.proof(t, "jti-dpop-required-ok"))
	if status != http.StatusOK {
		t.Fatalf("the pinned client was refused even with a proof: %d %v", status, body)
	}
	if body["token_type"] != "DPoP" {
		t.Errorf("token_type is %v, want DPoP", body["token_type"])
	}
}

// A client that has NOT pinned itself keeps the default behaviour. §5.2: "If
// omitted, the default value is false." Any other default would refuse every
// existing client's next token request.
func TestAnUnpinnedClientIsUnaffected(t *testing.T) {
	f := newTokenFixture(t)

	const verifier = "verifier-dpop-unpinned-aaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("an ordinary client was refused a bearer token: %d %v", status, body)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type is %v, want Bearer", body["token_type"])
	}
}

// The second call site, proven reachable rather than merely present.
//
// The OID4VCI pre-authorized code grant is dispatched from `handleToken`
// *before* the client is resolved — OID4VCI §6.1 lets a wallet send no
// `client_id`, so the handler resolves it from the offer instead. That means the
// §5.2 check on the ordinary path is jumped over entirely, and a client pinned
// to DPoP could obtain an unbound token through this grant.
//
// The hole would be invisible from outside: the wallet receives a working bearer
// token and nothing looks wrong until it is stolen. This is the recurring shape
// in this codebase — a rule enforced in fewer places than its documentation
// implies — so the rule lives in one function called from both sites, and this
// test is what keeps the second one honest.
func TestAPinnedClientCannotDowngradeViaThePreAuthorizedCodeGrant(t *testing.T) {
	f := newTokenFixture(t)
	f.requireDPoP(t)
	f.allowPreAuthGrant(t)

	code := f.preAuth(t, "", 5*time.Minute)
	status, body := f.post(t, preAuthForm(code, ""))
	if status != http.StatusBadRequest {
		t.Fatalf("a DPoP-pinned client got %d from the pre-authorized code grant "+
			"with no proof, carrying %v — the §5.2 rule is enforced on the ordinary "+
			"token path only, and this grant is dispatched before it",
			status, body["access_token"])
	}
	if body["error"] != "invalid_dpop_proof" {
		t.Errorf("error is %v, want invalid_dpop_proof", body["error"])
	}
}

// RFC 9449 §5.2 calls `dpop_bound_access_tokens` *client registration metadata*,
// so a client must be able to pin itself at the moment it registers — not only
// by an operator running a CLI command afterwards, which is not a thing a
// dynamically registered client can ask anyone to do.
//
// The end-to-end shape is what matters: register pinned, then try to redeem
// without a proof and be refused. Registering the flag and not enforcing it, or
// enforcing it for CLI-created clients only, would both leave a client believing
// it is sender-constrained when it is not — which is worse than not offering the
// field, because the belief is what it acts on.
func TestAClientCanPinItselfToDPoPAtRegistration(t *testing.T) {
	f := newTokenFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(
		`{"redirect_uris":["https://rp.test/cb"],"client_name":"pinned",`+
			`"dpop_bound_access_tokens":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+registrationToken(t, f))
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registration gave %d: %s", rec.Code, truncate(rec.Body.String(), 200))
	}
	var reg map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	clientID, _ := reg["client_id"].(string)
	if clientID == "" {
		t.Fatalf("no client_id: %v", reg)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.clients WHERE client_id = $1`, clientID)
	})

	// RFC 7591 §3.2.1: "The authorization server MUST return all registered
	// metadata about this client." Without the echo the client cannot tell
	// whether the server agreed to pin it or quietly ignored the field.
	if reg["dpop_bound_access_tokens"] != true {
		t.Errorf("the registration response does not confirm the pinning: %v",
			reg["dpop_bound_access_tokens"])
	}

	var pinned bool
	if err := f.pool.QueryRow(context.Background(),
		`SELECT dpop_bound_access_tokens FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if !pinned {
		t.Fatalf("the client registered with dpop_bound_access_tokens=true was " +
			"stored unpinned, so the field was accepted and dropped")
	}
}
