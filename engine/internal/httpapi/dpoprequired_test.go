package httpapi

import (
	"context"
	"net/http"
	"net/url"
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
