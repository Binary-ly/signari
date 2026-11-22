package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oidc"
)

// RFC 9449 §10 binds an authorization code to the key `dpop_jkt` names, and §10.1 to the
// key of a proof on the push "as if the contained public key's thumbprint was provided
// using dpop_jkt" (specs/rfc9449.txt:1283-1290). The parameter was read, kept with a
// pushed request and checked at the token endpoint, and the code was issued without it,
// so a code was redeemed with whatever key came (13.01, FAPI 2.0's
// ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt). It had never been set.
func TestACodeIsRedeemedOnlyWithTheKeyItsRequestNamed(t *testing.T) {
	f := newSignInFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET first_party = true WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	cookie := f.signInAndReturnCookie(t)
	bound, other := newProofKey(t), newProofKey(t)

	codeOf := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || loc.Query().Get("code") == "" {
			t.Fatalf("no code came back (%d, %q): %.300s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
		return loc.Query().Get("code")
	}
	redeem := func(code string, key *proofKey) int {
		t.Helper()
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
			"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
		req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proofFor(t, jose.ES256, key.priv, http.MethodPost, f.srv.cfg.Issuer+oidc.PathToken, ""))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	pushWithProof := func(key *proofKey) string {
		t.Helper()
		form, _ := url.ParseQuery(f.plainAuthz())
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proofFor(t, jose.ES256, key.priv, http.MethodPost, f.srv.cfg.Issuer+"/oauth2/par", ""))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var out struct {
			RequestURI string `json:"request_uri"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.RequestURI == "" {
			t.Fatalf("the push answered %d %s", rec.Code, rec.Body)
		}
		return out.RequestURI
	}
	named := url.Values{"dpop_jkt": {bound.thumbprint(t)}}

	if code := redeem(codeOf(f.authorizeWith(t, cookie, named)), other); code == http.StatusOK {
		t.Error("a code bound by dpop_jkt was redeemed with another key")
	}
	if code := redeem(codeOf(f.authorizeWith(t, cookie, named)), bound); code != http.StatusOK {
		t.Errorf("a code bound by dpop_jkt was refused its own key: %d", code)
	}
	if code := redeem(codeOf(f.byHandle(t, cookie, pushWithProof(bound))), other); code == http.StatusOK {
		t.Error("a code pushed behind a proof was redeemed with another key")
	}
	if code := redeem(codeOf(f.byHandle(t, cookie, pushWithProof(bound))), bound); code != http.StatusOK {
		t.Errorf("a code pushed behind a proof was refused its own key: %d", code)
	}
}
