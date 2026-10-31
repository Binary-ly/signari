package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// A token redeemed from an offer was an ordinary access token for the offer's
// client, and worked wherever that client's tokens did. Nobody signed in to get
// it, so each door is tried with it and with a token that did come from a
// sign-in: the second proves the door is open, the first that it is not open to
// this.
func TestARedeemedOffersTokenIsGoodForNothingElse(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	f.enableExchange(t)
	issuance := f.mintAccessToken(t)
	ordinary := f.mintAccessTokenWithScope(t, []string{"read"})
	const accessToken = "urn:ietf:params:oauth:token-type:access_token"

	userinfo := func(token string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	// Past the audience and stopped at the scope, which this one does not carry.
	if got := userinfo(ordinary); got != http.StatusForbidden {
		t.Fatalf("an ordinary token at userinfo answered %d", got)
	}
	if got := userinfo(issuance); got != http.StatusUnauthorized {
		t.Errorf("an issuance token at userinfo answered %d", got)
	}

	introspect := func(token string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(f.clientID), url.QueryEscape(f.exchangeSecret))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var b map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatalf("introspection answered %d %q", rec.Code, rec.Body.String())
		}
		return b
	}
	if got := introspect(ordinary); got["active"] != true {
		t.Fatalf("an ordinary token introspected as %v", got)
	}
	if got := introspect(issuance); got["active"] != false {
		t.Errorf("an issuance token introspected as %v", got)
	}

	exchange := func(extra url.Values) (int, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {oauth.GrantTypeTokenExchange}, "client_id": {f.clientID},
			"client_secret": {f.exchangeSecret}, "subject_token_type": {accessToken},
			"audience": {exchangeAudience}}
		for k, v := range extra {
			form[k] = v
		}
		return f.post(t, form)
	}
	refused := func(what string, status int, body map[string]any) {
		t.Helper()
		desc, _ := body["error_description"].(string)
		if status != http.StatusBadRequest || body["error"] != "invalid_grant" ||
			!strings.Contains(desc, "nothing else") {
			t.Errorf("%s answered %d %v", what, status, body)
		}
	}
	if status, body := exchange(url.Values{"subject_token": {ordinary}}); status != http.StatusOK {
		t.Fatalf("exchanging an ordinary token answered %d %v", status, body)
	}
	status, body := exchange(url.Values{"subject_token": {issuance}})
	refused("exchanging an issuance token", status, body)

	if status, body := exchange(url.Values{"subject_token": {ordinary}, "actor_token": {ordinary},
		"actor_token_type": {accessToken}}); status != http.StatusOK {
		t.Fatalf("acting with an ordinary token answered %d %v", status, body)
	}
	status, body = exchange(url.Values{"subject_token": {ordinary}, "actor_token": {issuance},
		"actor_token_type": {accessToken}})
	refused("acting with an issuance token", status, body)

	if status, body := f.txnToken(t, ordinary, accessToken, "read"); status != http.StatusOK {
		t.Fatalf("a transaction token from an ordinary token answered %d %v", status, body)
	}
	status, body = f.txnToken(t, issuance, accessToken, "read")
	refused("a transaction token from an issuance token", status, body)

	// And the other way round: what a sign-in holds does not reach this endpoint.
	if status, _ := f.postJSON(t, "/oid4vci/credential", ordinary, "{}"); status != http.StatusUnauthorized {
		t.Errorf("an ordinary token at the credential endpoint answered %d", status)
	}
}
