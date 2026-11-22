package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `profile` releases the names an account holds, in the ID token and at
// userinfo, and nothing without it. They were never released: the code said
// no display name was stored anywhere, which stopped being true with
// migration 0105 (2.15).
func TestProfileReleasesTheNamesAnAccountHolds(t *testing.T) {
	f := newTokenFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.users
		SET display_name = 'Ada Lovelace', given_name = 'Ada', surname = 'Lovelace' WHERE id = $1::uuid`,
		f.userID); err != nil {
		t.Fatal(err)
	}
	names := func(scopes []string, verifier string) (idToken, userinfo map[string]any) {
		t.Helper()
		code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, scopes)
		status, body := f.post(t, f.redeem(code, verifier))
		if status != http.StatusOK {
			t.Fatalf("redemption gave %d %v", status, body)
		}
		parts := strings.Split(body["id_token"].(string), ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(payload, &idToken)

		req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+body["access_token"].(string))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("userinfo gave %d %s", rec.Code, rec.Body)
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &userinfo)
		return idToken, userinfo
	}

	id, info := names([]string{"openid", "profile"}, "verifier-profile-names-aaaaaaaaaaaaaaaaaaaaaaa")
	for where, claims := range map[string]map[string]any{"the ID token": id, "userinfo": info} {
		if claims["name"] != "Ada Lovelace" || claims["given_name"] != "Ada" || claims["family_name"] != "Lovelace" {
			t.Errorf("%s under profile carries name %v, given_name %v, family_name %v",
				where, claims["name"], claims["given_name"], claims["family_name"])
		}
	}

	id, info = names([]string{"openid"}, "verifier-profile-names-bbbbbbbbbbbbbbbbbbbbbbb")
	for where, claims := range map[string]map[string]any{"the ID token": id, "userinfo": info} {
		for _, c := range []string{"name", "given_name", "family_name"} {
			if _, ok := claims[c]; ok {
				t.Errorf("%s without profile carries %s", where, c)
			}
		}
	}
}
