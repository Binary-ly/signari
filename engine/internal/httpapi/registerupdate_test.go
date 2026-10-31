package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A registrant manages their own client with the token they were given, held to the
// same rules as registering: nobody gets through PUT what POST would have refused.
func TestARegistrantReplacesTheirOwnClient(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	send := func(method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = freshAddress() + ":443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	token := registrationToken(t, f)
	if _, err := f.pool.Exec(ctx, `UPDATE core.registration_policies SET allowed_scopes = ARRAY['openid','profile']
		WHERE org_id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	rec, made := send(http.MethodPost, "/oauth2/register", token,
		`{"redirect_uris":["https://rp.test/cb"],"client_name":"first","scope":"openid"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	id, _ := made["client_id"].(string)
	manage, _ := made["registration_access_token"].(string)
	path := "/oauth2/register/" + id

	put := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		return send(http.MethodPut, path, manage, body)
	}
	for name, tc := range map[string]struct {
		body, want string
	}{
		"another client":  {`{"client_id":"someone-else","redirect_uris":["https://rp.test/cb"]}`, "invalid_client_metadata"},
		"no client id":    {`{"redirect_uris":["https://rp.test/cb"]}`, "invalid_client_metadata"},
		"a chosen secret": {`{"client_id":"` + id + `","client_secret":"x","redirect_uris":["https://rp.test/cb"]}`, "invalid_client_metadata"},
		"no redirects":    {`{"client_id":"` + id + `","redirect_uris":[]}`, "invalid_redirect_uri"},
		"a script":        {`{"client_id":"` + id + `","redirect_uris":["javascript:alert(1)"]}`, "invalid_redirect_uri"},
		"plaintext":       {`{"client_id":"` + id + `","redirect_uris":["http://rp.test/cb"]}`, "invalid_redirect_uri"},
		"not even JSON":   {`nonsense`, "invalid_client_metadata"},
	} {
		if rec, out := put(tc.body); rec.Code != http.StatusBadRequest || out["error"] != tc.want {
			t.Errorf("%s answered %d %v", name, rec.Code, out)
		}
	}

	rec, out := put(`{"client_id":"` + id + `","client_name":"second","scope":"openid profile admin",
		"redirect_uris":["https://rp.test/new","https://rp.test/other"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("replacing: %d %s", rec.Code, rec.Body.String())
	}
	if out["client_name"] != "second" || out["scope"] != "openid profile" {
		t.Errorf("the answer reads %v: a scope past the policy must not be granted", out)
	}
	_, read := send(http.MethodGet, path, manage, "")
	got, _ := read["redirect_uris"].([]any)
	if read["client_name"] != "second" || len(got) != 2 {
		t.Errorf("read back %v", read)
	}
	var old int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.client_redirect_uris
		WHERE client_id = $1 AND redirect_uri = 'https://rp.test/cb'`, id).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if old != 0 {
		t.Error("a redirect replaced is still registered")
	}

	// Somebody else's token gets what any wrong token does.
	if rec, _ := send(http.MethodPut, path, "not-the-token", `{"client_id":"`+id+`","redirect_uris":["https://evil.test/cb"]}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("a wrong token answered %d", rec.Code)
	}
}
