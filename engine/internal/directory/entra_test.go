package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A fake Graph. Pagination uses an ABSOLUTE @odata.nextLink carrying an opaque
// skip token, which is the part implementations get wrong: rebuilding the query
// from parts loses the token and re-reads page one forever.
func fakeGraph(t *testing.T, pages [][]map[string]any, failOnPage int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token"})

		case strings.Contains(r.URL.Path, "/users"):
			if r.Header.Get("Authorization") != "Bearer graph-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			idx := 0
			if s := r.URL.Query().Get("$skiptoken"); s != "" {
				_, _ = fmt.Sscanf(s, "skip-%d", &idx)
			}
			if failOnPage >= 0 && idx == failOnPage {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": "serviceError", "message": "upstream"},
				})
				return
			}
			body := map[string]any{"value": pages[idx]}
			if idx+1 < len(pages) {
				body["@odata.nextLink"] = fmt.Sprintf("%s/v1.0/users?$skiptoken=skip-%d",
					srv.URL, idx+1)
			}
			_ = json.NewEncoder(w).Encode(body)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func entraSource(srv *httptest.Server) *EntraSource {
	return &EntraSource{
		Creds:    &EntraCredentials{TenantID: "t", ClientID: "c", ClientSecret: "s"},
		BaseURL:  srv.URL,
		TokenURL: srv.URL + "/token",
		Client:   srv.Client(),
	}
}

func graphUser(id, upn, mail string, enabled bool) map[string]any {
	return map[string]any{
		"id": id, "userPrincipalName": upn, "mail": mail,
		"displayName": upn, "accountEnabled": enabled,
	}
}

func TestGraphFollowsTheNextLink(t *testing.T) {
	srv := fakeGraph(t, [][]map[string]any{
		{graphUser("1", "a@x.test", "a@x.test", true)},
		{graphUser("2", "b@x.test", "b@x.test", true)},
		{graphUser("3", "c@x.test", "c@x.test", true)},
	}, -1)

	got, err := entraSource(srv).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("fetched %d across 3 pages, want 3", len(got))
	}
}

func TestGraphFailedPageIsAnError(t *testing.T) {
	srv := fakeGraph(t, [][]map[string]any{
		{graphUser("1", "a@x.test", "a@x.test", true)},
		{graphUser("2", "b@x.test", "b@x.test", true)},
	}, 1)

	got, err := entraSource(srv).Fetch(context.Background())
	if err == nil {
		t.Fatalf("a failed page returned %d users and no error", len(got))
	}
	if got != nil {
		t.Error("a partial list came back with the error")
	}
}

// TestPrincipalNameIsUsedWhenMailIsEmpty. `mail` is frequently unset in Entra,
// and an empty address would create users nobody can sign in as.
func TestPrincipalNameIsUsedWhenMailIsEmpty(t *testing.T) {
	srv := fakeGraph(t, [][]map[string]any{{
		graphUser("1", "upn-only@x.test", "", true),
		graphUser("2", "other@x.test", "preferred@x.test", true),
	}}, -1)

	got, err := entraSource(srv).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]RemoteUser{}
	for _, u := range got {
		byID[u.ID] = u
	}
	if byID["1"].Email != "upn-only@x.test" {
		t.Errorf("empty mail did not fall back to the principal name: %q", byID["1"].Email)
	}
	if byID["2"].Email != "preferred@x.test" {
		t.Errorf("mail was not preferred over the principal name: %q", byID["2"].Email)
	}
}

func TestDisabledAccountIsSuspended(t *testing.T) {
	srv := fakeGraph(t, [][]map[string]any{{
		graphUser("1", "on@x.test", "on@x.test", true),
		graphUser("2", "off@x.test", "off@x.test", false),
	}}, -1)

	got, err := entraSource(srv).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range got {
		if u.Email == "off@x.test" && !u.Suspended {
			t.Error("accountEnabled=false was not treated as suspended")
		}
		if u.Email == "on@x.test" && u.Suspended {
			t.Error("an enabled account was reported suspended")
		}
	}
}

func TestEntraCredentialParsing(t *testing.T) {
	if _, err := ParseEntraCredentials([]byte(`{"tenant_id":"t"}`)); err == nil {
		t.Error("an incomplete credential was accepted")
	}
	if _, err := ParseEntraCredentials([]byte(`{`)); err == nil {
		t.Error("malformed JSON was accepted")
	}
}
