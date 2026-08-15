package directory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A fake Workspace, shaped exactly like the documented Admin SDK responses.
//
// It cannot prove we agree with Google -- only Google can do that, and it needs
// credentials. What it DOES prove is everything else: that pagination is
// followed to the end, that a mid-fetch failure is an error rather than a short
// list, that the assertion is signed and exchanged, and that suspended and
// archived users are both treated as gone. Those are the parts that decide
// whether a bad fetch deactivates a company.
func fakeWorkspace(t *testing.T, pages [][]map[string]any, failOnPage int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-token", "expires_in": 3600,
			})

		case strings.Contains(r.URL.Path, "/users"):
			if r.Header.Get("Authorization") != "Bearer fake-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			idx := 0
			if tok := r.URL.Query().Get("pageToken"); tok != "" {
				_, _ = fmt.Sscanf(tok, "page-%d", &idx)
			}
			if failOnPage >= 0 && idx == failOnPage {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"code": 500, "message": "backend error"},
				})
				return
			}
			body := map[string]any{"users": pages[idx]}
			if idx+1 < len(pages) {
				body["nextPageToken"] = fmt.Sprintf("page-%d", idx+1)
			}
			_ = json.NewEncoder(w).Encode(body)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testSource(t *testing.T, srv *httptest.Server) *GoogleSource {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	return &GoogleSource{
		Creds: &GoogleCredentials{
			Type: "service_account", ClientEmail: "sync@project.iam.gserviceaccount.com",
			PrivateKey: keyPEM, TokenURI: srv.URL + "/token",
		},
		Impersonate: "admin@example.test",
		Domain:      "example.test",
		BaseURL:     srv.URL,
		Client:      srv.Client(),
	}
}

func user(id, email string, suspended, archived bool) map[string]any {
	return map[string]any{
		"id": id, "primaryEmail": email,
		"name":      map[string]any{"fullName": email},
		"suspended": suspended, "archived": archived,
	}
}

func TestFetchFollowsEveryPage(t *testing.T) {
	srv := fakeWorkspace(t, [][]map[string]any{
		{user("1", "a@example.test", false, false)},
		{user("2", "b@example.test", false, false)},
		{user("3", "c@example.test", false, false)},
	}, -1)

	got, err := testSource(t, srv).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("fetched %d users across 3 pages, want 3", len(got))
	}
}

// TestAFailedPageIsAnErrorNotAShortList.
//
// The most dangerous possible bug in this file. A fetch that returns the first
// page and swallows a failure on the second hands the reconciler a list that
// looks like most of the company left -- and the reconciler is designed to
// believe what it is given.
func TestAFailedPageIsAnErrorNotAShortList(t *testing.T) {
	srv := fakeWorkspace(t, [][]map[string]any{
		{user("1", "a@example.test", false, false)},
		{user("2", "b@example.test", false, false)},
	}, 1) // second page fails

	got, err := testSource(t, srv).Fetch(context.Background())
	if err == nil {
		t.Fatalf("a failed page returned %d users and no error", len(got))
	}
	if got != nil {
		t.Error("a partial list was returned alongside the error")
	}
}

func TestSuspendedAndArchivedAreBothGone(t *testing.T) {
	srv := fakeWorkspace(t, [][]map[string]any{{
		user("1", "active@example.test", false, false),
		user("2", "suspended@example.test", true, false),
		user("3", "archived@example.test", false, true),
	}}, -1)

	got, err := testSource(t, srv).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]bool{}
	for _, u := range got {
		state[u.Email] = u.Suspended
	}
	if state["active@example.test"] {
		t.Error("an active user was reported suspended")
	}
	if !state["suspended@example.test"] {
		t.Error("a suspended user was not")
	}
	if !state["archived@example.test"] {
		t.Error("an archived user was not treated as gone")
	}
}

// TestNoImpersonationIsRefusedWithTheReason. A service account with no subject
// gets a 403 from Google that explains nothing.
func TestNoImpersonationIsRefusedWithTheReason(t *testing.T) {
	srv := fakeWorkspace(t, [][]map[string]any{{}}, -1)
	s := testSource(t, srv)
	s.Impersonate = ""

	_, err := s.Fetch(context.Background())
	if err == nil {
		t.Fatal("a fetch with no impersonated administrator was attempted")
	}
	if !strings.Contains(err.Error(), "domain-wide delegation") {
		t.Errorf("the error should name the actual cause; got %v", err)
	}
}

func TestCredentialParsing(t *testing.T) {
	if _, err := ParseGoogleCredentials([]byte(`{"type":"authorized_user"}`)); err == nil {
		t.Error("an OAuth client secret was accepted as a service account key")
	} else if !strings.Contains(err.Error(), "domain-wide delegation") {
		t.Errorf("the error should say why it will not work; got %v", err)
	}
	if _, err := ParseGoogleCredentials([]byte(`not json`)); err == nil {
		t.Error("garbage was accepted")
	}
	c, err := ParseGoogleCredentials([]byte(
		`{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.TokenURI == "" {
		t.Error("the default token URI was not filled in")
	}
}
