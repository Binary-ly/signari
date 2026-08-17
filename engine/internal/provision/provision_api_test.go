package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A fake Google Admin SDK and a fake Microsoft Graph.
//
// These check the SHAPE of what is sent, because that is what the real APIs
// reject and what no amount of reading the code reveals. Google suspends with
// PUT and a `suspended` field; Graph disables with PATCH and `accountEnabled`.
// Getting either wrong produces a 400 at the moment somebody is being
// deprovisioned, which is the worst time to discover it.

func TestGoogleListsEveryPage(t *testing.T) {
	// Two pages. A client that stops at the first decides every user beyond it
	// has been deleted, and the next sync deactivates them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("pageToken") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": "1", "primaryEmail": "a@x.test"},
					{"id": "2", "primaryEmail": "b@x.test", "suspended": true},
				},
				"nextPageToken": "page2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"users": []map[string]any{{"id": "3", "primaryEmail": "c@x.test"}},
		})
	}))
	defer srv.Close()

	g := &Google{BaseURL: srv.URL, Domain: "x.test", token: "t", expires: farFuture()}
	users, err := g.ListUsers(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3 across two pages — a client that stops at "+
			"the first page reports everyone beyond it as missing", len(users))
	}
	if users[1].Active {
		t.Error("a suspended Google account should be reported inactive")
	}
	// RemoteID, not ExternalID: the first is the target's own identifier and is
	// what every later update addresses; the second is ours, stored on the
	// remote record. Conflating them means a deactivation addressed by an id the
	// far end does not recognise, which succeeds against nothing.
	if users[0].RemoteID != "1" {
		t.Errorf("the remote id should be Google's user id, got %q", users[0].RemoteID)
	}
}

func TestGoogleSuspendsWithTheRightVerbAndField(t *testing.T) {
	var method, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	g := &Google{BaseURL: srv.URL, token: "t", expires: farFuture()}
	if err := g.SetActive(context.Background(), "123", false); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut {
		t.Errorf("Google suspends with PUT, used %s", method)
	}
	if !strings.Contains(body, `"suspended":true`) {
		t.Errorf("deactivating must set suspended=true, sent %s", body)
	}
}

func TestEntraDisablesWithTheRightVerbAndField(t *testing.T) {
	var method, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		body = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	e := &Entra{BaseURL: srv.URL, token: "t", expires: farFuture()}
	if err := e.SetActive(context.Background(), "abc", false); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPatch {
		t.Errorf("Graph disables with PATCH, used %s", method)
	}
	if !strings.Contains(body, `"accountEnabled":false`) {
		t.Errorf("deactivating must set accountEnabled=false, sent %s", body)
	}
}

func TestEntraCompletesAUserPrincipalName(t *testing.T) {
	var got entraUser
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "new-id"})
	}))
	defer srv.Close()

	e := &Entra{BaseURL: srv.URL, Domain: "acme.test", token: "t", expires: farFuture()}
	id, err := e.CreateUser(context.Background(), User{
		UserName: "alice", DisplayName: "Alice", Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "new-id" {
		t.Errorf("remote id %q", id)
	}
	if got.UserPrincipalName != "alice@acme.test" {
		t.Errorf("userPrincipalName = %q, want it completed with the domain",
			got.UserPrincipalName)
	}
	if got.MailNickname != "alice" {
		t.Errorf("mailNickname = %q", got.MailNickname)
	}
	// Both providers demand a password at creation; it must be set and must not
	// be anything guessable.
	if got.PasswordProfile == nil || len(got.PasswordProfile.Password) < 24 {
		t.Error("a long random password must be set at creation")
	}
}

// TestAPIErrorsCarryTheBody: a 400 from Graph explains what was wrong in the
// body, and swallowing it leaves an operator with a status code.
func TestAPIErrorsCarryTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":{"message":"Property userPrincipalName is invalid."}}`)
	}))
	defer srv.Close()

	e := &Entra{BaseURL: srv.URL, token: "t", expires: farFuture()}
	_, err := e.CreateUser(context.Background(), User{UserName: "x@y.test", Active: true})
	if err == nil {
		t.Fatal("a 400 was not reported")
	}
	if !strings.Contains(err.Error(), "userPrincipalName is invalid") {
		t.Errorf("the provider's explanation was dropped: %v", err)
	}
}

func TestSafetyLimitRefusesAMassDeactivation(t *testing.T) {
	d := Drift{ToDeactivate: make([]User, 60)}
	if err := CheckSafety(d, 100); err == nil {
		t.Fatal("deactivating 60 of 100 accounts was allowed")
	}
	// A small proportion is ordinary leaver processing and must not be blocked.
	if err := CheckSafety(Drift{ToDeactivate: make([]User, 5)}, 100); err != nil {
		t.Errorf("deactivating 5 of 100 should be fine: %v", err)
	}
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }
