package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Read endpoints, and the properties that make them safe to expose.
//
// The interesting assertions here are the negative ones: a read must not leak
// credential material, must not cross the organisation boundary, and must not be
// able to return an unbounded page.

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
}

// The read-modify-write cycle a conditional write needs, end to end, using only
// what the responses carry.
//
// This is the test that says the two halves fit together. Before the read
// endpoints existed a caller could obtain an ETag only from
// /admin/config-version, so every edit needed an extra request that had nothing
// to do with the resource being edited.
func TestAClientCanBeReadAndThenConditionallyWrittenFromTheResponseAlone(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)

	read := httptest.NewRecorder()
	s.Routes().ServeHTTP(read, adminReq(t, http.MethodGet, "/admin/clients/"+clientID, "", ""))
	if read.Code != http.StatusOK {
		t.Fatalf("GET gave %d: %s", read.Code, read.Body.String())
	}
	tag := read.Header().Get("ETag")
	if tag == "" {
		t.Fatal("a read carried no ETag, so a caller cannot make its write conditional " +
			"without an unrelated extra request")
	}

	write := httptest.NewRecorder()
	s.Routes().ServeHTTP(write, adminReq(t, http.MethodPatch, "/admin/clients/"+clientID,
		`{"enabled":false}`, tag))
	if write.Code != http.StatusOK {
		t.Fatalf("the ETag from the read was not accepted as If-Match: %d %s",
			write.Code, write.Body.String())
	}
	if clientEnabled(t, s, clientID) {
		t.Error("the conditional write reported success without applying")
	}
}

// A client read gives its redirect URIs, sorted (2.17). It gave none, so a
// caller holding a desired list had nothing to compare it with, and the
// Terraform provider reported a change to them as applied while sending nothing.
func TestAClientReadGivesItsRedirectURIs(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)
	for _, u := range []string{"https://b.example/cb", "https://a.example/cb"} {
		if _, err := s.db.Exec(context.Background(), `INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)`, clientID, u); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, "/admin/clients/"+clientID, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET gave %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		ClientID     string   `json:"client_id"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	decodeBody(t, rec, &got)
	if got.ClientID != clientID || fmt.Sprint(got.RedirectURIs) != "[https://a.example/cb https://b.example/cb]" {
		t.Errorf("GET gave %s, want the client with both redirect URIs in order", rec.Body.String())
	}
}

// A read must never return credential material.
//
// The failure this prevents is specific: `core.clients.client_secret_hash` is a
// verifier. An admin API that returns it turns read access into the ability to
// authenticate as every application, and it would arrive by someone selecting
// `*` for convenience.
func TestAClientReadNeverReturnsCredentialMaterial(t *testing.T) {
	s, _ := newTestServer(t)
	clientID := newPreconditionClient(t, s)
	// Verifiers worth searching for: the fixture's one-letter hash could not
	// be told apart from any other text.
	planted := fmt.Sprintf("planted-verifier-%d", time.Now().UnixNano())
	registration := sha256.Sum256([]byte(planted))
	if _, err := s.db.Exec(context.Background(), `UPDATE core.clients
		SET client_secret_hash = $2, registration_token_hash = $3
		WHERE client_id = $1`, clientID, planted, registration[:]); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/admin/clients/" + clientID, "/admin/clients"} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, path, "", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s gave %d", path, rec.Code)
		}
		// No verifier, as text or as the hex a bytea column reads back as.
		body := rec.Body.String()
		for _, v := range []string{planted, fmt.Sprintf("%x", registration)} {
			if strings.Contains(body, v) {
				t.Errorf("%s returned a stored verifier: %s", path, body)
			}
		}
		// And no field for one, at any depth. The words may appear in a value
		// that names a method (client_secret_post) and holds nothing; since the
		// whole configuration is returned (6.03), a body that merely never says
		// "secret" is no longer the property.
		var decoded any
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					for _, forbidden := range []string{"secret", "hash", "password"} {
						if strings.Contains(strings.ToLower(k), forbidden) {
							t.Errorf("%s returned a field %q", path, k)
						}
					}
					walk(e)
				}
			case []any:
				for _, e := range x {
					walk(e)
				}
			}
		}
		walk(decoded)
	}
}

// The same, for users: no password hash, no TOTP secret, no recovery codes.
//
// A planted password and the hash stored for it must appear nowhere, and no
// field may be named for a credential unless it is a flag about one: since the
// read shows what PATCH sets (6.08), it says require_password_change, so a
// body that never says "password" is no longer the property.
func TestAUserReadNeverReturnsCredentialMaterial(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	planted := fmt.Sprintf("planted-%d-pw", time.Now().UnixNano())
	email := fmt.Sprintf("cred-read-%d@example.test", time.Now().UnixNano())
	rec := call(t, s, http.MethodPost, "/admin/users", testToken, map[string]any{"org_id": anyOrgID(t, s),
		"email": email, "password": planted})
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating the user: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	t.Cleanup(func() { _, _ = s.db.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, created.ID) })
	var stored string
	if err := s.db.QueryRow(ctx, `SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`,
		created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{"require_password_change": true}

	for _, path := range []string{"/admin/users/" + created.ID, "/admin/users/" + newDriftUserWithTOTP(t, s),
		"/admin/users?email=" + url.QueryEscape(email)} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, path, "", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s gave %d: %s", path, rec.Code, rec.Body.String())
		}
		for _, v := range []string{planted, stored} {
			if strings.Contains(rec.Body.String(), v) {
				t.Errorf("%s returned a password or its stored hash: %s", path, rec.Body.String())
			}
		}
		var decoded any
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					for _, forbidden := range []string{"hash", "secret", "recovery_code", "password", "totp"} {
						if !strings.Contains(strings.ToLower(k), forbidden) {
							continue
						}
						if _, isFlag := e.(bool); !flags[k] || !isFlag {
							t.Errorf("%s returned a field %q: %v", path, k, e)
						}
					}
					walk(e)
				}
			case []any:
				for _, e := range x {
					walk(e)
				}
			}
		}
		walk(decoded)
	}
}

// A page is bounded whatever the caller asks for.
//
// An unbounded admin list is a memory amplifier in both the server and the
// client, and `?limit=100000` is what somebody types when a page looks short.
func TestAListPageIsBoundedAboveWhateverIsRequested(t *testing.T) {
	s, _ := newTestServer(t)
	// Enough rows that a page could exceed the cap if it were not clamped.
	for i := 0; i < 3; i++ {
		newPreconditionClient(t, s)
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, "/admin/clients?limit=100000", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		Clients []clientSummary `json:"clients"`
	}
	decodeBody(t, rec, &body)
	if len(body.Clients) > maxPageSize {
		t.Errorf("returned %d rows for limit=100000; the cap of %d was not applied",
			len(body.Clients), maxPageSize)
	}
}

// Paging with the returned cursor makes progress and does not repeat.
func TestCursorPagingMakesProgressWithoutRepeating(t *testing.T) {
	s, _ := newTestServer(t)
	for i := 0; i < 3; i++ {
		newPreconditionClient(t, s)
	}

	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 5; page++ {
		url := "/admin/clients?limit=1"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet, url, "", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", page, rec.Code, rec.Body.String())
		}
		var body struct {
			Clients    []clientSummary `json:"clients"`
			NextCursor string          `json:"next_cursor"`
		}
		decodeBody(t, rec, &body)
		for _, c := range body.Clients {
			if seen[c.ClientID] {
				t.Fatalf("client %s returned on two pages; the cursor is not advancing",
					c.ClientID)
			}
			seen[c.ClientID] = true
		}
		if body.NextCursor == "" {
			break
		}
		if body.NextCursor == cursor {
			t.Fatalf("next_cursor did not advance past %q; paging would loop forever", cursor)
		}
		cursor = body.NextCursor
	}
	if len(seen) < 3 {
		t.Errorf("paged through only %d clients; the fixtures created at least 3", len(seen))
	}
}

// A read scope grants reading and NOT writing.
func TestAReadScopeCannotWrite(t *testing.T) {
	p := &Principal{Scopes: []string{ScopeClientsRead}}
	if !p.Can(ScopeClientsRead) {
		t.Error("clients:read does not grant clients:read")
	}
	if p.Can(ScopeClientsWrite) {
		t.Error("clients:read granted clients:write; the implication must run one way only")
	}
	if p.Can(ScopeUsersRead) {
		t.Error("clients:read granted users:read")
	}
}

// A write scope grants the matching read.
//
// Without this, adding read endpoints would have removed access from every token
// already issued with `clients:write` -- an upgrade that breaks working
// integrations, which is the kind of change that gets a release rolled back.
func TestAWriteScopeImpliesTheMatchingReadScope(t *testing.T) {
	p := &Principal{Scopes: []string{ScopeClientsWrite}}
	if !p.Can(ScopeClientsRead) {
		t.Error("clients:write does not imply clients:read, so a token that can " +
			"change a client cannot read the one it is changing")
	}
	if p.Can(ScopeUsersRead) {
		t.Error("clients:write implied users:read; the implication must be per-resource")
	}
}

// The organisation boundary applies to reads.
//
// A token scoped to one organisation must not be able to enumerate another's,
// and a leak here is worse than a misdirected write because nothing records it.
func TestAScopedTokenCannotReadAnotherOrganisationsClients(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	// A second organisation with a client in it.
	var otherOrg string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, $1, 'other' FROM core.organizations ORDER BY created_at LIMIT 1
		RETURNING id::text`, fmt.Sprintf("other-%d", time.Now().UnixNano())).Scan(&otherOrg); err != nil {
		t.Fatalf("creating a second organisation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, otherOrg)
	})
	otherClient := fmt.Sprintf("other-%d", time.Now().UnixNano())
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, enabled)
		VALUES ($1, $2::uuid, 'other org client', 'confidential', 'x', true)`,
		otherClient, otherOrg); err != nil {
		t.Fatalf("creating the other org's client: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, otherClient)
	})

	// A token restricted to the FIRST organisation.
	home := anyOrgID(t, s)
	if home == otherOrg {
		t.Fatal("the fixture organisations collided")
	}
	secret := mintToken(t, s, fmt.Sprintf("scoped-%d", time.Now().UnixNano()),
		home, []string{ScopeClientsRead}, nil)

	// The direct read is refused...
	get := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/clients/"+otherClient, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	s.Routes().ServeHTTP(get, req)
	if get.Code != http.StatusForbidden {
		t.Errorf("reading another organisation's client gave %d, want 403: %s",
			get.Code, get.Body.String())
	}

	// ...and the LIST must contain nothing from any other organisation.
	//
	// Asserted as an INVARIANT over every row returned, not as "the fixture's
	// client is absent". The first version of this test searched the body for
	// that one client id and passed with the organisation filter deliberately
	// removed: the test database holds 1,265 clients, the page is capped at 200,
	// and the fixture sorted past the end of the first page. It was checking
	// where a row happened to land rather than whether the boundary held.
	list := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodGet, "/admin/clients?limit=200", nil)
	lreq.Header.Set("Authorization", "Bearer "+secret)
	s.Routes().ServeHTTP(list, lreq)
	if list.Code != http.StatusOK {
		t.Fatalf("list gave %d: %s", list.Code, list.Body.String())
	}
	var body struct {
		Clients []clientSummary `json:"clients"`
	}
	decodeBody(t, list, &body)
	if len(body.Clients) == 0 {
		t.Fatal("the list returned nothing, so it cannot demonstrate the boundary")
	}
	for _, c := range body.Clients {
		if !strings.EqualFold(c.OrgID, home) {
			t.Fatalf("a token scoped to organisation %s was shown client %s from "+
				"organisation %s", home, c.ClientID, c.OrgID)
		}
	}
}
