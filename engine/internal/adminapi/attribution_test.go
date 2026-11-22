package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Who made a change (6.05): the token, the person the caller acts for, the
// break-glass token marked, and what each setting was before.

func patchAs(t *testing.T, s *Server, token, operator, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	if operator != "" {
		r.Header.Set(OperatorHeader, operator)
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, r)
	return rec
}

type recorded struct {
	TokenID string
	Detail  map[string]any
}

func clientUpdates(t *testing.T, s *Server, clientID string) []recorded {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT coalesce(admin_token_id::text, ''), detail
		FROM core.audit_events WHERE client_id = $1 AND event_type = 'admin.client_updated'
		ORDER BY occurred_at, id`, clientID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []recorded
	for rows.Next() {
		var r recorded
		var raw []byte
		if err := rows.Scan(&r.TokenID, &raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &r.Detail)
		out = append(out, r)
	}
	return out
}

func TestTwoOperatorsOnOneTokenAreTwoActors(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)
	console := mintToken(t, s, "attribution-console-"+client, "", []string{ScopeClientsWrite, ScopeAuditRead}, nil)

	if rec := patchAs(t, s, console, "console-user:41", "/admin/clients/"+client, `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("first operator: %d %s", rec.Code, rec.Body.String())
	}
	if rec := patchAs(t, s, console, "console-user:42", "/admin/clients/"+client, `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("second operator: %d %s", rec.Code, rec.Body.String())
	}
	if rec := patchAs(t, s, console, "alice@example.com", "/admin/clients/"+client, `{"enabled":false}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an address as the operator answered %d", rec.Code)
	}
	if rec := patchAs(t, s, testToken, "", "/admin/clients/"+client, `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("break-glass: %d %s", rec.Code, rec.Body.String())
	}

	got := clientUpdates(t, s, client)
	if len(got) != 3 {
		t.Fatalf("%d update records, want 3 (the address refused, nothing written)", len(got))
	}
	if got[0].Detail["operator"] != "console-user:41" || got[1].Detail["operator"] != "console-user:42" {
		t.Errorf("two people on one token are not two actors: %v / %v", got[0].Detail["operator"], got[1].Detail["operator"])
	}
	if got[0].TokenID == "" || got[0].TokenID != got[1].TokenID {
		t.Errorf("the console's token is not named on its records: %q %q", got[0].TokenID, got[1].TokenID)
	}
	if got[2].TokenID != "" || got[2].Detail["break_glass"] != true {
		t.Errorf("the break-glass write is not marked: token %q detail %v", got[2].TokenID, got[2].Detail)
	}
	if got[0].Detail["break_glass"] != nil {
		t.Errorf("an ordinary token's write is marked break-glass")
	}

	// What it was, and what it became.
	changes, _ := got[0].Detail["changes"].(map[string]any)
	if e, _ := changes["enabled"].(map[string]any); e["from"] != true || e["to"] != false {
		t.Errorf("the first change's before and after: %v", changes)
	}
	if len(changes) != 1 {
		t.Errorf("a change of one setting recorded %d", len(changes))
	}
	for _, secret := range []string{"client_secret_hash", "registration_token_hash"} {
		if _, ok := changes[secret]; ok {
			t.Errorf("%s reached the trail", secret)
		}
	}

	// The read names the token and finds its records by it.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/audit-events?event_type=admin.client_updated&client_id="+
		url.QueryEscape(client)+"&admin_token_id="+url.QueryEscape(got[0].TokenID), nil)
	r.Header.Set("Authorization", "Bearer "+console)
	s.Routes().ServeHTTP(rec, r)
	var page struct {
		Events []auditEvent `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if rec.Code != http.StatusOK || len(page.Events) != 2 || page.Events[0].AdminTokenID != got[0].TokenID {
		t.Errorf("the trail by token: %d, %d events %s", rec.Code, len(page.Events), truncate(rec.Body.String(), 200))
	}
}

func TestAClientChangeOfNothingRecordsNoChanges(t *testing.T) {
	s, _ := newTestServer(t)
	client := newPreconditionClient(t, s)
	if rec := patchAs(t, s, testToken, "", "/admin/clients/"+client, `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, err := s.db.Exec(context.Background(), `UPDATE core.clients SET tls_san_email = 'device-owner@example.com'
		WHERE client_id = $1`, client); err != nil {
		t.Fatal(err)
	}
	if rec := patchAs(t, s, testToken, "", "/admin/clients/"+client, `{"require_pkce":false}`); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	got := clientUpdates(t, s, client)
	if c, _ := got[0].Detail["changes"].(map[string]any); len(c) != 0 {
		t.Errorf("a request that changed nothing recorded %v", c)
	}
	raw, _ := json.Marshal(got[1].Detail)
	if strings.Contains(string(raw), "device-owner") {
		t.Errorf("a certificate address reached the trail: %s", raw)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
