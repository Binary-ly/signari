package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// The issuer for an account, the same whoever is named: nothing here says who exists.
func TestWebFingerNamesTheIssuerWhoeverIsAsked(t *testing.T) {
	f := newTokenFixture(t)
	ask := func(q url.Values) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/webfinger?"+q.Encode(), nil))
		return rec
	}
	const rel = "http://openid.net/specs/connect/1.0/issuer"
	var answers []string
	for _, who := range []string{"acct:ada@example.test", "acct:nobody-at-all@example.test"} {
		rec := ask(url.Values{"resource": {who}, "rel": {rel}})
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/jrd+json" ||
			rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("answered %d, %v", rec.Code, rec.Header())
		}
		var got struct {
			Subject string              `json:"subject"`
			Links   []map[string]string `json:"links"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Subject != who || len(got.Links) != 1 || got.Links[0]["rel"] != rel || got.Links[0]["href"] != f.srv.cfg.Issuer {
			t.Errorf("answered %+v", got)
		}
		answers = append(answers, strings.Replace(rec.Body.String(), who, "", 1))
	}
	if answers[0] != answers[1] {
		t.Errorf("two people get different answers: %q, %q", answers[0], answers[1])
	}
	if rec := ask(url.Values{"resource": {"acct:a@b.test"}, "rel": {"http://example.test/other"}}); !strings.Contains(rec.Body.String(), `"links":[]`) {
		t.Errorf("a relation nobody holds answered %s", rec.Body.String())
	}
	for name, q := range map[string]url.Values{"no resource": {}, "not a URI": {"resource": {"ada"}},
		"too long": {"resource": {"acct:" + strings.Repeat("a", 2000)}}} {
		if rec := ask(q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d", name, rec.Code)
		}
	}
}

// A client held to state hears about it at its redirect, and one that is not sees no
// change.
func TestAClientCanBeHeldToState(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	authorize := func(state string) *httptest.ResponseRecorder {
		t.Helper()
		q := url.Values{"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"}, "response_type": {"code"},
			"scope": {"openid"}, "code_challenge": {oauth.Challenge("verifier-state-test-0123456789abcdefghijklmn")},
			"code_challenge_method": {"S256"}}
		if state != "" {
			q.Set("state", state)
		}
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
		return rec
	}
	if loc := authorize("").Header().Get("Location"); strings.Contains(loc, "this+client+must+send+state") {
		t.Fatalf("a client not held to it was refused: %s", loc)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET require_state = true WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	loc := authorize("").Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.test/cb") || !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("a client held to it was answered %q", loc)
	}
	if loc := authorize("abc").Header().Get("Location"); strings.Contains(loc, "error=invalid_request") {
		t.Errorf("a request with state was answered %q", loc)
	}
}

// A challenge is meant to be new each time. Sending one again is flagged and not
// refused, and two clients sending the same one have not repeated anything.
func TestARepeatedChallengeIsFlagged(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	note := func(clientID, challenge string) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := f.srv.noteChallengeReuse(ctx, tx, f.orgID, clientID, f.userID, challenge); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	flagged := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE org_id = $1::uuid
			AND event_type = 'oauth.pkce_challenge_reused'`, f.orgID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	fresh, err := newSID()
	if err != nil {
		t.Fatal(err)
	}
	challenge := "challenge-" + fresh
	note(f.clientID, challenge)
	note("another-client", challenge)
	note(f.clientID, "")
	note(f.clientID, "")
	if n := flagged(); n != 0 {
		t.Fatalf("%d flagged before anything repeated", n)
	}
	note(f.clientID, challenge)
	if n := flagged(); n != 1 {
		t.Errorf("%d flagged, want one", n)
	}
	var detail string
	if err := f.pool.QueryRow(ctx, `SELECT detail::text FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type = 'oauth.pkce_challenge_reused'`, f.orgID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, challenge) {
		t.Errorf("the record holds the challenge: %s", detail)
	}
}
