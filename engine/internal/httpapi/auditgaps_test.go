package httpapi

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

// A sign-out, a revocation and a refresh-token reuse each leave an audit
// record, and so reach event subscribers (2.52). Their types were declared and
// written by nothing: the reuse, the theft signal that revokes a whole family,
// was in the log and nowhere else.

// countAudit counts audit rows of a type for the fixture's person and client,
// with a detail value when one is named.
func countAudit(t *testing.T, f *tokenFixture, eventType, detailKey, detailValue string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.audit_events
		WHERE event_type = $1 AND subject_id = $2::uuid AND client_id = $3
		  AND ($4 = '' OR detail->>$4 = $5)`,
		eventType, f.userID, f.clientID, detailKey, detailValue).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestARevocationIsRecorded(t *testing.T) {
	f := newTokenFixture(t)
	secret := revocableClient(t, f)
	verifier := "verifier-revoke-audit-aaaaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "offline_access"})
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "client_secret": {secret},
		"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	revoke := func(token string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, oidc.PathRevocation, strings.NewReader(url.Values{
			"token": {token}, "client_id": {f.clientID}, "client_secret": {secret}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("revoke gave %d", rec.Code)
		}
	}
	revoke(body["refresh_token"].(string))
	if n := countAudit(t, f, "oauth.token_revoked", "token_type", "refresh_token"); n != 1 {
		t.Errorf("revoking a refresh token left %d oauth.token_revoked records for its holder, want 1", n)
	}
	revoke(body["access_token"].(string))
	if n := countAudit(t, f, "oauth.token_revoked", "token_type", "access_token"); n != 1 {
		t.Errorf("revoking an access token left %d records, want 1", n)
	}
	// An unknown token is a 200 that revoked nothing, and is not recorded as a revocation.
	revoke("not-a-token-this-server-issued")
	if n := countAudit(t, f, "oauth.token_revoked", "", ""); n != 2 {
		t.Errorf("after an unknown token there are %d revocation records, want still 2", n)
	}
}

func TestARefreshTokenReuseIsRecorded(t *testing.T) {
	f := newTokenFixture(t)
	verifier := "verifier-reuse-audit-aaaaaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "offline_access"})
	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	first := body["refresh_token"].(string)
	if status, body := f.refreshWith(t, first, ""); status != http.StatusOK {
		t.Fatalf("the first refresh gave %d: %v", status, body)
	}
	if status, _ := f.refreshWith(t, first, ""); status != http.StatusBadRequest {
		t.Fatalf("presenting a spent refresh token again gave %d, want 400", status)
	}
	if n := countAudit(t, f, "oauth.refresh_reused", "", ""); n != 1 {
		t.Errorf("a refresh token reuse left %d oauth.refresh_reused records for its holder, want 1", n)
	}
}

func TestASignOutIsRecorded(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	h := f.srv.Routes()
	session := f.signInAndReturnCookie(t)

	get := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+url.Values{"client_id": {f.clientID}}.Encode(), nil)
	get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	page := httptest.NewRecorder()
	h.ServeHTTP(page, get)
	a := regexp.MustCompile(`<form method="post" action="([^"]*)"`).FindStringSubmatch(page.Body.String())
	c := regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]*)"`).FindStringSubmatch(page.Body.String())
	if a == nil || c == nil {
		t.Fatalf("no confirmation form: %d", page.Code)
	}
	post := httptest.NewRequest(http.MethodPost, html.UnescapeString(a[1]),
		strings.NewReader(url.Values{csrfFormField: {c[1]}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	for _, ck := range page.Result().Cookies() {
		post.AddCookie(ck)
	}
	h.ServeHTTP(httptest.NewRecorder(), post)

	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
		WHERE event_type = 'session.logout' AND subject_id = $1::uuid
		  AND (detail->>'sessions_ended')::int = 1`, f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("signing out left %d session.logout records ending one session, want 1", n)
	}
}
