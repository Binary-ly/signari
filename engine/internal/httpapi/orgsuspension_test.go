package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/store"
)

// A suspended organisation is refused at every entry point (6.09): a sign-in,
// a session it already has, the authorization endpoint, every token grant,
// userinfo and introspection, a directory bind, SCIM and the outposts. And it
// resumes when reactivated, since suspension refuses and ends nothing.

func setOrgStatus(t *testing.T, pool *pgxpool.Pool, orgID, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE core.organizations SET status = $2 WHERE id = $1::uuid`, orgID, status); err != nil {
		t.Fatal(err)
	}
}

func suspendOrgForTest(t *testing.T, pool *pgxpool.Pool, orgID string) {
	t.Helper()
	setOrgStatus(t, pool, orgID, "suspended")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`UPDATE core.organizations SET status = 'active' WHERE id = $1::uuid`, orgID)
	})
}

func (f *signInFixture) accountPage(t *testing.T, cookie string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code
}

func TestASuspendedOrganisationSignsNobodyIn(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()

	signedIn := cookieFrom(f.signInWith(t, ""), SessionCookieName)
	if signedIn == nil {
		t.Fatal("the fixture could not sign in before the suspension")
	}
	if code := f.accountPage(t, signedIn.Value); code != http.StatusOK {
		t.Fatalf("the account page before the suspension answered %d", code)
	}

	suspendOrgForTest(t, f.pool, f.orgID)

	if c := cookieFrom(f.signInWith(t, ""), SessionCookieName); c != nil {
		t.Error("a correct password signed somebody in to a suspended organisation")
	}
	var reason string
	if err := f.pool.QueryRow(ctx, `SELECT detail->>'reason' FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type = 'login.failed' ORDER BY occurred_at DESC LIMIT 1`,
		f.orgID).Scan(&reason); err != nil {
		t.Errorf("reading the refused sign-in's record: %v", err)
	} else if reason != "account_org_suspended" {
		t.Errorf("the refused sign-in was recorded as %q", reason)
	}
	if code := f.accountPage(t, signedIn.Value); code == http.StatusOK {
		t.Error("a session signed in before the suspension still opened the account page")
	}
	if rec := f.authorizePlain(t, signedIn.Value); rec.Code < 400 ||
		!strings.Contains(rec.Body.String(), "suspended") {
		t.Errorf("/authorize for a suspended organisation's client answered %d %s",
			rec.Code, truncate(rec.Body.String(), 160))
	}
	if _, err := f.binder().Authenticate(ctx, f.email, signInTestPassword); err == nil {
		t.Error("an LDAP bind succeeded in a suspended organisation")
	}

	// Nobody joins it, even by an invitation it sent, which is kept for later.
	joiner := "joiner-" + f.orgID[:8] + "@example.test"
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE org_id = $1::uuid AND email = $2`,
			f.orgID, joiner)
	})
	invite, err := store.CreateInvitation(ctx, f.pool, f.orgID, joiner, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	b := newTestBrowser(t, f.srv.Routes())
	rec := b.post("/signup", b.get("/signup?invite="+url.QueryEscape(invite)),
		url.Values{"email": {joiner}, "password": {"a-joiners-long-password-609"}, "invite": {invite}})
	var joined int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE email = $1`, joiner).Scan(&joined)
	if joined != 0 || !strings.Contains(rec.Body.String(), "cannot be created here") {
		t.Errorf("a sign-up into a suspended organisation: %d accounts, %d %s", joined, rec.Code,
			truncate(rec.Body.String(), 160))
	}
	if _, err := store.PeekInvitation(ctx, f.pool, invite); err != nil {
		t.Errorf("the refused sign-up spent its invitation: %v", err)
	}

	// Nor is a reset begun for its people.
	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	var resets int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM core.recovery_requests WHERE user_id = $1::uuid`,
		f.userID).Scan(&resets)
	if resets != 0 {
		t.Errorf("a reset was begun for a suspended organisation's account")
	}

	// Reactivated, the session it had resumes: suspension ends nothing.
	setOrgStatus(t, f.pool, f.orgID, "active")
	if code := f.accountPage(t, signedIn.Value); code != http.StatusOK {
		t.Errorf("after reactivation the session's account page answered %d", code)
	}
	if _, err := f.binder().Authenticate(ctx, f.email, signInTestPassword); err != nil {
		t.Errorf("after reactivation the bind was refused: %v", err)
	}
}

func TestASuspendedOrganisationsTokensAndCallersAreRefused(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET client_type = 'confidential',
		client_secret_hash = $2,
		grant_types = ARRAY['authorization_code','refresh_token','client_credentials']
		WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	refresh := f.firstRefreshTokenWithSecret(t, secret)
	verifier := strings.Repeat("e", 48)
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {f.issueCodeWithScopes(t, verifier, []string{"openid"})},
		"redirect_uri": {"https://rp.test/cb"}, "client_id": {f.clientID},
		"client_secret": {secret}, "code_verifier": {verifier},
	})
	access, _ := body["access_token"].(string)
	if status != http.StatusOK || access == "" {
		t.Fatalf("fixture access token: %d %v", status, body)
	}
	if code := f.userinfo(t, access); code != http.StatusOK {
		t.Fatalf("userinfo before the suspension answered %d", code)
	}

	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	scimToken := "scim-suspended-" + hex.EncodeToString(raw)
	scimSum := sha256.Sum256([]byte(scimToken))
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.scim_sources (org_id, slug, display_name, token_hash)
		VALUES ($1::uuid, $2, 'Suspension test', $3)`, f.orgID, "susp-"+hex.EncodeToString(raw[:4]), scimSum[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.scim_sources WHERE token_hash = $1`, scimSum[:])
	})
	pdp := newPDPCaller(t, f)
	scim := func() int {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer "+scimToken)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	const evaluation = `{"subject":{"type":"user","id":"alice"},"resource":{"type":"document","id":"1"},"action":{"name":"read"}}`
	if code := scim(); code != http.StatusOK {
		t.Fatalf("SCIM before the suspension answered %d", code)
	}
	if code, _ := postAuthz(t, f, pdp, "/access/v1/evaluation", evaluation); code != http.StatusOK {
		t.Fatalf("an evaluation before the suspension answered %d", code)
	}

	suspendOrgForTest(t, f.pool, f.orgID)

	authed := func(form url.Values) url.Values {
		form.Set("client_id", f.clientID)
		form.Set("client_secret", secret)
		return form
	}
	for name, form := range map[string]url.Values{
		"client_credentials": {"grant_type": {"client_credentials"}},
		"refresh_token":      {"grant_type": {"refresh_token"}, "refresh_token": {refresh}},
	} {
		if code, b := f.post(t, authed(form)); code < 400 {
			t.Errorf("%s in a suspended organisation answered %d %v", name, code, b)
		}
	}
	if code := f.userinfo(t, access); code == http.StatusOK {
		t.Error("userinfo answered a suspended organisation's access token")
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
		strings.NewReader(authed(url.Values{"token": {access}}).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Errorf("introspection by a suspended organisation's client answered %d %s", rec.Code, rec.Body.String())
	}
	if code := scim(); code != http.StatusUnauthorized {
		t.Errorf("SCIM provisioning into a suspended organisation answered %d", code)
	}
	if code, _ := postAuthz(t, f, pdp, "/access/v1/evaluation", evaluation); code != http.StatusUnauthorized {
		t.Errorf("a suspended organisation's outpost was answered: %d", code)
	}
}
