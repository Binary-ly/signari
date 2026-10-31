package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// mintFor is a person's token audienced to a resource, as a program holds one.
func (pa *proxyAuthz) mintFor(t *testing.T, resource, sid string, thumbprint string) string {
	t.Helper()
	ctx := context.Background()
	f := pa.f
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.resource_servers (org_id, resource, name)
		VALUES ($1::uuid, $2, 'proxied') ON CONFLICT DO NOTHING`, f.orgID, resource); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	mint := ctx
	if thumbprint != "" {
		mint = withDPoPThumbprint(ctx, thumbprint)
	}
	resp, _, err := f.srv.mintSet(mint, tx, c, f.orgID, f.userID, sid, "", []string{"read"}, []string{resource}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

func (pa *proxyAuthz) verifyBearer(t *testing.T, token, host string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", "/report")
	rec := httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// A program with a token for the host is let through as who the token speaks for.
func TestAnAccessTokenPassesForwardAuth(t *testing.T) {
	pa := newProxyAuthz(t)
	token := pa.mintFor(t, "https://"+pa.own, pa.sid, "")
	rec := pa.verifyBearer(t, token, pa.own)
	if rec.Code != http.StatusOK {
		t.Fatalf("a token for the host answered %d: %s", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}
	if rec.Header().Get("X-Forwarded-User") != pa.f.userID || rec.Header().Get("X-Forwarded-Email") != pa.f.email {
		t.Errorf("it passed as %q, %q", rec.Header().Get("X-Forwarded-User"), rec.Header().Get("X-Forwarded-Email"))
	}
}

// Each thing that ends a token ends it here, on the next request.
func TestARevokedAccessTokenFailsForwardAuth(t *testing.T) {
	pa := newProxyAuthz(t)
	ctx := context.Background()
	token := pa.mintFor(t, "https://"+pa.own, pa.sid, "")
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusOK {
		t.Fatalf("before anything ended it, it answered %d", rec.Code)
	}
	claims, err := tokens.VerifyAccessTokenAny(pa.f.srv.cfg.Keys, []string{pa.f.srv.cfg.Issuer}, token)
	if err != nil {
		t.Fatal(err)
	}
	inTx := func(change func(pgx.Tx) error) {
		t.Helper()
		tx, err := pa.f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := change(tx); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	inTx(func(tx pgx.Tx) error {
		return store.RevokeJTI(ctx, tx, claims.JTI, pa.f.clientID, time.Unix(claims.Expiry, 0))
	})
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token answered %d", rec.Code)
	}

	token = pa.mintFor(t, "https://"+pa.own, pa.sid, "")
	inTx(func(tx pgx.Tx) error {
		_, err := store.TerminateSessions(ctx, tx, pa.sid, "", store.ReasonLogout)
		return err
	})
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token whose session ended answered %d", rec.Code)
	}
}

// Audienced to the host means that host. A token for another is refused however
// valid, and so is one for this client, or the issuer, which every token here is.
func TestAForwardAuthTokenMustNameTheHost(t *testing.T) {
	pa := newProxyAuthz(t)
	other := pa.mintFor(t, "https://elsewhere.example.test", pa.sid, "")
	if rec := pa.verifyBearer(t, other, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token for another host answered %d", rec.Code)
	}
	ctx := context.Background()
	tx, err := pa.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := pa.f.srv.lookupClient(ctx, pa.f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := pa.f.srv.mintSet(ctx, tx, c, pa.f.orgID, pa.f.userID, pa.sid, "", []string{"read"}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := pa.verifyBearer(t, resp.AccessToken, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token for the client answered %d", rec.Code)
	}
	if rec := pa.verifyBearer(t, "not-a-token", pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("rubbish answered %d", rec.Code)
	}
}

// A sender-constrained token's proof is for the application's address, which only
// the application could check, so passing it here would take possession on trust.
func TestABoundTokenCannotBePresentedThroughTheProxy(t *testing.T) {
	pa := newProxyAuthz(t)
	token := pa.mintFor(t, "https://"+pa.own, pa.sid, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("a bound token answered %d", rec.Code)
	}
}

// A token gets no further than a cookie would: the host has to be one of its
// organisation's, enabled, and the access policy still has its say.
func TestATokenIsAuthorizedAsACookieIs(t *testing.T) {
	pa := newProxyAuthz(t)
	for name, host := range map[string]string{"another organisation's": pa.foreign, "a disabled": pa.disabled} {
		token := pa.mintFor(t, "https://"+host, pa.sid, "")
		if rec := pa.verifyBearer(t, token, host); rec.Code != http.StatusForbidden {
			t.Errorf("%s host answered %d", name, rec.Code)
		}
	}
}

// A service has no person behind it. It passes as itself, and a client turned off
// stops passing on the next request.
func TestAServiceTokenPassesForwardAuthAsItself(t *testing.T) {
	pa := newProxyAuthz(t)
	f := pa.f
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	service := f.clientID + "-svc"
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash, grant_types, scopes) VALUES ($1, $2::uuid, 'Service', 'confidential', $3,
		ARRAY['client_credentials'], ARRAY['read'])`, service, f.orgID, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, service)
	})
	resource := "https://" + pa.own
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.resource_servers (org_id, resource, name)
		VALUES ($1::uuid, $2, 'proxied') ON CONFLICT DO NOTHING`, f.orgID, resource); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}, "resource": {resource}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(service), url.QueryEscape(secret))
	got := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(got, req)
	var body map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil || got.Code != http.StatusOK {
		t.Fatalf("the token request answered %d: %s", got.Code, got.Body.String())
	}
	token, _ := body["access_token"].(string)

	rec := pa.verifyBearer(t, token, pa.own)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Forwarded-User") != service ||
		rec.Header().Get("X-Forwarded-Email") != "" {
		t.Fatalf("a service answered %d as %q (%q)", rec.Code, rec.Header().Get("X-Forwarded-User"),
			rec.Header().Get("X-Signari-Reason"))
	}

	// A policy meets it as what it is, a client with no groups: a rule about
	// something else lets it by, and one about this host stops it by name, not
	// with the error a failed lookup of a person's groups would give.
	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient("somewhere-else"))
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusOK {
		t.Errorf("under a rule about something else it answered %d (%q)", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}
	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient("proxy:"+pa.own))
	rec = pa.verifyBearer(t, token, pa.own)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Signari-Reason") != "This application is closed to you." {
		t.Errorf("under a rule about this host it answered %d (%q)", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}
	removePolicy(t, f.srv, f.pool, f.orgID)

	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET enabled = false WHERE client_id = $1`, service); err != nil {
		t.Fatal(err)
	}
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("a disabled service answered %d", rec.Code)
	}
}

// A person deactivated is refused at once, on a token that has no session to end
// with them.
func TestADeactivatedPersonsTokenFailsForwardAuth(t *testing.T) {
	pa := newProxyAuthz(t)
	token := pa.mintFor(t, "https://"+pa.own, "", "")
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusOK {
		t.Fatalf("before the deactivation it answered %d (%q)", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}
	if _, err := pa.f.pool.Exec(context.Background(), `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`,
		pa.f.userID); err != nil {
		t.Fatal(err)
	}
	if rec := pa.verifyBearer(t, token, pa.own); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the deactivation it answered %d", rec.Code)
	}
}

// A browser's cookie says more than whatever Authorization the application behind
// the proxy may be using, so it decides when both are there.
func TestACookieDecidesWhenBothArrive(t *testing.T) {
	pa := newProxyAuthz(t)
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.AddCookie(&http.Cookie{Name: ProxyCookieName, Value: pa.token(t, pa.f.orgID)})
	r.Header.Set("Authorization", "Bearer the-applications-own-token")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", pa.own)
	r.Header.Set("X-Forwarded-Uri", "/")
	rec := httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("a good cookie beside an application's token answered %d", rec.Code)
	}
}
