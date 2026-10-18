package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"signari.dev/engine/internal/tokens"
)

// Forward auth checked that a proxy cookie was valid and its session live, and
// nothing else: any signed-in person of any organisation passed every protected
// host in the deployment.

type proxyAuthz struct {
	f                      *signInFixture
	sid                    string
	own, foreign, disabled string
}

func newProxyAuthz(t *testing.T) *proxyAuthz {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	f.signInAndReturnCookie(t)
	pa := &proxyAuthz{f: f}
	if err := f.pool.QueryRow(ctx, `
		SELECT sid FROM core.sessions WHERE user_id = $1::uuid ORDER BY created_at DESC LIMIT 1`,
		f.userID).Scan(&pa.sid); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UnixNano()
	pa.own = fmt.Sprintf("own-%d.example.com", n)
	pa.foreign = fmt.Sprintf("foreign-%d.example.com", n)
	pa.disabled = fmt.Sprintf("off-%d.example.com", n)

	var otherOrg string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'px-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	for _, h := range []struct {
		org, host string
		enabled   bool
	}{{f.orgID, pa.own, true}, {otherOrg, pa.foreign, true}, {f.orgID, pa.disabled, false}} {
		if _, err := f.pool.Exec(ctx,
			`INSERT INTO core.proxy_hosts (org_id, host, enabled) VALUES ($1::uuid, $2, $3)`,
			h.org, h.host, h.enabled); err != nil {
			t.Fatal(err)
		}
	}
	return pa
}

func (pa *proxyAuthz) token(t *testing.T, orgID string) string {
	t.Helper()
	key, err := pa.f.srv.anySigningKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.NewSigner(key).SignJSON(proxyClaims{
		Issuer: pa.f.srv.cfg.Issuer, Subject: pa.f.userID, SID: pa.sid, OrgID: orgID,
		Expiry: time.Now().Add(10 * time.Minute).Unix(),
	}, typProxy)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (pa *proxyAuthz) verify(t *testing.T, token, host, remote string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.AddCookie(&http.Cookie{Name: ProxyCookieName, Value: token})
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", "/")
	if remote != "" {
		r.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	pa.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func TestForwardAuthAdmitsOnlyItsOwnOrganisationsHosts(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)

	rec := pa.verify(t, tok, pa.own, "")
	if rec.Code != http.StatusOK || rec.Header().Get("X-Forwarded-User") != pa.f.userID {
		t.Fatalf("the organisation's own host answered %d (user %q), want 200 with the identity",
			rec.Code, rec.Header().Get("X-Forwarded-User"))
	}
	for name, host := range map[string]string{
		"another organisation's host": pa.foreign,
		"a host nobody registered":    "nobody-" + pa.own,
		"a disabled host":             pa.disabled,
	} {
		rec := pa.verify(t, tok, host, "")
		if rec.Code != http.StatusForbidden || rec.Header().Get("X-Forwarded-User") != "" {
			t.Errorf("%s answered %d (identity %q), want 403 and no identity",
				name, rec.Code, rec.Header().Get("X-Forwarded-User"))
		}
	}
	if rec := pa.verify(t, tok, "", ""); rec.Code != http.StatusForbidden {
		t.Errorf("a request naming no host answered %d, want 403", rec.Code)
	}

	// A token from before the organisation was carried is asked to sign in
	// again, not honoured.
	if rec := pa.verify(t, pa.token(t, ""), pa.own, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token naming no organisation answered %d, want 401", rec.Code)
	}
}

func TestTheAccessPolicyDecidesWhoReachesAProtectedHost(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	applyPolicy(t, pa.f.srv, pa.f.pool, pa.f.orgID, denyClient("proxy:"+pa.own))

	rec := pa.verify(t, tok, pa.own, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a deny rule for proxy:%s answered %d, want 403", pa.own, rec.Code)
	}
	if got := rec.Header().Get("X-Signari-Reason"); got != "This application is closed to you." {
		t.Errorf("the refusal's reason is %q, want the policy's message", got)
	}
}

// A proxy that copies an identity header from the auth response only when the
// response carries one leaves the client's own copy on the forwarded request
// otherwise. So for somebody with no address on record the response must still
// carry X-Forwarded-Email -- empty -- on the wire, or the client chooses it.
func TestEveryIdentityHeaderIsSentEvenWhenEmpty(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID) // proxyClaims with no Email

	ts := httptest.NewServer(pa.f.srv.Routes())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/proxy/verify", nil)
	req.AddCookie(&http.Cookie{Name: ProxyCookieName, Value: tok})
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", pa.own)
	req.Header.Set("X-Forwarded-Email", "ceo@victim.test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify answered %d", resp.StatusCode)
	}
	for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Sub", "X-Forwarded-Email"} {
		if _, present := resp.Header[h]; !present {
			t.Errorf("%s is absent from the response, so a copy-if-present proxy keeps the "+
				"client's own value", h)
		}
	}
	if got := resp.Header.Get("X-Forwarded-Email"); got != "" {
		t.Errorf("X-Forwarded-Email is %q for a token with no address", got)
	}
}

// The request at verify is the proxy's. Its address is the proxy's own, and a
// network rule read against it would admit everybody from inside the office the
// proxy sits in.
func TestTheProxysOwnAddressDoesNotSatisfyANetworkRule(t *testing.T) {
	pa := newProxyAuthz(t)
	tok := pa.token(t, pa.f.orgID)
	client := "proxy:" + pa.own
	applyPolicy(t, pa.f.srv, pa.f.pool, pa.f.orgID, fmt.Sprintf(`
version: 1
policies:
  - name: office-only
    when: {client: %q}
    require: {from_networks: ["10.0.0.0/8"]}
tests:
  - name: inside
    given: {client: %q, ip: "10.1.2.3"}
    expect: allow
`, client, client))

	if rec := pa.verify(t, tok, pa.own, "10.0.0.5:44321"); rec.Code != http.StatusForbidden {
		t.Fatalf("a proxy inside 10.0.0.0/8 satisfied an office-only rule for everybody (status %d)", rec.Code)
	}
}
