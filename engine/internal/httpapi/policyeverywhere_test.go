package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// The access policy was asked at the authorization endpoint, the portal,
// remote access and WS-Federation -- and nowhere else. SAML, the device grant,
// CIBA approval and every refresh went round it, so a deny rule for a client
// refused its browser sign-ins and approved its smart-TV ones, its SAML ones,
// and every refresh of a token it had already issued.

// applyPolicy installs an access policy for one organisation, as `signari policy
// apply` would. Nothing is reloaded: the server reads which document is in
// force on every decision, which is what these tests also show.
func applyPolicy(t *testing.T, srv *Server, pool *pgxpool.Pool, orgID, doc string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.access_policies (org_id, document) VALUES ($1::uuid, $2)
		ON CONFLICT (org_id) DO UPDATE SET document = EXCLUDED.document, applied_at = now()`,
		orgID, doc); err != nil {
		t.Fatalf("applying the policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.access_policies WHERE org_id = $1::uuid`, orgID)
	})
}

func removePolicy(t *testing.T, srv *Server, pool *pgxpool.Pool, orgID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM core.access_policies WHERE org_id = $1::uuid`, orgID); err != nil {
		t.Fatal(err)
	}
}

// denyClient is a policy refusing one client (or SAML entity ID) outright.
func denyClient(client string) string {
	return fmt.Sprintf(`
version: 1
policies:
  - name: not-this-one
    when: {client: %q}
    deny: true
    message: "This application is closed to you."
tests:
  - name: refused
    given: {client: %q}
    expect: deny
  - name: others are not
    given: {client: %q}
    expect: allow
`, client, client, "not-"+client)
}

// ---- SAML ------------------------------------------------------------------

var samlResponseField = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

func (rf *realmFixture) samlSSO(t *testing.T, entity string) (int, string) {
	t.Helper()
	req := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%d" Version="2.0"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/acs"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), entity)
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(req))}}
	r := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	m := samlResponseField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		return rec.Code, ""
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatalf("the SAMLResponse is not base64: %v", err)
	}
	return rec.Code, string(xml)
}

func TestADenyRuleOnAnEntityIDRefusesSAML(t *testing.T) {
	rf := newRealmFixture(t)

	// The control first: the service provider works, so the refusal below is
	// the policy and not a broken request.
	_, resp := rf.samlSSO(t, rf.own)
	if !strings.Contains(resp, "Assertion") || strings.Contains(resp, "RequestDenied") {
		t.Fatalf("with no policy the service provider got no assertion: %.300s", resp)
	}

	applyPolicy(t, rf.f.srv, rf.f.pool, rf.f.orgID, denyClient(rf.own))
	_, resp = rf.samlSSO(t, rf.own)
	if strings.Contains(resp, "<saml:Assertion") || strings.Contains(resp, ":Assertion ") {
		t.Fatal("a deny rule on the entity ID did not stop a SAML assertion being issued")
	}
	if !strings.Contains(resp, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied") {
		t.Fatalf("the refusal was not told to the service provider as RequestDenied: %.400s", resp)
	}

	// WS-Federation, through the same function, is refused by the same rule.
	if rec := rf.signIn(rf.own, true); rec.Code != http.StatusForbidden {
		t.Fatalf("WS-Federation for the denied realm answered %d, want 403", rec.Code)
	}
}

// ---- the device grant and CIBA ------------------------------------------------

func (f *signInFixture) formPost(t *testing.T, cookie, page, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rec := accountGET(f, cookie, page)
	m := csrfValue.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("%s carries no CSRF field", page)
	}
	var csrfCookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c.Value
		}
	}
	form.Set(csrfFormField, m[1])
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfCookie})
	r.RemoteAddr = testClientIP(t) + ":5555"
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, r)
	return out
}

func (f *signInFixture) requestStatus(t *testing.T, id string) string {
	t.Helper()
	var status string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT status FROM core.device_authorizations WHERE id = $1::uuid`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestADenyRuleRefusesADeviceApproval(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	ctx := context.Background()

	newRequest := func(userCode string) string {
		id, err := store.CreateDeviceAuthorization(ctx, f.pool, f.orgID, f.clientID, "openid", nil,
			store.HashToken("dc-"+userCode+fmt.Sprint(time.Now().UnixNano())), store.HashToken(userCode),
			5, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	approve := func(userCode string) *httptest.ResponseRecorder {
		return f.formPost(t, cookie, "/device", "/device",
			url.Values{"user_code": {userCode}, "decision": {"approve"}})
	}

	control, err := oauth.NewUserCode()
	if err != nil {
		t.Fatal(err)
	}
	id := newRequest(control)
	approve(control)
	if s := f.requestStatus(t, id); s != "approved" {
		t.Fatalf("with no policy the device approval left the request %q", s)
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	refused, err := oauth.NewUserCode()
	if err != nil {
		t.Fatal(err)
	}
	id = newRequest(refused)
	rec := approve(refused)
	if s := f.requestStatus(t, id); s != "denied" {
		t.Fatalf("a deny rule for the client left the approved device request %q, want denied "+
			"so the device is told access_denied", s)
	}
	if !strings.Contains(rec.Body.String(), "This application is closed to you.") {
		t.Error("the person approving was not shown the policy's message")
	}
}

func TestADenyRuleRefusesACIBAApproval(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	ctx := context.Background()

	newRequest := func() string {
		id, err := store.CreateBackchannelAuthentication(ctx, f.pool, f.orgID, f.clientID, f.userID,
			"openid", "", nil, store.HashToken(fmt.Sprint("ar-", time.Now().UnixNano())), 5,
			10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	approve := func(id string) *httptest.ResponseRecorder {
		return f.formPost(t, cookie, "/account/requests", "/account/requests",
			url.Values{"id": {id}, "decision": {"approve"}})
	}

	id := newRequest()
	approve(id)
	if s := f.requestStatus(t, id); s != "approved" {
		t.Fatalf("with no policy the CIBA approval left the request %q", s)
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	id = newRequest()
	rec := approve(id)
	if s := f.requestStatus(t, id); s != "denied" {
		t.Fatalf("a deny rule for the client left the approved CIBA request %q, want denied", s)
	}
	if !strings.Contains(rec.Body.String(), "This application is closed to you.") {
		t.Error("the person approving was not shown the policy's message")
	}
}

// A failed read before a CIBA decision refuses the decision. It left the
// request unloaded, the policy check is skipped for an unloaded request, and
// the approval went through -- past a deny rule -- having asked nobody.
func TestAFailedReadBeforeACIBADecisionApprovesNothing(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	ctx := context.Background()
	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))

	id, err := store.CreateBackchannelAuthentication(ctx, f.pool, f.orgID, f.clientID, f.userID,
		"openid", "", nil, store.HashToken(fmt.Sprint("ar-", time.Now().UnixNano())), 5, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.pendingBackchannel = func(context.Context, *pgxpool.Pool, string, string) (*store.DeviceAuthorization, error) {
		return nil, errors.New("injected: the read failed")
	}
	rec := f.formPost(t, cookie, "/account/requests", "/account/requests",
		url.Values{"id": {id}, "decision": {"approve"}})
	if s := f.requestStatus(t, id); s == "approved" {
		t.Fatalf("a failed read let the approval through past a deny rule (%d)", rec.Code)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("a failed read answered %d, want 503", rec.Code)
	}
}

// ---- refresh -------------------------------------------------------------------

func TestTheAccessPolicyIsAskedAgainAtEveryRefresh(t *testing.T) {
	f := newTokenFixture(t)
	const verifier = "verifier-for-the-refresh-policy-journey-0123456789-abc"
	status, body := f.post(t, f.redeem(f.issueCode(t, verifier), verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", body)
	}
	refreshWith := func(token string) (int, map[string]any) {
		return f.post(t, url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {token}, "client_id": {f.clientID}})
	}

	// A network condition is about the browser at sign-in. The refresh comes
	// from the application's server, and must not be refused for its address.
	applyPolicy(t, f.srv, f.pool, f.orgID, fmt.Sprintf(`
version: 1
policies:
  - name: office-only
    when: {client: %q}
    require: {from_networks: ["10.0.0.0/8"]}
tests:
  - name: outside
    given: {client: %q, ip: "192.0.2.1"}
    expect: deny
`, f.clientID, f.clientID))
	status, body = refreshWith(refresh)
	if status != http.StatusOK {
		t.Fatalf("a network rule refused a refresh from the application's server: %d %v", status, body)
	}
	refresh, _ = body["refresh_token"].(string)

	// A deny rule written after the grant was issued applies to its next refresh.
	applyPolicy(t, f.srv, f.pool, f.orgID, denyClient(f.clientID))
	status, body = refreshWith(refresh)
	if status == http.StatusOK || body["error"] != "invalid_grant" {
		t.Fatalf("a refresh under a deny rule for the client answered %d (error %v), want invalid_grant",
			status, body["error"])
	}

	// Not revoked: lifting the rule restores the same token.
	removePolicy(t, f.srv, f.pool, f.orgID)
	if status, body = refreshWith(refresh); status != http.StatusOK {
		t.Fatalf("after the rule was lifted the refresh token still failed: %d %v", status, body)
	}
}
