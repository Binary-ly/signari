package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/store"
)

// A fake of the operator's own service: what it was asked, and what it says.
type hookService struct {
	mu     sync.Mutex
	asked  []map[string]any
	answer string // the JSON it answers; "" is no answer at all
}

func (h *hookService) says(answer string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answer = answer
}

func (h *hookService) lastAsked() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.asked) == 0 {
		return nil
	}
	return h.asked[len(h.asked)-1]
}

func (h *hookService) times() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.asked)
}

func (h *hookService) roundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	asked := map[string]any{}
	_ = json.Unmarshal(raw, &asked)
	h.mu.Lock()
	h.asked = append(h.asked, asked)
	answer := h.answer
	h.mu.Unlock()
	if answer == "" {
		return nil, fmt.Errorf("the service is down")
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(answer))}, nil
}

// registerHook registers a fail-closed provider for a hook and points the server at the
// fake, allowed to contribute claims.
func registerHook(t *testing.T, srv *Server, pool *pgxpool.Pool, orgID string, hook provider.Hook, claims ...string) *hookService {
	t.Helper()
	if claims == nil {
		claims = []string{}
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO core.providers (org_id, name, hook, url, mode, timeout_ms, allowed_claims)
		VALUES ($1::uuid, 'operator', $2, 'https://operator.test/hook', 'fail_closed', 2000, $3)`,
		orgID, string(hook), claims); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.providers WHERE org_id = $1::uuid AND hook = $2`, orgID, string(hook))
	})
	service := &hookService{answer: `{"decision":true}`}
	srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(service.roundTrip)}
	}
	return service
}

// lastRefusal is the newest provider.refused record about a subject's organisation.
func lastRefusal(t *testing.T, pool *pgxpool.Pool, orgID string) (hook, reason string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(detail->>'hook', ''), COALESCE(detail->>'reason', '') FROM core.audit_events
		 WHERE event_type = 'provider.refused' AND org_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`,
		orgID).Scan(&hook, &reason); err != nil {
		t.Fatalf("no provider.refused record: %v", err)
	}
	return hook, reason
}

// The authenticate hook, where every way in arrives: told who and how, and able to stop
// the session being made, by saying no or, for a service registered fail_closed, by
// not being there. A person refused is not told why.
func TestTheAuthenticateHookCanRefuseASignIn(t *testing.T) {
	f := newSignInFixture(t)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookAuthenticate)

	if f.signInAndReturnCookie(t) == "" {
		t.Fatal("a service saying yes refused the sign-in")
	}
	asked := service.lastAsked()
	if asked["subject"] != f.userID || asked["org_id"] != f.orgID || fmt.Sprint(asked["amr"]) != "[pwd]" {
		t.Errorf("the service was told %v", asked)
	}

	gotSession := func(rec *httptest.ResponseRecorder) bool {
		for _, c := range rec.Result().Cookies() {
			if c.Name == SessionCookieName && c.Value != "" {
				return true
			}
		}
		return false
	}
	service.says(`{"decision":false,"reason":"this account is under review by the fraud team"}`)
	rec := f.postLogin(t, nil)
	if gotSession(rec) {
		t.Fatal("a refused sign-in got a session")
	}
	if strings.Contains(rec.Body.String(), "fraud") {
		t.Error("the provider's reason reached the person")
	}
	if hook, reason := lastRefusal(t, f.pool, f.orgID); hook != "authenticate" || !strings.Contains(reason, "fraud") {
		t.Errorf("recorded %q, %q", hook, reason)
	}

	service.says("")
	if gotSession(f.postLogin(t, nil)) {
		t.Error("a fail_closed service that was down let a sign-in through")
	}
}

// The user_create hook, for somebody signing themselves up and for somebody arriving from
// an identity provider, and neither account exists after a no.
func TestTheUserCreateHookCanRefuseAnAccount(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookUserCreate)

	n := time.Now().UnixNano()
	yes, no := fmt.Sprintf("yes-%d@example.test", n), fmt.Sprintf("no-%d@example.test", n)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE email = ANY($1)`, []string{yes, no})
	})
	password := "a-perfectly-fine-password-42"
	postSignup(t, f, url.Values{"email": {yes}, "password": {password}})
	if !accountExists(t, f, yes) {
		t.Fatal("a service saying yes refused the account")
	}
	if asked := service.lastAsked(); asked["email"] != yes || asked["source"] != "signup" || asked["org_id"] != f.orgID {
		t.Errorf("the service was told %v", asked)
	}
	service.says(`{"decision":false,"reason":"disposable address"}`)
	rec := postSignup(t, f, url.Values{"email": {no}, "password": {password}})
	if accountExists(t, f, no) {
		t.Error("a refused sign-up made an account")
	}
	if strings.Contains(rec.Body.String(), "disposable") {
		t.Error("the provider's reason reached the person")
	}
	if hook, reason := lastRefusal(t, f.pool, f.orgID); hook != "user_create" || reason != "disposable address" {
		t.Errorf("recorded %q, %q", hook, reason)
	}
}

func TestTheUserCreateHookCoversAFederatedArrival(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookUserCreate)
	var providerID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, allow_linking, allow_signup)
		VALUES ($1::uuid, 'hook-' || substr(gen_random_uuid()::text, 1, 8), 'Upstream', 'oidc', 'signari', true, true)
		RETURNING id::text`, f.orgID).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	n := time.Now().UnixNano()
	yes, no := fmt.Sprintf("arrive-yes-%d@example.test", n), fmt.Sprintf("arrive-no-%d@example.test", n)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
		_, _ = f.pool.Exec(ctx, `DELETE FROM core.users WHERE email = ANY($1)`, []string{yes, no})
	})
	arrive := func(subject, email string) *httptest.ResponseRecorder {
		t.Helper()
		cfg := federation.Config{ID: providerID, OrgID: f.orgID, Slug: "upstream", Kind: federation.KindOIDC,
			Policy: federation.Policy{AllowSignup: true, AllowLinking: true, TrustsEmailVerification: true}}
		rec := httptest.NewRecorder()
		f.srv.completeFederation(rec, httptest.NewRequest(http.MethodGet, "/login/callback", nil), &cfg,
			&store.PendingLogin{ProviderID: providerID, OrgID: f.orgID},
			federation.ExternalIdentity{Subject: subject, Email: email, EmailVerified: true})
		return rec
	}
	exists := func(email string) bool {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE email = $1`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	if rec := arrive("yes", yes); !strings.Contains(rec.Body.String(), "signed in") || !exists(yes) {
		t.Fatalf("a service saying yes: %d %.200s", rec.Code, rec.Body)
	}
	if asked := service.lastAsked(); asked["source"] != "federation" || asked["email"] != yes {
		t.Errorf("the service was told %v", asked)
	}
	service.says(`{"decision":false,"reason":"contractors only by invitation"}`)
	if rec := arrive("no", no); strings.Contains(rec.Body.String(), "signed in") || exists(no) {
		t.Errorf("a refused arrival: %d %.200s", rec.Code, rec.Body)
	}
	if hook, _ := lastRefusal(t, f.pool, f.orgID); hook != "user_create" {
		t.Errorf("recorded %q", hook)
	}
	// Somebody who has an account is not being created, and is not asked about.
	before := service.times()
	if rec := arrive("yes", yes); !strings.Contains(rec.Body.String(), "signed in") {
		t.Errorf("signing in again was refused: %d", rec.Code)
	}
	if service.times() != before {
		t.Error("the service was asked about somebody who already has an account")
	}
}

// The client_access hook, in AuthZEN's shape, at each way a person reaches an application.
func TestTheClientAccessHookCanRefuseAnApplication(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	cookie := f.signInAndReturnCookie(t)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookClientAccess)

	if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"prompt": {"none"}})); q.Get("code") == "" {
		t.Fatalf("a service saying yes got %v", q)
	}
	asked := service.lastAsked()
	subject, _ := asked["subject"].(map[string]any)
	resource, _ := asked["resource"].(map[string]any)
	action, _ := asked["action"].(map[string]any)
	if subject["type"] != "user" || subject["id"] != f.userID || resource["type"] != "client" ||
		resource["id"] != f.clientID || action["name"] != "access" {
		t.Errorf("the service was told %v", asked)
	}

	service.says(`{"decision":false,"reason":"out of hours"}`)
	rec := f.authorizeWith(t, cookie, url.Values{})
	if strings.Contains(rec.Header().Get("Location"), "code=") || !strings.Contains(rec.Body.String(), clientAccessRefusal) ||
		strings.Contains(rec.Body.String(), "out of hours") {
		t.Errorf("at the authorization endpoint: %d %q %.200s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}

	// A device approval, told to the waiting device as a denial.
	userCode, err := oauth.NewUserCode()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.CreateDeviceAuthorization(ctx, f.pool, f.orgID, f.clientID, "openid", nil,
		store.HashToken("dc-"+userCode), store.HashToken(userCode), 5, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.formPost(t, cookie, "/device", "/device", url.Values{"user_code": {userCode}, "decision": {"approve"}})
	if s := f.requestStatus(t, device); s != "denied" {
		t.Errorf("a device approval left the request %q", s)
	}

	// And a CIBA approval.
	ciba, err := store.CreateBackchannelAuthentication(ctx, f.pool, f.orgID, f.clientID, f.userID, "openid", "", nil,
		store.HashToken(fmt.Sprint("ar-", time.Now().UnixNano())), 5, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.formPost(t, cookie, "/account/requests", "/account/requests", url.Values{"id": {ciba}, "decision": {"approve"}})
	if s := f.requestStatus(t, ciba); s != "denied" {
		t.Errorf("a CIBA approval left the request %q", s)
	}
}

// The userinfo hook adds what the operator's list lets it, never what is already there,
// and can refuse the answer.
func TestTheUserinfoHookAddsWhatItsListLets(t *testing.T) {
	f := newTokenFixture(t)
	secret := revocableClient(t, f)
	access := f.signsIn(t, secret, "openid")["access_token"].(string)
	service := registerHook(t, f.srv, f.pool, f.orgID, provider.HookUserinfo, "tier")
	service.says(`{"decision":true,"claims":{"tier":"gold","secret":"not on the list","sub":"somebody-else"}}`)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got["tier"] != "gold" || got["secret"] != nil || got["sub"] != f.userID {
		t.Errorf("userinfo said %v", got)
	}
	if asked := service.lastAsked(); asked["subject"] != f.userID || asked["client_id"] != f.clientID {
		t.Errorf("the service was told %v", asked)
	}

	service.says(`{"decision":false,"reason":"on hold"}`)
	req = httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "on hold") {
		t.Errorf("a refused userinfo: %d %s", rec.Code, rec.Body)
	}
}

// A list for a hook that only answers yes or no would read as working and do nothing.
func TestAHookThatAddsNothingHasNoList(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	registerHook(t, f.srv, f.pool, f.orgID, provider.HookAuthenticate)
	registerHook(t, f.srv, f.pool, f.orgID, provider.HookUserinfo)
	if err := store.SetProviderClaims(ctx, f.pool, f.orgID, provider.HookAuthenticate, []string{"tier"}); !errors.Is(err, store.ErrHookAddsNothing) {
		t.Errorf("a list for authenticate: %v", err)
	}
	if err := store.SetProviderClaims(ctx, f.pool, f.orgID, provider.HookAuthenticate, nil); err != nil {
		t.Errorf("clearing a list that is not there: %v", err)
	}
	if err := store.SetProviderClaims(ctx, f.pool, f.orgID, provider.HookUserinfo, []string{"tier"}); err != nil {
		t.Errorf("a list for userinfo: %v", err)
	}
}

// The saml_assertion hook adds attributes the operator's list lets it, and a refusal is
// told to the service provider as a policy refusal is.
func TestTheSAMLAssertionHookAddsAndRefuses(t *testing.T) {
	rf := newRealmFixture(t)
	service := registerHook(t, rf.f.srv, rf.f.pool, rf.f.orgID, provider.HookSAMLAssertion, "tier")
	service.says(`{"decision":true,"claims":{"tier":["gold","vip"],"secret":"not on the list"}}`)

	_, resp := rf.samlSSO(t, rf.own)
	if !strings.Contains(resp, "Assertion") {
		t.Fatalf("no assertion: %.300s", resp)
	}
	if !strings.Contains(resp, `Name="tier"`) || !strings.Contains(resp, ">gold<") || !strings.Contains(resp, ">vip<") ||
		strings.Contains(resp, "not on the list") {
		t.Errorf("the assertion said %.900s", resp)
	}
	if asked := service.lastAsked(); asked["entity_id"] != rf.own {
		t.Errorf("the service was told %v", asked)
	}

	service.says(`{"decision":false,"reason":"this service is suspended"}`)
	_, resp = rf.samlSSO(t, rf.own)
	if strings.Contains(resp, "<saml:Assertion") || !strings.Contains(resp, "status:RequestDenied") {
		t.Errorf("a refused assertion: %.400s", resp)
	}
}
