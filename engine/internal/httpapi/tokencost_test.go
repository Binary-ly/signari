package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
)

// statements remembers what a pool was asked, so a test can say which went over.
type statements struct {
	mu   sync.Mutex
	seen []string
}

func (s *statements) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, strings.Join(strings.Fields(d.SQL), " "))
	return ctx
}

func (s *statements) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (s *statements) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := s.seen
	s.seen = nil
	return got
}

// traced puts a recording pool under a server.
func traced(t *testing.T, srv *Server) *statements {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	spent := &statements{}
	cfg.ConnConfig.Tracer = spent
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	srv.db = pool
	return spent
}

// A session-bound token with a refresh token behind it, the most a check can have
// to ask about, and a secret to introspect it with.
func costlyToken(t *testing.T, f *tokenFixture) (access, secret string) {
	t.Helper()
	secret = revocableClient(t, f)
	const verifier = "verifier-cost-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "profile", "email", "offline_access"})
	status, body := f.post(t, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "client_secret": {secret}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier}})
	if status != http.StatusOK {
		t.Fatalf("redeeming: %d %v", status, body)
	}
	access, _ = body["access_token"].(string)
	return access, secret
}

func underLimit(t *testing.T, what string, got []string, limit int) {
	t.Helper()
	if len(got) <= limit {
		t.Logf("%s took %d statements", what, len(got))
		return
	}
	t.Errorf("%s took %d statements, wanting at most %d:", what, len(got), limit)
	for _, s := range got {
		t.Logf("  %.110s", s)
	}
}

// transactions counts those a pool was asked to begin.
func transactions(got []string) int {
	n := 0
	for _, s := range got {
		if strings.EqualFold(s, "begin") {
			n++
		}
	}
	return n
}

// A password sign-in, form to session: each transaction is a commit somebody waits
// for, and each statement a round trip.
func TestAPasswordSignInTakesFewTransactions(t *testing.T) {
	f := newSignInFixture(t)
	clearSignInBucket(t, f.pool)
	spent := traced(t, f.srv)
	if got := f.attempt(t, f.email, signInTestPassword); !got.signedIn() {
		t.Fatalf("signing in: %+v", got)
	}
	seen := spent.take()
	underLimit(t, "the form and a password sign-in", seen, 27)
	if transactions(seen) > 1 {
		t.Errorf("a sign-in opened %d transactions", transactions(seen))
	}
}

// The token endpoint's three common grants, with a root key and an instance as a
// deployment has them, and begin and commit counted. A mapper or a provider adds
// what it needs; a deployment with neither pays for neither.
func TestTheTokenEndpointAsksTheDatabaseLittle(t *testing.T) {
	f := newTokenFixture(t)
	secret := revocableClient(t, f)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.root = root
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations
		WHERE id = $1::uuid`, f.orgID).Scan(&f.srv.instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET grant_types = grant_types || ARRAY['client_credentials', 'refresh_token'],
		scopes = scopes || ARRAY['api.read'] WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	const verifier = "verifier-cost-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "offline_access"})
	spent := traced(t, f.srv)

	status, body := f.post(t, url.Values{"grant_type": {"client_credentials"}, "client_id": {f.clientID},
		"client_secret": {secret}, "scope": {"api.read"}})
	if status != http.StatusOK {
		t.Fatalf("client credentials: %d %v", status, body)
	}
	underLimit(t, "client credentials", spent.take(), 3)

	status, body = f.post(t, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "client_secret": {secret}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier}})
	if status != http.StatusOK {
		t.Fatalf("redeeming a code: %d %v", status, body)
	}
	underLimit(t, "redeeming a code", spent.take(), 10)

	refresh, _ := body["refresh_token"].(string)
	status, body = f.post(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.clientID}, "client_secret": {secret}})
	if status != http.StatusOK {
		t.Fatalf("refreshing: %d %v", status, body)
	}
	underLimit(t, "refreshing", spent.take(), 11)
}

// A browser with a session coming back to /authorize, which is most of what the
// endpoint serves once people are signed in: every application they open. Begin
// and commit counted, in a deployment with a root key, an instance, no provider
// and no policy, and for an application the person has agreed to.
func TestAResumedAuthorizationAsksTheDatabaseLittle(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.root = root
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations
		WHERE id = $1::uuid`, f.orgID).Scan(&f.srv.instanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.consents (user_id, client_id, scopes)
		VALUES ($1::uuid, $2, ARRAY['openid'])`, f.userID, f.clientID); err != nil {
		t.Fatal(err)
	}
	cookie := f.signInAndReturnCookie(t)
	spent := traced(t, f.srv)

	req := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+f.plainAuthz(), nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if redirected(t, rec).Get("code") == "" {
		t.Fatalf("no code: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	underLimit(t, "a resumed authorization", spent.take(), 8)
}

// A SAML sign-in for somebody with a session, the second of two, since the first
// makes the key's certificate. Begin and commit counted, with a provider that
// releases no groups and no attributes.
func TestASAMLResponseAsksTheDatabaseLittle(t *testing.T) {
	rf := newRealmFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	rf.f.srv.root = root
	if err := rf.f.pool.QueryRow(context.Background(), `SELECT instance_id::text FROM core.organizations
		WHERE id = $1::uuid`, rf.f.orgID).Scan(&rf.f.srv.instanceID); err != nil {
		t.Fatal(err)
	}
	spent := traced(t, rf.f.srv)
	if _, doc := rf.samlSSO(t, rf.own); doc == "" {
		t.Fatal("no response")
	}
	spent.take()
	if _, doc := rf.samlSSO(t, rf.own); doc == "" {
		t.Fatal("no second response")
	}
	underLimit(t, "a SAML response", spent.take(), 9)
}

// These two are what a resource server calls on every request it serves, so a
// statement here is one for each of those.
func TestIntrospectionAndUserinfoAskTheDatabaseLittle(t *testing.T) {
	f := newTokenFixture(t)
	access, secret := costlyToken(t, f)
	// As a real deployment has them: a root key, which is what opens claim mappers
	// to being asked about, and an instance, which is what issuer aliases are of.
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.root = root
	if err := f.pool.QueryRow(context.Background(), `SELECT instance_id::text FROM core.organizations
		WHERE id = $1::uuid`, f.orgID).Scan(&f.srv.instanceID); err != nil {
		t.Fatal(err)
	}
	spent := traced(t, f.srv)

	if got := f.introspect(t, access, f.clientID, secret); got["active"] != true {
		t.Fatalf("introspection answered %v", got)
	}
	underLimit(t, "introspection", spent.take(), 3)

	req := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo answered %d: %s", rec.Code, rec.Body.String())
	}
	underLimit(t, "userinfo", spent.take(), 3)
}
