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
