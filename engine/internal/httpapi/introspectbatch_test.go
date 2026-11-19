package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// roundTrips counts what reaches the database: a statement on its own, or a batch, as one.
// A batch's statements are told apart from a statement on its own, so a failure says what
// each trip was.
type roundTrips struct {
	n    atomic.Int64
	mu   sync.Mutex
	what []string
}

func (c *roundTrips) note(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.what = append(c.what, strings.Join(strings.Fields(s), " "))
}

func (c *roundTrips) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	c.note(d.SQL)
	return ctx
}
func (c *roundTrips) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (c *roundTrips) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	c.n.Add(1)
	c.note("batch:")
	return ctx
}
func (c *roundTrips) TraceBatchQuery(_ context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	c.note("  in the batch: " + d.SQL)
}
func (c *roundTrips) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

func (c *roundTrips) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, s := range c.what {
		if len(s) > 160 {
			s = s[:160] + "..."
		}
		b.WriteString("\n  " + s)
	}
	return b.String()
}

// reset forgets what was counted, for a test counting one step at a time.
func (c *roundTrips) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n.Store(0)
	c.what = nil
}

func countRoundTrips(t *testing.T, f *tokenFixture) *roundTrips {
	t.Helper()
	return countRoundTripsOf(t, f.srv)
}

// countRoundTripsOf points srv at a pool that counts, from here on.
func countRoundTripsOf(t *testing.T, srv *Server) *roundTrips {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	trips := &roundTrips{}
	cfg.ConnConfig.Tracer = trips
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Connections opened now, or a new one's SET ROLE counts as the request's.
	var held []*pgxpool.Conn
	for range 3 {
		c, err := pool.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	for _, c := range held {
		c.Release()
	}
	trips.reset()
	srv.db = pool
	return trips
}

// Introspection asks what has become of the token in the round trip that finds the client
// (E.23), one round trip for the whole answer, and that answer is still the token's: a
// revoked token read that way is inactive.
func TestIntrospectionAsksTheTokensStandingWithTheClient(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, clientAuthPerPairWindow)
	secret := revocableClient(t, f)
	verifier := "verifier-introspect-batch-aaaaaaaaaaaaaaaaaaaa"
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid", "offline_access"})
	status, body := f.post(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "client_secret": {secret},
		"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("the code exchange answered %d: %v", status, body)
	}
	access, _ := body["access_token"].(string)
	refresh, _ := body["refresh_token"].(string)
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.18.%d.%d", n%250, (n/250)%250+1)
	introspect := func(token string) map[string]any {
		t.Helper()
		status, got := postTokenAdmin(t, f, oidc.PathIntrospection, addr,
			url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "token": {token}})
		if status != http.StatusOK {
			t.Fatalf("introspection answered %d: %v", status, got)
		}
		return got
	}

	trips := countRoundTrips(t, f)
	if got := introspect(access); got["active"] != true {
		t.Fatalf("a live token introspected as %v", got)
	}
	if got := trips.n.Load(); got != 1 {
		t.Errorf("introspecting a live access token took %d round trips; the client, its failure "+
			"counters and the token's standing are one:%s", got, trips)
	}

	if status, got := postTokenAdmin(t, f, "/oauth2/revoke", addr,
		url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "token": {refresh}}); status != http.StatusOK {
		t.Fatalf("revoking the refresh token answered %d: %v", status, got)
	}
	if got := introspect(access); got["active"] != false {
		t.Fatalf("an access token whose grant was revoked introspected as %v, read with the client", got)
	}
}

// Asking with the client is no way for a caller that cannot authenticate to have the
// engine read on its token's behalf. A pairwise subject is read back to its person when its
// token is verified, so its token is verified after authentication, and a wrong secret
// costs the batch that finds the client and the failure it charges, and nothing for the
// token. The token is still answered once the client has authenticated.
func TestAnUnauthenticatedIntrospectionReadsNothingForItsToken(t *testing.T) {
	f := newTokenFixture(t)
	clearOfWindowEdge(t, clientAuthPerPairWindow)
	f.forgetPairwise(t)
	secret := revocableClient(t, f)
	setSubject(t, f.pool, f.clientID, "pairwise", "batch.example")
	access := f.signsIn(t, secret, "openid")["access_token"].(string)
	sub, _ := claimsOfJWT(t, access)["sub"].(string)
	if !strings.HasPrefix(sub, store.PairwisePrefix) {
		t.Fatalf("the fixture's token names %q, not a pairwise subject", sub)
	}
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.18.%d.%d", n%250, (n/250)%250+1)
	form := func(s string) url.Values {
		return url.Values{"client_id": {f.clientID}, "client_secret": {s}, "token": {access}}
	}

	trips := countRoundTrips(t, f)
	if status, got := postTokenAdmin(t, f, oidc.PathIntrospection, addr, form("not-the-secret")); status != http.StatusUnauthorized {
		t.Fatalf("a wrong secret was answered %d: %v", status, got)
	}
	trips.mu.Lock()
	for _, s := range trips.what {
		if s != "batch:" && !strings.HasPrefix(s, "in the batch: ") && !strings.HasPrefix(s, "INSERT INTO core.rate_limits") {
			t.Errorf("a caller that did not authenticate had the engine run %q", s)
		}
	}
	trips.mu.Unlock()

	if status, got := postTokenAdmin(t, f, oidc.PathIntrospection, addr, form(secret)); status != http.StatusOK ||
		got["active"] != true || got["sub"] != sub {
		t.Fatalf("the client introspecting its pairwise token was answered %d %v", status, got)
	}
}
