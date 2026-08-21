package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// Handler-level tests for the token endpoint.
//
// internal/store already proves the primitives in isolation (atomic single-use
// codes, family revocation). What is untested until here is the WIRING: whether
// handleToken actually calls them, in the right order, and acts on the result.
// A correct primitive that the handler forgets to consult is indistinguishable
// from a missing one at the HTTP boundary, and the HTTP boundary is what
// attackers reach.

const tokenTestIssuer = "https://token-test.example"

type tokenFixture struct {
	srv      *Server
	pool     *pgxpool.Pool
	orgID    string
	userID   string
	clientID string
	sid      string

	// exchangeSecret is set by enableExchange. Token exchange requires a
	// confidential client -- a public one cannot prove it is the client the
	// permission was granted to -- so enabling exchange necessarily means giving
	// the fixture a secret and using it.
	exchangeSecret string
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// In-memory keys: this exercises the handler, not key storage.
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(oidc.Config{Issuer: tokenTestIssuer, Keys: set, AllowInsecureIssuer: true},
		pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &tokenFixture{srv: srv, pool: pool}
	suffix := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")

	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://tok-' || gen_random_uuid() || '.test', 'T') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 't' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle)
		SELECT id, 't'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')
		FROM o RETURNING org_id::text, id::text`).Scan(&f.orgID, &f.userID); err != nil {
		t.Fatalf("fixture user: %v", err)
	}

	f.clientID = "tok-" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2,'T','public','', ARRAY['authorization_code','refresh_token'],
		        ARRAY['openid','offline_access'], true)`, f.clientID, f.orgID); err != nil {
		t.Fatalf("fixture client: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
		f.clientID, "https://rp.test/cb"); err != nil {
		t.Fatalf("fixture redirect: %v", err)
	}

	f.sid = "tok-sid-" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, decode(md5($1),'hex'), $2, $3, '1', ARRAY['pwd'], now(), now() + interval '1 hour')`,
		f.sid, f.orgID, f.userID); err != nil {
		t.Fatalf("fixture session: %v", err)
	}

	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DELETE FROM core.sessions WHERE sid = $1`, f.sid)
		_, _ = pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, f.clientID)
	})
	return f
}

// issueCode plants an authorization code the way the authorize endpoint would.
func (f *tokenFixture) issueCode(t *testing.T, verifier string) string {
	t.Helper()
	ctx := context.Background()

	code, hash, err := store.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	grant := oauth.GrantRecord{
		ClientID: f.clientID, RedirectURI: "https://rp.test/cb",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
		Nonce: "nonce-1", Scopes: []string{"openid", "offline_access"},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := store.IssueCode(ctx, tx, f.orgID, f.clientID, f.sid, f.userID, grant, hash, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchSessionClient(ctx, tx, f.sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return code
}

func (f *tokenFixture) post(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func (f *tokenFixture) redeem(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {f.clientID},
		"redirect_uri":  {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}
}

// A code is spendable exactly once, and a SECOND attempt must not merely fail --
// it must revoke the tokens the first redemption produced. Either the code
// leaked or the client is broken; both warrant killing the grant, and rejecting
// without revoking leaves a thief holding live tokens.
func TestCodeReuseRevokesTheIssuedTokens(t *testing.T) {
	f := newTokenFixture(t)
	verifier := strings.Repeat("v", 64)
	code := f.issueCode(t, verifier)

	status, body := f.post(t, f.redeem(code, verifier))
	if status != http.StatusOK {
		t.Fatalf("first redemption gave %d: %v", status, body)
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no refresh token issued; the rest of this test proves nothing")
	}

	status2, _ := f.post(t, f.redeem(code, verifier))
	if status2 == http.StatusOK {
		t.Fatal("the same authorization code was redeemed twice")
	}

	// The decisive assertion: the refresh token from the FIRST redemption must
	// now be dead. A handler that rejects the replay but leaves the family live
	// passes the check above and still loses the account.
	var revoked bool
	if err := f.pool.QueryRow(context.Background(), `
		SELECT fam.revoked_at IS NOT NULL
		FROM core.refresh_tokens t
		JOIN core.refresh_token_families fam ON fam.id = t.family_id
		WHERE t.token_hash = $1`, store.HashToken(refresh)).Scan(&revoked); err != nil {
		t.Fatalf("looking up the refresh family: %v", err)
	}
	if !revoked {
		t.Error("code was replayed and the token family is STILL LIVE")
	}
}

// PKCE is the only thing authenticating a public client. If a wrong or absent
// verifier is accepted, a stolen code is enough on its own.
func TestPKCEIsEnforced(t *testing.T) {
	verifier := strings.Repeat("v", 64)

	for name, mutate := range map[string]func(url.Values){
		"absent verifier": func(v url.Values) { v.Del("code_verifier") },
		"empty verifier":  func(v url.Values) { v.Set("code_verifier", "") },
		"wrong verifier":  func(v url.Values) { v.Set("code_verifier", strings.Repeat("x", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newTokenFixture(t)
			code := f.issueCode(t, verifier)
			form := f.redeem(code, verifier)
			mutate(form)
			if status, body := f.post(t, form); status == http.StatusOK {
				t.Fatalf("%s was accepted: %v", name, body)
			}
		})
	}
}

// RFC 6749 §4.1.3: redirect_uri must equal the one used at authorization -- not
// merely be A registered URI. The weaker check lets a code obtained through one
// callback be redeemed through another, which is the classic code-injection set-up.
func TestRedirectURIMustMatchTheAuthorizationRequest(t *testing.T) {
	f := newTokenFixture(t)
	verifier := strings.Repeat("v", 64)
	code := f.issueCode(t, verifier)

	form := f.redeem(code, verifier)
	form.Set("redirect_uri", "https://rp.test/other")
	if status, body := f.post(t, form); status == http.StatusOK {
		t.Fatalf("a mismatched redirect_uri was accepted: %v", body)
	}
}

// A code issued to one client must not be redeemable by another, even one that
// authenticates perfectly well as itself.
func TestCodeIsBoundToTheClientItWasIssuedTo(t *testing.T) {
	f := newTokenFixture(t)
	other := newTokenFixture(t) // a second, legitimate client
	verifier := strings.Repeat("v", 64)
	code := f.issueCode(t, verifier)

	form := other.redeem(code, verifier)
	if status, body := other.post(t, form); status == http.StatusOK {
		t.Fatalf("client %s redeemed a code issued to %s: %v", other.clientID, f.clientID, body)
	}
}

// Grants we do not implement must be refused by name, before any lookup.
func TestRemovedGrantsAreRefused(t *testing.T) {
	f := newTokenFixture(t)
	for _, gt := range []string{"password", "implicit", "", "magic"} {
		status, body := f.post(t, url.Values{
			"grant_type": {gt}, "client_id": {f.clientID},
		})
		if status == http.StatusOK {
			t.Errorf("grant_type=%q was accepted", gt)
		}
		if body["error"] == nil {
			t.Errorf("grant_type=%q: no error code in the response", gt)
		}
	}
}

// Token responses carry bearer credentials and must never be cached.
func TestTokenResponsesAreNotCacheable(t *testing.T) {
	f := newTokenFixture(t)
	verifier := strings.Repeat("v", 64)
	code := f.issueCode(t, verifier)

	req := httptest.NewRequest(http.MethodPost, oidc.PathToken,
		strings.NewReader(f.redeem(code, verifier).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
