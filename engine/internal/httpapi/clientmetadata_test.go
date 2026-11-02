package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// An application nobody registered, known by the URL its document is at: an MCP client
// reaching a server of this deployment, the case the row was written for.

type documentClient struct {
	*signInFixture
	site     *httptest.Server
	id       string
	prefix   string
	instance string
	fetched  atomic.Int32
	// doc is what the site says, as a function so that a test can change its mind.
	doc     func() map[string]any
	headers http.Header
	failing atomic.Bool
}

func newDocumentClient(t *testing.T) *documentClient {
	t.Helper()
	d := &documentClient{signInFixture: newSignInFixture(t), headers: http.Header{}}
	ctx := context.Background()
	if err := d.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`, d.orgID).Scan(&d.instance); err != nil {
		t.Fatal(err)
	}
	d.srv.SetInstance(d.instance)
	d.site = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		d.fetched.Add(1)
		if d.failing.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		for name, values := range d.headers {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.doc())
	}))
	t.Cleanup(d.site.Close)
	d.srv.outboundHTTP = func(time.Duration) *http.Client { return d.site.Client() }
	d.id = d.site.URL + "/mcp/client.json"
	d.prefix = d.site.URL + "/mcp/"
	d.doc = func() map[string]any {
		return map[string]any{"client_id": d.id, "client_name": "An MCP client", "scope": "openid profile admin",
			"redirect_uris": []string{d.site.URL + "/callback"}, "grant_types": []string{"authorization_code", "refresh_token"}}
	}
	t.Cleanup(func() {
		_, _ = d.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, d.id)
		_, _ = d.pool.Exec(context.Background(), `DELETE FROM core.client_metadata_rules WHERE instance_id = $1::uuid AND url_prefix = $2`,
			d.instance, d.prefix)
	})
	return d
}

func (d *documentClient) allow(t *testing.T) {
	t.Helper()
	if err := store.SetClientMetadataRule(context.Background(), d.pool, d.instance, store.ClientMetadataRule{URLPrefix: d.prefix,
		OrgID: d.orgID, Scopes: []string{"openid", "profile"}}); err != nil {
		t.Fatal(err)
	}
}

func (d *documentClient) known(t *testing.T) bool {
	t.Helper()
	var found bool
	if err := d.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1)`, d.id).Scan(&found); err != nil {
		t.Fatal(err)
	}
	return found
}

func (d *documentClient) expire(t *testing.T) {
	t.Helper()
	if _, err := d.pool.Exec(context.Background(), `UPDATE core.clients SET federation_expires_at = now() - interval '1 minute'
		WHERE client_id = $1`, d.id); err != nil {
		t.Fatal(err)
	}
}

const documentVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func (d *documentClient) authorize(t *testing.T, b *testBrowser) *httptest.ResponseRecorder {
	t.Helper()
	sum := sha256.Sum256([]byte(documentVerifier))
	return b.get(oidc.PathAuthorize + "?" + d.authz(base64.RawURLEncoding.EncodeToString(sum[:])))
}

func (d *documentClient) authz(challenge string) string {
	return url.Values{"client_id": {d.id}, "response_type": {"code"}, "scope": {"openid profile"},
		"redirect_uri": {d.site.URL + "/callback"}, "state": {"s"}, "nonce": {"n"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}.Encode()
}

func (d *documentClient) signedIn(t *testing.T) *testBrowser {
	t.Helper()
	clearSignInBucket(t, d.pool)
	b := newTestBrowser(t, d.srv.Routes())
	b.post("/login", b.get("/login"), url.Values{"username": {d.email}, "password": {signInTestPassword}})
	return b
}

// consented answers the consent page and comes back with the code.
func (d *documentClient) consented(t *testing.T, b *testBrowser, page *httptest.ResponseRecorder) string {
	t.Helper()
	sum := sha256.Sum256([]byte(documentVerifier))
	answered := b.post("/consent", page, url.Values{"decision": {"allow"}, "scope": {"openid", "profile"},
		"authz": {d.authz(base64.RawURLEncoding.EncodeToString(sum[:]))}})
	if !strings.Contains(answered.Header().Get("Location"), "code=") {
		answered = b.follow(answered)
	}
	loc, err := url.Parse(answered.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("no code: %d %q %.300s", answered.Code, answered.Header().Get("Location"), answered.Body)
	}
	return loc.Query().Get("code")
}

func TestAClientKnownByItsURLCompletesASignIn(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	b := d.signedIn(t)
	page := d.authorize(t, b)
	if !d.known(t) {
		t.Fatalf("it was not admitted: %d %.300s", page.Code, page.Body)
	}
	ctx := context.Background()
	var org, name, kind, method, prefix string
	var scopes, redirects []string
	var firstParty bool
	var expires time.Time
	if err := d.pool.QueryRow(ctx, `SELECT org_id::text, display_name, client_type, token_endpoint_auth_method, scopes,
		client_metadata_prefix, federation_expires_at, first_party,
		ARRAY(SELECT redirect_uri FROM core.client_redirect_uris r WHERE r.client_id = c.client_id)
		FROM core.clients c WHERE client_id = $1`, d.id).Scan(&org, &name, &kind, &method, &scopes, &prefix, &expires, &firstParty, &redirects); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(d.site.URL, "https://")
	if org != d.orgID || kind != "public" || method != "none" || prefix != d.prefix || firstParty {
		t.Errorf("registered as org %s, %s, %s, under %s, first party %v", org, kind, method, prefix, firstParty)
	}
	// §8.5: the hostname goes where the name goes, the name being anybody's to choose.
	if name != "An MCP client ("+host+")" {
		t.Errorf("it is called %q", name)
	}
	// It asked for admin too, and the rule says what a stranger may have.
	if strings.Join(scopes, " ") != "openid profile" {
		t.Errorf("it may have %v", scopes)
	}
	if len(redirects) != 1 || redirects[0] != d.site.URL+"/callback" {
		t.Errorf("redirects %v", redirects)
	}
	if left := time.Until(expires); left <= 0 || left > 2*time.Hour {
		t.Errorf("it expires in %v", left)
	}
	if !strings.Contains(page.Body.String(), host) {
		t.Errorf("the consent page does not name the host: %d %.300s", page.Code, page.Body)
	}

	code := d.consented(t, b, page)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {d.id},
		"redirect_uri": {d.site.URL + "/callback"}, "code_verifier": {documentVerifier}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	d.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("redeeming answered %d %.300s", rec.Code, rec.Body)
	}
	fetched := d.fetched.Load()
	d.authorize(t, b)
	if got := d.fetched.Load(); got != fetched {
		t.Errorf("a client within its lifetime was fetched again: %d then %d", fetched, got)
	}
}

// No rule, no request. The list being empty is the ordinary case and it costs nothing.
func TestWithNoRuleNothingIsFetched(t *testing.T) {
	d := newDocumentClient(t)
	b := d.signedIn(t)
	if page := d.authorize(t, b); strings.Contains(page.Header().Get("Location"), "code=") {
		t.Errorf("it got somewhere: %q", page.Header().Get("Location"))
	}
	if d.known(t) || d.fetched.Load() != 0 {
		t.Errorf("known %v after %d fetches", d.known(t), d.fetched.Load())
	}
	// A rule for something else is the same, the prefix ending in a slash so that it
	// cannot also cover https://host.evil.test/.
	if err := store.SetClientMetadataRule(context.Background(), d.pool, d.instance, store.ClientMetadataRule{
		URLPrefix: d.site.URL + "/other/", OrgID: d.orgID}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.pool.Exec(context.Background(), `DELETE FROM core.client_metadata_rules WHERE instance_id = $1::uuid`, d.instance)
	})
	d.authorize(t, b)
	if d.known(t) || d.fetched.Load() != 0 {
		t.Errorf("another rule's URL was fetched: %d", d.fetched.Load())
	}
}

func TestADocumentThatFailsLeavesNothing(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	d.failing.Store(true)
	b := d.signedIn(t)
	page := d.authorize(t, b)
	if d.known(t) {
		t.Fatal("a client was made of an error")
	}
	if strings.Contains(page.Header().Get("Location"), d.site.URL) {
		t.Errorf("a client nothing vouches for was redirected to: %q", page.Header().Get("Location"))
	}
	// §5.2: "MUST NOT cache error responses", so the next request asks again.
	before := d.fetched.Load()
	d.failing.Store(false)
	d.authorize(t, b)
	if d.fetched.Load() == before || !d.known(t) {
		t.Errorf("an error was remembered: %d fetches, known %v", d.fetched.Load(), d.known(t))
	}
}

// Past its lifetime it is asked again, its new redirect comes in with that, and a site
// that has stopped answering loses the client until it answers.
func TestAClientIsAskedAgainWhenItExpires(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	d.headers.Set("Cache-Control", "max-age=120")
	b := d.signedIn(t)
	d.authorize(t, b)
	ctx := context.Background()
	var expires time.Time
	if err := d.pool.QueryRow(ctx, `SELECT federation_expires_at FROM core.clients WHERE client_id = $1`, d.id).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(expires); left <= 0 || left > 3*time.Minute {
		t.Errorf("its cache header was not honoured: %v left", left)
	}
	was := d.doc
	d.doc = func() map[string]any {
		doc := was()
		doc["redirect_uris"] = []string{d.site.URL + "/callback", d.site.URL + "/second"}
		doc["client_name"] = "Renamed"
		return doc
	}
	d.expire(t)
	d.authorize(t, b)
	var name string
	var redirects int
	if err := d.pool.QueryRow(ctx, `SELECT display_name, (SELECT count(*) FROM core.client_redirect_uris r WHERE r.client_id = c.client_id)
		FROM core.clients c WHERE client_id = $1`, d.id).Scan(&name, &redirects); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "Renamed") || redirects != 2 {
		t.Errorf("the client is %q with %d redirects", name, redirects)
	}

	d.expire(t)
	d.failing.Store(true)
	page := d.authorize(t, b)
	if page.Code == http.StatusFound || strings.Contains(page.Header().Get("Location"), d.site.URL) ||
		!strings.Contains(page.Body.String(), "expired") {
		t.Errorf("a client whose site went quiet was served: %d %q %.200s", page.Code, page.Header().Get("Location"), page.Body)
	}
}

// §7.2: a client somebody registered is theirs, whatever a document at that URL says.
func TestADocumentDoesNotTakeOverAClient(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	ctx := context.Background()
	if _, err := d.pool.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type)
		VALUES ($1, $2::uuid, 'Registered here', 'public')`, d.id, d.orgID); err != nil {
		t.Fatal(err)
	}
	d.authorize(t, d.signedIn(t))
	var name string
	if err := d.pool.QueryRow(ctx, `SELECT display_name FROM core.clients WHERE client_id = $1`, d.id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Registered here" || d.fetched.Load() != 0 {
		t.Errorf("it is called %q after %d fetches", name, d.fetched.Load())
	}
	// And a rule with that URL fetched by mistake could not write over it either.
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.RegisterMetadataClient(ctx, tx, store.MetadataClient{ClientID: d.id, OrgID: d.orgID, Name: "Took over",
		Prefix: d.prefix, Public: true, Scopes: []string{"openid"}, GrantTypes: []string{"authorization_code"},
		Expiry: time.Now().Add(time.Hour)}); err == nil {
		t.Error("it wrote over a client")
	}
}

// §8.2: a client that says it holds a key has to prove it, by the key its document names.
func TestAClientWithAKeyHasToUseIt(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	was := d.doc
	d.doc = func() map[string]any {
		doc := was()
		doc["token_endpoint_auth_method"] = "private_key_jwt"
		doc["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
		return doc
	}
	b := d.signedIn(t)
	page := d.authorize(t, b)
	if !d.known(t) {
		t.Fatalf("it was not admitted: %d %.300s", page.Code, page.Body)
	}
	code := d.consented(t, b, page)
	redeem := func(extra url.Values) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {d.id},
			"redirect_uri": {d.site.URL + "/callback"}, "code_verifier": {documentVerifier}}
		for name, values := range extra {
			form[name] = values
		}
		req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		d.srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := redeem(nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no proof answered %d %.200s", rec.Code, rec.Body)
	}
	assertion := signStatement(t, private, "k1", "JWT", map[string]any{"iss": d.id, "sub": d.id, "aud": d.srv.cfg.Issuer,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "document-1"})
	rec := redeem(url.Values{"client_assertion_type": {clientauth.AssertionType}, "client_assertion": {assertion}})
	if rec.Code != http.StatusOK {
		t.Errorf("the key's owner answered %d %.300s", rec.Code, rec.Body)
	}
}

// Pushing the request first is the same arrival by another door.
func TestAClientKnownByItsURLCanPushItsRequest(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	sum := sha256.Sum256([]byte(documentVerifier))
	form, err := url.ParseQuery(d.authz(base64.RawURLEncoding.EncodeToString(sum[:])))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	d.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || !d.known(t) {
		t.Errorf("the push answered %d, known %v: %.300s", rec.Code, d.known(t), rec.Body)
	}
}

// As is a signed request at the authorization endpoint, which is read before anything
// else there and has to find the client it is from.
func TestAClientKnownByItsURLCanSignItsRequest(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	was := d.doc
	d.doc = func() map[string]any {
		doc := was()
		doc["token_endpoint_auth_method"] = "private_key_jwt"
		doc["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
		return doc
	}
	sum := sha256.Sum256([]byte(documentVerifier))
	object := signStatement(t, private, "k1", "oauth-authz-req+jwt", map[string]any{"iss": d.id, "aud": d.srv.cfg.Issuer,
		"client_id": d.id, "response_type": "code", "scope": "openid profile", "redirect_uri": d.site.URL + "/callback",
		"state": "s", "nonce": "n", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]),
		"code_challenge_method": "S256", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "document-object"})
	page := d.signedIn(t).get(oidc.PathAuthorize + "?" + url.Values{"client_id": {d.id}, "request": {object}}.Encode())
	if !d.known(t) {
		t.Fatalf("it was not admitted: %d %.300s", page.Code, page.Body)
	}
	// The consent page, and not a refusal sent to the client.
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "An MCP client") {
		t.Errorf("a signed request came to %d %q: %.300s", page.Code, page.Header().Get("Location"), page.Body)
	}
}

// §6, and only while it is true.
func TestDiscoverySaysSoOnlyWithARule(t *testing.T) {
	d := newDocumentClient(t)
	ask := func() bool {
		t.Helper()
		md, err := d.srv.buildDiscovery(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return md.ClientIDMetadataDocumentSupported
	}
	if ask() {
		t.Error("it was advertised with no rule")
	}
	d.allow(t)
	if !ask() {
		t.Error("it was not advertised with a rule")
	}
}

// A rule taken away takes its clients with it, who had no other standing.
func TestForgettingARuleForgetsItsClients(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	d.authorize(t, d.signedIn(t))
	if !d.known(t) {
		t.Fatal("it was not admitted")
	}
	ctx := context.Background()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	gone, err := store.RemoveClientMetadataRule(ctx, tx, d.instance, d.prefix)
	if err != nil || gone != 1 {
		t.Fatalf("%d, %v", gone, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if d.known(t) {
		t.Error("the client outlived its rule")
	}
}

// A stranger's address cannot have this server fetch without end.
func TestFetchesArePaced(t *testing.T) {
	d := newDocumentClient(t)
	d.allow(t)
	d.failing.Store(true)
	b := d.signedIn(t)
	for range clientMetadataFetchesPerAddress + 5 {
		d.authorize(t, b)
	}
	if got := d.fetched.Load(); got > clientMetadataFetchesPerAddress {
		t.Errorf("%d fetches from one address", got)
	}
}

func TestAMetadataClientsNameStaysItsHost(t *testing.T) {
	for name, want := range map[string]string{
		"":                       "app.example",
		"   ":                    "app.example",
		"Claude":                 "Claude (app.example)",
		"Two\n  lines":           "Two lines (app.example)",
		strings.Repeat("a", 200): strings.Repeat("a", clientMetadataNameLimit) + " (app.example)",
	} {
		if got := metadataClientName(name, "https://app.example/client.json"); got != want {
			t.Errorf("%q came out %q", name, got)
		}
	}
}
