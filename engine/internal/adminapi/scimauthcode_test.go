package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// codeTarget is a SCIM target with its own authorization server: an authorization
// endpoint that answers with a code as if the person had agreed, and a token
// endpoint that rotates refresh tokens and ends the grant when a spent one comes
// back (specs/draft-ietf-oauth-v2-1-17.txt:2660-2672).
type codeTarget struct {
	*httptest.Server
	mu        sync.Mutex
	codes     map[string][2]string // code: challenge, redirect URI
	live      string
	spent     map[string]bool
	ended     bool
	issued    int
	presented []string
	access    string
	bearers   []string
	delay     time.Duration
}

func newCodeTarget(t *testing.T) *codeTarget {
	t.Helper()
	f := &codeTarget{codes: map[string][2]string{}, spent: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != "our client" || q.Get("response_type") != "code" ||
			q.Get("code_challenge_method") != "S256" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		code := fmt.Sprintf("code-%d", len(f.codes)+f.issued+1)
		f.codes[code] = [2]string{q.Get("code_challenge"), q.Get("redirect_uri")}
		f.mu.Unlock()
		back, _ := url.Parse(q.Get("redirect_uri"))
		bq := back.Query()
		bq.Set("code", code)
		bq.Set("state", q.Get("state"))
		back.RawQuery = bq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		delay := f.delay
		f.mu.Unlock()
		time.Sleep(delay)
		f.mu.Lock()
		defer f.mu.Unlock()
		refuse := func(code string) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		id, secret, _ := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if id != "our client" || secret != "the secret" {
			refuse("invalid_client")
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			given, ok := f.codes[r.PostForm.Get("code")]
			delete(f.codes, r.PostForm.Get("code"))
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != given[0] || r.PostForm.Get("redirect_uri") != given[1] {
				refuse("invalid_grant")
				return
			}
		case "refresh_token":
			rt := r.PostForm.Get("refresh_token")
			f.presented = append(f.presented, rt)
			if f.spent[rt] {
				f.ended = true
			}
			if f.ended || rt != f.live {
				refuse("invalid_grant")
				return
			}
			f.spent[rt] = true
		default:
			refuse("unsupported_grant_type")
			return
		}
		f.issued++
		f.live, f.access = fmt.Sprintf("rt-%d", f.issued), fmt.Sprintf("at-%d", f.issued)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": f.access, "token_type": "Bearer",
			"expires_in": 3600, "refresh_token": f.live})
	})
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.bearers = append(f.bearers, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer "+f.access {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /Users", func(w http.ResponseWriter, r *http.Request) {
		if authorized(w, r) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": fmt.Sprintf("u-%d", time.Now().UnixNano())})
		}
	})
	mux.HandleFunc("GET /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if authorized(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("id")})
		}
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

// signIn is the person at the target: they open the authorization URL, agree, and
// are sent back with a code and the state.
func (f *codeTarget) signIn(t *testing.T, authorizationURL string) url.Values {
	t.Helper()
	hc := f.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil {
		t.Fatalf("the authorization endpoint answered %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	return back.Query()
}

func addCodeTarget(t *testing.T, s *Server, org string, f *codeTarget) {
	t.Helper()
	if err := provision.AddTarget(context.Background(), s.db, s.root, org, provision.TargetSpec{Slug: "billing",
		BaseURL: f.URL, Token: "the secret", OAuthTokenURL: f.URL + "/token", OAuthClientID: "our client",
		OAuthScope: "scim.write", OAuthAuthorizeURL: f.URL + "/authorize"}); err != nil {
		t.Fatal(err)
	}
}

func heldRefreshToken(t *testing.T, s *Server, org string) string {
	t.Helper()
	var sealed []byte
	if err := s.db.QueryRow(context.Background(), `SELECT oauth_refresh_token FROM core.scim_targets
		WHERE org_id = $1::uuid AND slug = 'billing'`, org).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if sealed == nil {
		return ""
	}
	plain, err := s.root.Open(sealed, "scim_refresh_token")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), string(plain)) {
		t.Errorf("the refresh token is held in the clear")
	}
	return string(plain)
}

func newPerson(t *testing.T, s *Server, org, name string) {
	t.Helper()
	var person string
	if err := s.db.QueryRow(context.Background(), `INSERT INTO core.users (org_id, username, email, status, user_handle)
		VALUES ($1::uuid, $2, $2 || '@example.test', 'active', decode(md5(random()::text) || md5(random()::text) ||
		        md5(random()::text) || md5(random()::text), 'hex')) RETURNING id::text`, org, name).Scan(&person); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, person) })
}

// From registration to a sync that renews its own grant (7.14): nothing syncs until
// somebody signs in at the target, the code their sign-in sends back is redeemed
// once, with the verifier whose challenge went with it, and every sync asks with the
// refresh token the last one left.
func TestATargetIsAuthorizedOnceAndEachSyncRenewsItsGrant(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	f := newCodeTarget(t)
	s.targetClient = func() (*http.Client, error) { return f.Client(), nil }
	base := "/admin/organizations/" + org + "/scim-targets"

	for name, body := range map[string]map[string]any{
		"an authorization URL with no token URL": {"oauth_authorize_url": "https://signin.example.test/authorize"},
		"a plain authorization URL": {"oauth_token_url": "https://auth.example.test/token", "oauth_client_id": "c",
			"oauth_authorize_url": "http://signin.example.test/authorize"},
	} {
		req := map[string]any{"slug": "bad", "base_url": "https://scim.example.test/v2", "token": "t"}
		for k, v := range body {
			req[k] = v
		}
		if rec := call(t, s, http.MethodPost, base, testToken, req); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d %s", name, rec.Code, rec.Body.String())
		}
	}
	addCodeTarget(t, s, org, f)
	newPerson(t, s, org, "ada")
	if list := call(t, s, http.MethodGet, base, testToken, nil).Body.String(); !strings.Contains(list,
		`"oauth_grant":"authorization_code"`) || !strings.Contains(list, `"oauth_authorized_at":null`) {
		t.Errorf("the target reads %s", list)
	}

	// Nobody has signed in, so a sync has no token, asks for none, and says why
	// each account was not made.
	if rec := call(t, s, http.MethodPost, base+"/billing/sync", testToken, map[string]any{"apply": true}); !strings.Contains(
		rec.Body.String(), `"failed":1`) || !strings.Contains(rec.Body.String(), "nobody has authorized") {
		t.Errorf("an unauthorized sync answered %d %s", rec.Code, rec.Body.String())
	}
	f.mu.Lock()
	if f.issued != 0 {
		t.Errorf("an unauthorized sync was issued %d tokens", f.issued)
	}
	f.mu.Unlock()

	if rec := call(t, s, http.MethodPost, base+"/billing/authorization", testToken,
		map[string]any{"redirect_uri": "http://localhost:5123/callback"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a redirect to localhost by name answered %d %s", rec.Code, rec.Body.String())
	}
	const redirect = "https://console.example.test/scim/callback"
	rec := call(t, s, http.MethodPost, base+"/billing/authorization", testToken, map[string]any{"redirect_uri": redirect})
	var started struct {
		URL   string `json:"authorization_url"`
		State string `json:"state"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &started) != nil || started.State == "" {
		t.Fatalf("starting: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(started.URL, f.URL+"/authorize?") {
		t.Errorf("the person is sent to %s", started.URL)
	}
	var stateHash, verifier []byte
	if err := s.db.QueryRow(ctx, `SELECT oauth_pending_state, oauth_pending_verifier FROM core.scim_targets
		WHERE org_id = $1::uuid AND slug = 'billing'`, org).Scan(&stateHash, &verifier); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateHash), started.State) || strings.Contains(started.URL, string(verifier)) {
		t.Error("the state or the verifier is held as it travels")
	}

	back := f.signIn(t, started.URL)
	if back.Get("state") != started.State {
		t.Fatalf("came back with %v", back)
	}
	finish := func(state, code string) *httptest.ResponseRecorder {
		return call(t, s, http.MethodPost, base+"/billing/authorization/code", testToken,
			map[string]any{"state": state, "code": code})
	}
	// Somebody else's state leaves this authorization waiting.
	if rec := finish("not-the-state", back.Get("code")); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "authorization_unknown") {
		t.Errorf("another state answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := finish(started.State, back.Get("code")); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "authorized_at") {
		t.Fatalf("finishing: %d %s", rec.Code, rec.Body.String())
	}
	// Spent: a second answer with it reaches no token endpoint.
	if rec := finish(started.State, back.Get("code")); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "authorization_unknown") {
		t.Errorf("the state answered twice: %d %s", rec.Code, rec.Body.String())
	}
	if got := heldRefreshToken(t, s, org); got != "rt-1" {
		t.Errorf("held %q after the sign-in", got)
	}

	// Somebody joins between the two, so the second has an account to make.
	for _, joining := range []string{"", "grace"} {
		if joining != "" {
			newPerson(t, s, org, joining)
		}
		if rec := call(t, s, http.MethodPost, base+"/billing/sync", testToken, map[string]any{"apply": true}); rec.Code !=
			http.StatusOK || !strings.Contains(rec.Body.String(), `"created":1`) {
			t.Fatalf("syncing: %d %s", rec.Code, rec.Body.String())
		}
	}
	f.mu.Lock()
	presented, ended, bearers := strings.Join(f.presented, ","), f.ended, f.bearers
	f.mu.Unlock()
	if presented != "rt-1,rt-2" || ended {
		t.Errorf("the token endpoint was shown %s (grant ended: %v)", presented, ended)
	}
	if len(bearers) == 0 || bearers[0] != "Bearer at-2" {
		t.Errorf("the target was sent %v", bearers)
	}
	if got := heldRefreshToken(t, s, org); got != "rt-3" {
		t.Errorf("held %q after two syncs", got)
	}
	if list := call(t, s, http.MethodGet, base, testToken, nil).Body.String(); strings.Contains(list,
		`"oauth_authorized_at":null`) || strings.Contains(list, "rt-") {
		t.Errorf("the target reads %s", list)
	}

	// Neither the state nor the token is in the trail.
	rows, err := s.db.Query(ctx, `SELECT event_type, detail::text FROM core.audit_events
		WHERE org_id = $1::uuid AND event_type LIKE 'admin.scim_target_authori%'`, org)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for rows.Next() {
		var kind, detail string
		if err := rows.Scan(&kind, &detail); err != nil {
			t.Fatal(err)
		}
		kinds[kind] = true
		if strings.Contains(detail, started.State) || strings.Contains(detail, "rt-") {
			t.Errorf("%s recorded %s", kind, detail)
		}
	}
	rows.Close()
	if !kinds["admin.scim_target_authorization_started"] || !kinds["admin.scim_target_authorized"] {
		t.Errorf("recorded %v", kinds)
	}
}

// newDriftCodeTarget is an organisation with a target that takes the authorization
// code grant, its fake as the server's way to reach targets.
func newDriftCodeTarget(t *testing.T, s *Server) string {
	t.Helper()
	org := newDriftMigrationOrg(t, s, false)
	f := newCodeTarget(t)
	s.targetClient = func() (*http.Client, error) { return f.Client(), nil }
	addCodeTarget(t, s, org, f)
	return org
}

// signedInAtTheTarget starts an authorization of the target path names and signs
// in for it, answering the body that finishes it.
func signedInAtTheTarget(t *testing.T, s *Server, path string) string {
	t.Helper()
	org := strings.Split(path, "/")[3]
	started, err := provision.BeginAuthorization(context.Background(), s.db, s.root, org, "billing",
		"http://127.0.0.1:5123/callback")
	if err != nil {
		t.Fatal(err)
	}
	trusting, err := s.targetClient()
	if err != nil {
		t.Fatal(err)
	}
	hc := *trusting
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(started.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || back.Query().Get("code") == "" {
		t.Fatalf("signing in answered %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	body, _ := json.Marshal(map[string]string{"state": started.State, "code": back.Query().Get("code")})
	return string(body)
}

// authorize takes a target through a sign-in with the steps the routes use.
func authorize(t *testing.T, s *Server, org string, f *codeTarget) {
	t.Helper()
	ctx := context.Background()
	started, err := provision.BeginAuthorization(ctx, s.db, s.root, org, "billing", "http://127.0.0.1:5123/callback")
	if err != nil {
		t.Fatal(err)
	}
	back := f.signIn(t, started.URL)
	grant, err := provision.ExchangeAuthorization(ctx, s.db, s.root, f.Client(), org, "billing", started.State,
		back.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grant.Keep(ctx, s.db); err != nil {
		t.Fatal(err)
	}
}

// Two passes at once never spend one refresh token: the second waits for the first
// to keep the one it was given, rather than presenting the one it spent, which an
// authorization server that rotates them takes as a theft and ends the grant over.
func TestTwoPassesAtOnceNeverSpendOneRefreshToken(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	f := newCodeTarget(t)
	addCodeTarget(t, s, org, f)
	authorize(t, s, org, f)
	f.mu.Lock()
	f.delay = 300 * time.Millisecond
	f.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			targets, err := store.LoadSCIMTargets(ctx, s.db, s.root, org, "billing")
			if err == nil && len(targets) != 1 {
				err = fmt.Errorf("loaded %d targets", len(targets))
			}
			if err == nil {
				_, err = scim.NewClient(targets[0], f.Client()).GetUser(ctx, "u-1")
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	f.mu.Lock()
	presented, ended := strings.Join(f.presented, ","), f.ended
	f.mu.Unlock()
	if errs[0] != nil || errs[1] != nil || ended || presented != "rt-1,rt-2" {
		t.Errorf("passes failed with %v and %v; the token endpoint was shown %s (grant ended: %v)",
			errs[0], errs[1], presented, ended)
	}
}

// An authorization past its time redeems nothing, even with its own state, and a
// new one replaces one still waiting.
func TestAnAuthorizationLastsItsTimeAndOnlyTheLatestCounts(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	f := newCodeTarget(t)
	addCodeTarget(t, s, org, f)
	redeem := func(state, code string) error {
		_, err := provision.ExchangeAuthorization(ctx, s.db, s.root, f.Client(), org, "billing", state, code)
		return err
	}

	first, err := provision.BeginAuthorization(ctx, s.db, s.root, org, "billing", "http://127.0.0.1:5123/callback")
	if err != nil {
		t.Fatal(err)
	}
	firstBack := f.signIn(t, first.URL)
	second, err := provision.BeginAuthorization(ctx, s.db, s.root, org, "billing", "http://127.0.0.1:5123/callback")
	if err != nil {
		t.Fatal(err)
	}
	if err := redeem(first.State, firstBack.Get("code")); !errors.Is(err, store.ErrSCIMAuthorizationUnknown) {
		t.Errorf("a replaced authorization answered %v", err)
	}

	back := f.signIn(t, second.URL)
	if _, err := s.db.Exec(ctx, `UPDATE core.scim_targets SET oauth_pending_until = now() - interval '1 second'
		WHERE org_id = $1::uuid AND slug = 'billing'`, org); err != nil {
		t.Fatal(err)
	}
	if err := redeem(second.State, back.Get("code")); !errors.Is(err, store.ErrSCIMAuthorizationUnknown) {
		t.Errorf("an expired authorization answered %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issued != 0 {
		t.Errorf("%d tokens were issued for authorizations that had ended", f.issued)
	}
}

// A new grant or base URL forgets what a sign-in left, since somebody agreed to the
// old one; a new secret alone does not, since the grant is the client's. A grant
// that changes while somebody signs in leaves nothing kept.
func TestANewGrantForgetsTheAuthorization(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	f := newCodeTarget(t)
	addCodeTarget(t, s, org, f)
	authorize(t, s, org, f)
	// A new grant's token URL is held to the dialler's rules, and the fake is on loopback.
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.AllowPrivate("") })

	secret := "the secret"
	if err := provision.UpdateTarget(ctx, s.db, s.root, org, "billing", "scim",
		provision.TargetChange{Token: &secret}); err != nil {
		t.Fatal(err)
	}
	if heldRefreshToken(t, s, org) == "" {
		t.Error("a new secret forgot the authorization")
	}
	grant := provision.TargetOAuth{TokenURL: f.URL + "/token", ClientID: "our client", Scope: "scim.read",
		AuthorizeURL: f.URL + "/authorize"}
	if err := provision.UpdateTarget(ctx, s.db, s.root, org, "billing", "scim",
		provision.TargetChange{Token: &secret, OAuth: &grant}); err != nil {
		t.Fatal(err)
	}
	if got := heldRefreshToken(t, s, org); got != "" {
		t.Errorf("a new scope kept %q", got)
	}
	targets, err := store.LoadSCIMTargets(ctx, s.db, s.root, org, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scim.NewClient(targets[0], f.Client()).GetUser(ctx, "u-1"); !errors.Is(err, scim.ErrNotAuthorized) {
		t.Errorf("a forgotten authorization answered %v", err)
	}

	authorize(t, s, org, f)
	base := "https://scim.example.test/v2"
	if err := provision.UpdateTarget(ctx, s.db, s.root, org, "billing", "scim",
		provision.TargetChange{Token: &secret, BaseURL: &base}); err != nil {
		t.Fatal(err)
	}
	if got := heldRefreshToken(t, s, org); got != "" {
		t.Errorf("a new base URL kept %q", got)
	}

	// The grant changes between the code's redemption and its keeping.
	started, err := provision.BeginAuthorization(ctx, s.db, s.root, org, "billing", "http://127.0.0.1:5123/callback")
	if err != nil {
		t.Fatal(err)
	}
	back := f.signIn(t, started.URL)
	redeemed, err := provision.ExchangeAuthorization(ctx, s.db, s.root, f.Client(), org, "billing", started.State,
		back.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	grant.ClientID = "another client"
	if err := provision.UpdateTarget(ctx, s.db, s.root, org, "billing", "scim",
		provision.TargetChange{Token: &secret, OAuth: &grant}); err != nil {
		t.Fatal(err)
	}
	if _, err := redeemed.Keep(ctx, s.db); !errors.Is(err, store.ErrSCIMGrantChanged) {
		t.Errorf("a grant changed meanwhile kept the token: %v", err)
	}
	if got := heldRefreshToken(t, s, org); got != "" {
		t.Errorf("held %q for a grant nobody agreed to", got)
	}
}
