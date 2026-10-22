package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/passwords"
)

// Two instances served by one process (6.12), each its own issuer behind its
// own host with its own keys, refuse each other: a token, a client, a session
// and an account of one are nothing at the other, and a name both hold signs in
// to each at its own host.

// servedAs gives a fixture a server of its own instance: that instance's issuer,
// fresh keys, and its id, as `signari serve` builds one for each.
func servedAs(t *testing.T, f *signInFixture) string {
	t.Helper()
	var instanceID, issuer string
	if err := f.pool.QueryRow(context.Background(), `SELECT i.id::text, i.issuer
		FROM core.organizations o JOIN core.instances i ON i.id = o.instance_id
		WHERE o.id = $1::uuid`, f.orgID).Scan(&instanceID, &issuer); err != nil {
		t.Fatal(err)
	}
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(oidc.Config{Issuer: issuer, Keys: set, AllowInsecureIssuer: true},
		f.pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetInstance(instanceID)
	f.srv = srv
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET first_party = true WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	return issuer
}

// at is the fixture's people, clients and sessions, asked of another server.
func (f *signInFixture) at(other *signInFixture) *signInFixture {
	c := *f
	c.srv = other.srv
	return &c
}

// accessToken signs in at the fixture's own server and redeems a code there.
func (f *signInFixture) accessToken(t *testing.T) string {
	t.Helper()
	cookie := f.signInAndReturnCookie(t)
	rec := f.authorizePlain(t, cookie)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("the authorization at its own instance answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, req)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil || body.AccessToken == "" {
		t.Fatalf("the redemption at its own instance answered %d: %s", out.Code, truncate(out.Body.String(), 200))
	}
	return body.AccessToken
}

func TestTwoInstancesOnOneProcessRefuseEachOther(t *testing.T) {
	a, b := newSignInFixture(t), newSignInFixture(t)
	issuerA, issuerB := servedAs(t, a), servedAs(t, b)
	ctx := context.Background()

	router, err := HostRouter([]*Server{a.srv, b.srv}, []http.Handler{a.srv.Routes(), b.srv.Routes()})
	if err != nil {
		t.Fatal(err)
	}
	via := func(host, method, path, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Host = host
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	hostOf := func(issuer string) string { u, _ := url.Parse(issuer); return u.Host }

	// Each host is its own issuer, and a host neither names is the first's.
	for host, want := range map[string]string{
		hostOf(issuerA): issuerA, strings.ToUpper(hostOf(issuerB)) + ":443": issuerB,
		"nobody.example": issuerA,
	} {
		rec := via(host, http.MethodGet, oidc.PathDiscovery, "")
		var md struct{ Issuer string }
		if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil || md.Issuer != want {
			t.Errorf("discovery at %s named %q, want %q (%d)", host, md.Issuer, want, rec.Code)
		}
	}

	// A token one signs is refused by the other.
	token := a.accessToken(t)
	if rec := via(hostOf(issuerA), http.MethodGet, oidc.PathUserinfo, token); rec.Code != http.StatusOK {
		t.Fatalf("its own instance's userinfo refused the token: %d %s", rec.Code, truncate(rec.Body.String(), 160))
	}
	if rec := via(hostOf(issuerB), http.MethodGet, oidc.PathUserinfo, token); rec.Code != http.StatusUnauthorized {
		t.Errorf("another instance's userinfo answered %d to the token", rec.Code)
	}

	// Its client is unknown there, and its session is no session.
	if rec := a.at(b).authorizePlain(t, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("another instance's client was answered %d %q at /authorize", rec.Code, rec.Header().Get("Location"))
	}
	cookie := a.signInAndReturnCookie(t)
	if code := a.accountPage(t, cookie); code != http.StatusOK {
		t.Fatalf("its own instance's account page answered %d", code)
	}
	if code := a.at(b).accountPage(t, cookie); code == http.StatusOK {
		t.Error("another instance's session opened the account page")
	}

	// A bare sign-in page belongs to the only organisation of its instance,
	// whatever other instances hold.
	if got := a.srv.loginOrg(ctx, ""); got != a.orgID {
		t.Errorf("a bare sign-in page of a one-organisation instance belongs to %q, want %q", got, a.orgID)
	}

	// A name held in both signs in to each at its own host, and with the
	// other's password to neither: counted across instances, it was held by
	// two accounts here and refused as ambiguous at both. With a second
	// organisation, so the page names none and the name is looked up across
	// the instance's.
	var second string
	if err := a.pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'x' || substr(gen_random_uuid()::text, 1, 8), 'Second' FROM core.organizations
		 WHERE id = $1::uuid RETURNING id::text`, a.orgID).Scan(&second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = a.pool.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, second)
	})
	if got := a.srv.loginOrg(ctx, ""); got != "" {
		t.Fatalf("a bare sign-in page of a two-organisation instance belongs to %q", got)
	}
	if _, err := b.pool.Exec(ctx, `UPDATE core.users SET email = $2 WHERE id = $1::uuid`,
		b.userID, a.email); err != nil {
		t.Fatal(err)
	}
	b.email = a.email
	hash, err := passwords.NewHasher(passwords.MemoryBudgetMiB).Hash(ctx, "b-instance-own-password-612")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.pool.Exec(ctx, `UPDATE core.password_credentials SET hash = $2 WHERE user_id = $1::uuid`,
		b.userID, hash); err != nil {
		t.Fatal(err)
	}
	clearSignInBucket(t, a.pool)
	if c := cookieFrom(a.signInWith(t, ""), SessionCookieName); c == nil {
		t.Error("a name another instance also holds did not sign in at its own")
	}
	if c := cookieFrom(a.at(b).signInWith(t, ""), SessionCookieName); c != nil {
		t.Error("an account's password signed in at another instance, where the name is somebody else's")
	}
}

// The last check, where every way in ends: an account of another instance that
// a lookup found anyway is not given a session, and the refusal says why.
func TestASignInOfAnotherInstancesAccountIsRefusedWhereItCompletes(t *testing.T) {
	a, b := newSignInFixture(t), newSignInFixture(t)
	servedAs(t, a)
	servedAs(t, b)
	ctx := context.Background()

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	a.srv.completeSignIn(rec, req, tx, b.userID, b.orgID, []string{"pwd"}, "")
	if c := cookieFrom(rec, SessionCookieName); c != nil {
		t.Fatal("another instance's account was given a session")
	}
	var reason string
	if err := a.pool.QueryRow(ctx, `SELECT detail->>'reason' FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'login.failed' ORDER BY occurred_at DESC LIMIT 1`,
		b.userID).Scan(&reason); err != nil || reason != "account_other_instance" {
		t.Errorf("the refusal was recorded as %q (%v)", reason, err)
	}
}

func TestTheHostRouterRefusesTwoInstancesOnOneHost(t *testing.T) {
	mk := func(issuer string) *Server { return &Server{cfg: oidc.Config{Issuer: issuer}} }
	h := http.NotFoundHandler()
	if _, err := HostRouter([]*Server{mk("https://id.example"), mk("https://ID.example:443")},
		[]http.Handler{h, h}); err == nil {
		t.Error("two instances on one host were accepted: a request could reach only one of them")
	}
	if _, err := HostRouter([]*Server{mk("https://a.example"), mk("https://b.example")},
		[]http.Handler{h, h}); err != nil {
		t.Errorf("two hosts were refused: %v", err)
	}
}
