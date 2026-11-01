package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/tokens"
)

// ownCookieHost is a protected application on a domain the issuer shares nothing with,
// and a browser that keeps cookies per address, as a browser does.
type ownCookieHost struct {
	pa   *proxyAuthz
	host string
	// session is the browser's sign-in at the issuer, jar what it holds at the application.
	session string
	jar     map[string]string
}

func newOwnCookieHost(t *testing.T) *ownCookieHost {
	t.Helper()
	pa := newProxyAuthz(t)
	if _, err := pa.f.pool.Exec(context.Background(), `UPDATE core.proxy_hosts SET own_cookie = true WHERE host = $1`, pa.own); err != nil {
		t.Fatal(err)
	}
	return &ownCookieHost{pa: pa, host: pa.own, session: pa.f.signInAndReturnCookie(t), jar: map[string]string{}}
}

// atApp is a request reaching this server through the application's proxy.
func (o *ownCookieHost) atApp(target string, jar map[string]string, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = "auth.internal"
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Proto", "https")
	for name, value := range jar {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	o.pa.f.srv.Routes().ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.Domain != "" {
			continue
		}
		if c.MaxAge < 0 {
			delete(jar, c.Name)
		} else {
			jar[c.Name] = c.Value
		}
	}
	return rec
}

// atIssuer is the browser at the issuer, signed in.
func (o *ownCookieHost) atIssuer(target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: o.session})
	rec := httptest.NewRecorder()
	o.pa.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// pathOf drops the scheme and host of an address on the application, as the proxy does.
func pathOf(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return u.RequestURI()
}

// startSignIn walks a browser from a page of the application to the callback, stopping
// at the link the issuer sends it to.
func (o *ownCookieHost) startSignIn(t *testing.T, jar map[string]string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", o.host)
	r.Header.Set("X-Forwarded-Uri", "/dashboard?tab=1")
	rec := httptest.NewRecorder()
	o.pa.f.srv.Routes().ServeHTTP(rec, r)
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(location, "https://"+o.host+pathProxyBegin+"?") {
		t.Fatalf("an unsigned browser was sent to %q: %d", location, rec.Code)
	}
	begin := o.atApp(pathOf(t, location), jar, o.host)
	if begin.Code != http.StatusSeeOther || jar[proxyStateCookie] == "" {
		t.Fatalf("begin answered %d, holding %v", begin.Code, jar)
	}
	start, err := url.Parse(begin.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	back := o.atIssuer(start.RequestURI())
	callback := back.Header().Get("Location")
	if back.Code != http.StatusSeeOther || !strings.HasPrefix(callback, "https://"+o.host+pathProxyCallback+"?code=") {
		t.Fatalf("the issuer answered %d %q: %.200s", back.Code, callback, back.Body.String())
	}
	for _, c := range back.Result().Cookies() {
		if c.Name == ProxyCookieName {
			t.Error("the issuer set a cookie the application will never be sent")
		}
	}
	return pathOf(t, callback)
}

// An application on no domain the issuer shares, from the first page to being let in.
func TestAnApplicationOnAnotherDomainKeepsACookieOfItsOwn(t *testing.T) {
	o := newOwnCookieHost(t)
	callback := o.startSignIn(t, o.jar)
	done := o.atApp(callback, o.jar, o.host)
	if done.Code != http.StatusSeeOther || done.Header().Get("Location") != "https://"+o.host+"/dashboard?tab=1" {
		t.Fatalf("the callback answered %d %q: %.200s", done.Code, done.Header().Get("Location"), done.Body.String())
	}
	var set *http.Cookie
	for _, c := range done.Result().Cookies() {
		if c.Name == ProxyCookieName {
			set = c
		}
	}
	if set == nil || set.Domain != "" || !set.Secure || !set.HttpOnly {
		t.Fatalf("the cookie is %+v", set)
	}
	if _, kept := o.jar[proxyStateCookie]; kept {
		t.Error("the state was left in the browser")
	}

	// The proxy asks with it, and the person is who they signed in as.
	verified := o.pa.verify(t, set.Value, o.host, "")
	if verified.Code != http.StatusOK || verified.Header().Get("X-Forwarded-User") != o.pa.f.userID {
		t.Fatalf("verify answered %d as %q", verified.Code, verified.Header().Get("X-Forwarded-User"))
	}

	// That cookie is that application's. Carried to another it says nothing.
	if rec := o.pa.verify(t, set.Value, o.pa.disabled, ""); rec.Code == http.StatusOK {
		t.Errorf("another host answered %d", rec.Code)
	}
	if _, err := o.pa.f.pool.Exec(context.Background(), `INSERT INTO core.proxy_hosts (org_id, host) VALUES ($1::uuid, $2)`,
		o.pa.f.orgID, "second-"+o.host); err != nil {
		t.Fatal(err)
	}
	rec := o.pa.verify(t, set.Value, "second-"+o.host, "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("X-Signari-Reason"), "another application") {
		t.Errorf("a host of the same organisation answered %d %q", rec.Code, rec.Header().Get("X-Signari-Reason"))
	}
}

// The attack the state exists for. Somebody signs in themselves, stops at the callback,
// and sends the link to somebody else, who would then be working in the application as
// them and telling it things.
func TestALinkToTheCallbackDoesNotSignAnybodyElseIn(t *testing.T) {
	o := newOwnCookieHost(t)
	link := o.startSignIn(t, map[string]string{})

	victim := map[string]string{}
	if rec := o.atApp(link, victim, o.host); rec.Code != http.StatusBadRequest {
		t.Fatalf("a browser that started nothing answered %d", rec.Code)
	}
	if _, set := victim[ProxyCookieName]; set {
		t.Error("it was given a cookie")
	}

	// Nor one that has started a sign-in of its own, with another state.
	o.startSignIn(t, victim)
	if rec := o.atApp(link, victim, o.host); rec.Code != http.StatusBadRequest {
		t.Fatalf("a browser mid-way through its own answered %d", rec.Code)
	}
	if _, set := victim[ProxyCookieName]; set {
		t.Error("it was given a cookie")
	}
}

// What the code is held to, each on its own.
func TestACodeIsGoodForOneApplicationOneMinuteAndALiveSession(t *testing.T) {
	o := newOwnCookieHost(t)
	jar := map[string]string{}
	callback := o.startSignIn(t, jar)

	// At another application of the same organisation it is nothing, though that one
	// keeps a cookie of its own too and the browser holds the state.
	if _, err := o.pa.f.pool.Exec(context.Background(), `INSERT INTO core.proxy_hosts (org_id, host, own_cookie) VALUES ($1::uuid, $2, true)`,
		o.pa.f.orgID, "second-"+o.host); err != nil {
		t.Fatal(err)
	}
	other := map[string]string{proxyStateCookie: jar[proxyStateCookie]}
	if rec := o.atApp(callback, other, "second-"+o.host); rec.Code != http.StatusBadRequest {
		t.Errorf("another application answered %d", rec.Code)
	}

	if rec := o.atApp("/.signari/proxy/callback?code=not-a-code", map[string]string{}, o.host); rec.Code != http.StatusBadRequest {
		t.Errorf("no code answered %d", rec.Code)
	}

	sign := func(c proxyCode) string {
		t.Helper()
		key, err := o.pa.f.srv.anySigningKey()
		if err != nil {
			t.Fatal(err)
		}
		tok, err := tokens.NewSigner(key).SignJSON(c, typProxyCode)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	code := proxyCode{Issuer: o.pa.f.srv.cfg.Issuer, Subject: o.pa.f.userID, SID: o.pa.sid, OrgID: o.pa.f.orgID, Host: o.host,
		State: "state", Target: "https://" + o.host + "/", Expiry: time.Now().Add(time.Minute).Unix()}
	state := map[string]string{proxyStateCookie: "state"}
	if rec := o.atApp(pathProxyCallback+"?code="+sign(code), state, o.host); rec.Code != http.StatusSeeOther {
		t.Fatalf("a good code answered %d %.200s", rec.Code, rec.Body.String())
	}

	expired := code
	expired.Expiry = time.Now().Add(-time.Minute).Unix()
	if rec := o.atApp(pathProxyCallback+"?code="+sign(expired), map[string]string{proxyStateCookie: "state"}, o.host); rec.Code != http.StatusBadRequest {
		t.Errorf("an expired code answered %d", rec.Code)
	}

	// A proxy token is not a code, though the same key signs both.
	if rec := o.atApp(pathProxyCallback+"?code="+o.pa.token(t, o.pa.f.orgID), map[string]string{proxyStateCookie: "state"}, o.host); rec.Code != http.StatusBadRequest {
		t.Errorf("a proxy token answered %d", rec.Code)
	}

	// Switched back to the shared cookie, the application no longer takes these.
	if _, err := o.pa.f.pool.Exec(context.Background(), `UPDATE core.proxy_hosts SET own_cookie = false WHERE host = $1`, o.host); err != nil {
		t.Fatal(err)
	}
	if rec := o.atApp(pathProxyCallback+"?code="+sign(code), map[string]string{proxyStateCookie: "state"}, o.host); rec.Code != http.StatusBadRequest {
		t.Errorf("a host no longer keeping its own answered %d", rec.Code)
	}
	if _, err := o.pa.f.pool.Exec(context.Background(), `UPDATE core.proxy_hosts SET own_cookie = true WHERE host = $1`, o.host); err != nil {
		t.Fatal(err)
	}

	if _, err := o.pa.f.pool.Exec(context.Background(), `UPDATE core.sessions SET revoked_at = now(), revocation_reason = 'admin_revoke' WHERE sid = $1`, o.pa.sid); err != nil {
		t.Fatal(err)
	}
	if rec := o.atApp(pathProxyCallback+"?code="+sign(code), map[string]string{proxyStateCookie: "state"}, o.host); rec.Code != http.StatusBadRequest {
		t.Errorf("a session that has ended answered %d", rec.Code)
	}
}

// Beginning is on the address it was asked on, and nowhere a link says.
func TestASignInBeginsOnlyForTheApplicationItIsAt(t *testing.T) {
	o := newOwnCookieHost(t)
	for name, rd := range map[string]string{
		"somewhere else": "https://attacker.test/",
		"nothing at all": "",
		"a path alone":   "/dashboard",
		"a similar name": "https://" + o.host + ".attacker.test/",
	} {
		jar := map[string]string{}
		rec := o.atApp(pathProxyBegin+"?rd="+url.QueryEscape(rd), jar, o.host)
		if rec.Code != http.StatusBadRequest || len(jar) != 0 {
			t.Errorf("%s answered %d %q, holding %v", name, rec.Code, rec.Header().Get("Location"), jar)
		}
	}
	// The issuer asks for the state a host like this cannot do without.
	rec := o.atIssuer("/proxy/start?rd=" + url.QueryEscape("https://"+o.host+"/"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a start with no state answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// A sign-in begun with nobody signed in at the issuer comes back with what it set out with.
func TestTheStateSurvivesSigningIn(t *testing.T) {
	o := newOwnCookieHost(t)
	r := httptest.NewRequest(http.MethodGet, "/proxy/start?rd="+url.QueryEscape("https://"+o.host+"/")+"&state=held", nil)
	rec := httptest.NewRecorder()
	o.pa.f.srv.Routes().ServeHTTP(rec, r)
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	dest, ok := parkedReturn(u.Query().Get("authz"))
	if !ok || !strings.Contains(dest, "state=held") {
		t.Errorf("parked as %q", dest)
	}
}

// A host with a parent of its own: the cookie is set for that, and a parent the issuer
// is not under would be refused by the browser, so it is refused here first.
func TestAHostCanHaveAParentDomainOfItsOwn(t *testing.T) {
	pa := newProxyAuthz(t)
	ctx := context.Background()
	session := pa.f.signInAndReturnCookie(t)
	pa.f.srv.cfg.Issuer = "https://auth.corp.example.test"
	pa.f.srv.cfg.ProxyCookieDomain = "elsewhere.test"
	host := "app." + pa.own + ".corp.example.test"
	if _, err := pa.f.pool.Exec(ctx, `UPDATE core.proxy_hosts SET host = $2, cookie_domain = 'corp.example.test' WHERE host = $1`,
		pa.own, host); err != nil {
		t.Fatal(err)
	}
	start := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/proxy/start?rd="+url.QueryEscape("https://"+host+"/"), nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
		rec := httptest.NewRecorder()
		pa.f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	rec := start()
	var domain string
	for _, c := range rec.Result().Cookies() {
		if c.Name == ProxyCookieName {
			domain = c.Domain
		}
	}
	if rec.Code != http.StatusSeeOther || domain != "corp.example.test" {
		t.Fatalf("answered %d with a cookie for %q: %.200s", rec.Code, domain, rec.Body.String())
	}

	// Under it the application is, and the issuer is not.
	narrow := strings.TrimPrefix(host, "app.")
	if _, err := pa.f.pool.Exec(ctx, `UPDATE core.proxy_hosts SET cookie_domain = $2 WHERE host = $1`, host, narrow); err != nil {
		t.Fatal(err)
	}
	if rec := start(); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "this issuer is not under") {
		t.Errorf("a parent the issuer is not under answered %d %.200s", rec.Code, rec.Body.String())
	}
}
