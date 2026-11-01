package httpapi

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// wsfed asks the endpoint as a browser does, with the person's session or with none.
func (rf *realmFixture) wsfed(method string, q url.Values, signedIn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/wsfed?"+q.Encode(), nil)
	if method == http.MethodPost {
		r = httptest.NewRequest(http.MethodPost, "/wsfed", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if signedIn {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	}
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

// wsfedAsk is a sign-in to the fixture's own realm, with more on it.
func (rf *realmFixture) wsfedAsk(extra url.Values) url.Values {
	q := url.Values{"wa": {"wsignin1.0"}, "wtrealm": {rf.own}}
	for name, given := range extra {
		q[name] = given
	}
	return q
}

var wresultField = regexp.MustCompile(`name="wresult" value="([^"]*)"`)

// wsfedToken is the answer an application receives, read as a document.
func wsfedToken(t *testing.T, rec *httptest.ResponseRecorder) *etree.Element {
	t.Helper()
	m := wresultField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no token in a %d answer: %.300s", rec.Code, rec.Body.String())
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(html.UnescapeString(m[1])); err != nil {
		t.Fatal(err)
	}
	return doc.Root()
}

// wsfedParked is the request a sign-in comes back to, from where it was sent.
func wsfedParked(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(location, "/login?authz=") {
		t.Fatalf("not sent to sign in: %d %q", rec.Code, location)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	dest, ok := parkedReturn(u.Query().Get("authz"))
	if !ok || !strings.HasPrefix(dest, "/wsfed?") {
		t.Fatalf("parked %q", dest)
	}
	back, err := url.Parse(dest)
	if err != nil {
		t.Fatal(err)
	}
	return back.Query()
}

// An application's page posts its request, and the session cookie stays behind on a
// cross-site POST. Answered where it landed, it read as nobody signed in, and the body
// was not read at all.
func TestAWSFederationRequestMayArriveAsAForm(t *testing.T) {
	rf := newRealmFixture(t)
	asked := rf.wsfedAsk(url.Values{"wctx": {"rm=0&ru=/home"}, "wreply": {"https://sp.test/acs"}})

	for _, signedIn := range []bool{false, true} {
		rec := rf.wsfed(http.MethodPost, asked, signedIn)
		u, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || rec.Code != http.StatusSeeOther || u.Path != "/wsfed" {
			t.Fatalf("a form answered %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if got := u.Query().Encode(); got != asked.Encode() {
			t.Errorf("sent back as %s", got)
		}
		// Coming back as a GET, the browser brings the cookie, and it is a request
		// like any link's.
		if root := wsfedToken(t, rf.wsfed(http.MethodGet, u.Query(), true)); root.Tag != "RequestSecurityTokenResponse" {
			t.Errorf("the answer is %s", root.Tag)
		}
	}
	if rec := rf.wsfed(http.MethodGet, asked, true); !strings.Contains(html.UnescapeString(rec.Body.String()), "rm=0&ru=/home") {
		t.Errorf("wctx did not come back: %.300s", rec.Body.String())
	}
}

// What was checked has to be what is used.
func TestAWSFederationParameterIsGivenOnce(t *testing.T) {
	rf := newRealmFixture(t)
	before := rf.tokensIssued(t)
	asked := rf.wsfedAsk(nil)

	twice := rf.wsfedAsk(url.Values{"wreply": {"https://sp.test/acs", "https://attacker.test/"}})
	if rec := rf.wsfed(http.MethodPost, twice, true); rec.Code != http.StatusBadRequest {
		t.Errorf("twice in a form: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := rf.wsfed(http.MethodGet, twice, true); rec.Code != http.StatusBadRequest {
		t.Errorf("twice in a URL: %d", rec.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "/wsfed?"+url.Values{"wreply": {"https://sp.test/acs"}}.Encode(),
		strings.NewReader(rf.wsfedAsk(url.Values{"wreply": {"https://attacker.test/"}}).Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("in the URL and the body: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	if rec := rf.wsfed(http.MethodGet, asked, true); rec.Code != http.StatusOK {
		t.Fatalf("asked once: %d", rec.Code)
	}
	if got := rf.tokensIssued(t) - before; got != 1 {
		t.Errorf("%d tokens", got)
	}
}

// How long ago the person signed in, against what the application will take. A session
// that is too old goes to sign in, and comes back without the demand it has just met.
func TestAFreshnessDemandIsHeldToTheSignIn(t *testing.T) {
	rf := newRealmFixture(t)
	if _, err := rf.f.pool.Exec(context.Background(), `UPDATE core.sessions SET auth_time = now() - interval '2 hours'
		WHERE cookie_hash = $1`, store.HashToken(rf.cookie)); err != nil {
		t.Fatal(err)
	}
	ask := func(wfresh string) *httptest.ResponseRecorder {
		return rf.wsfed(http.MethodGet, rf.wsfedAsk(url.Values{"wfresh": {wfresh}}), true)
	}

	if root := wsfedToken(t, ask("180")); root == nil {
		t.Error("a sign-in within the limit was refused")
	}
	back := wsfedParked(t, ask("60"))
	if back.Has("wfresh") {
		t.Error("the demand came back with the request, and would ask again for ever")
	}
	if back.Get("wtrealm") != rf.own || back.Get("wa") != "wsignin1.0" {
		t.Errorf("came back as %v", back)
	}
	if root := wsfedToken(t, rf.wsfed(http.MethodGet, back, true)); root == nil {
		t.Error("the request did not finish on its return")
	}

	// 0 asks for a sign-in now, however recent the last.
	if _, err := rf.f.pool.Exec(context.Background(), `UPDATE core.sessions SET auth_time = now() WHERE cookie_hash = $1`,
		store.HashToken(rf.cookie)); err != nil {
		t.Fatal(err)
	}
	wsfedParked(t, ask("0"))

	for _, unreadable := range []string{"soon", "-1", "1.5", "99999999"} {
		if rec := ask(unreadable); rec.Code != http.StatusBadRequest {
			t.Errorf("wfresh=%s answered %d", unreadable, rec.Code)
		}
	}
}

// What the application asks of the sign-in, per request, as acr_values is: a password
// session must not answer a demand for a second factor because it was live.
func TestAnAuthenticationTypeIsHeldToTheSession(t *testing.T) {
	rf := newRealmFixture(t)
	ask := func(wauth string) *httptest.ResponseRecorder {
		return rf.wsfed(http.MethodGet, rf.wsfedAsk(url.Values{"wauth": {wauth}}), true)
	}
	if rec := ask("urn:nobody:offers:this"); rec.Code != http.StatusBadRequest {
		t.Errorf("a type nothing here offers answered %d", rec.Code)
	}
	if root := wsfedToken(t, ask("urn:oasis:names:tc:SAML:1.0:am:password")); root == nil {
		t.Error("a password session refused a password")
	}

	// Asking to sign in again would bring the same session back here for ever.
	if rec := ask(saml.AuthnContextMFA); rec.Code != http.StatusForbidden {
		t.Errorf("no factor to reach for answered %d %q", rec.Code, rec.Header().Get("Location"))
	}

	ctx := context.Background()
	if _, err := rf.f.pool.Exec(ctx, `INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`, rf.f.userID, rf.f.orgID); err != nil {
		t.Fatal(err)
	}
	rec := ask(saml.AuthnContextMFA)
	wsfedParked(t, rec)
	if !strings.Contains(rec.Header().Get("Location"), "acr_values") {
		t.Errorf("sent to sign in without saying a factor is wanted: %q", rec.Header().Get("Location"))
	}
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.sessions SET amr = ARRAY['pwd','otp','mfa'] WHERE cookie_hash = $1`,
		store.HashToken(rf.cookie)); err != nil {
		t.Fatal(err)
	}
	if root := wsfedToken(t, ask(saml.AuthnContextMFA)); root == nil {
		t.Error("a multi-factor session refused")
	}
}

// whr chooses a route and nothing else, and only among the realm's own organisation's
// providers. Named by slug, by the name the provider goes by, or by a domain it signs in.
func TestAHomeRealmChoosesTheProvider(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	suffix := fmt.Sprint(rf.own[strings.LastIndexByte(rf.own, ':')+1:])
	corp, upstream, off, foreign := "corp-"+suffix, "up-"+suffix, "off-"+suffix, "foreign-"+suffix
	var otherOrg string
	if err := rf.f.pool.QueryRow(ctx, `SELECT org_id::text FROM core.saml_providers WHERE entity_id = $1`, rf.foreign).
		Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		org, slug, issuer string
		enabled           bool
	}{{rf.f.orgID, corp, "https://corp.test/" + suffix, true}, {rf.f.orgID, off, "https://off.test/" + suffix, false},
		{otherOrg, foreign, "https://foreign.test/" + suffix, true}} {
		if _, err := rf.f.pool.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id,
			scopes, login_domains, issuer, enabled) VALUES ($1::uuid, $2, 'Corp', 'oidc', 'c', '{}', $3, $4, $5)`,
			p.org, p.slug, []string{p.slug + ".example"}, p.issuer, p.enabled); err != nil {
			t.Fatal(err)
		}
	}
	entity := "https://upstream.test/" + suffix
	if _, err := rf.f.pool.Exec(ctx, `WITH ip AS (
		  INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		  VALUES ($1::uuid, $2, 'Upstream', 'saml', '', '{}') RETURNING id)
		INSERT INTO core.saml_sources (provider_id, org_id, entity_id, sso_url, cert_pem)
		SELECT id, $1::uuid, $3, 'https://upstream.test/sso', 'pem' FROM ip`, rf.f.orgID, upstream, entity); err != nil {
		t.Fatal(err)
	}

	for whr, want := range map[string]string{
		corp:                             "/login/with/" + corp,
		"https://corp.test/" + suffix:    "/login/with/" + corp,
		corp + ".example":                "/login/with/" + corp,
		entity:                           "/saml/source/" + upstream + "/start",
		off:                              "/login",
		"https://off.test/" + suffix:     "/login",
		foreign:                          "/login",
		"https://foreign.test/" + suffix: "/login",
		foreign + ".example":             "/login",
		"nothing-here":                   "/login",
	} {
		rec := rf.wsfed(http.MethodGet, rf.wsfedAsk(url.Values{"whr": {whr}, "wfresh": {"5"}}), false)
		u, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || rec.Code != http.StatusSeeOther {
			t.Fatalf("whr=%s answered %d %q", whr, rec.Code, rec.Header().Get("Location"))
		}
		if u.Path != want {
			t.Errorf("whr=%s went to %s, not %s", whr, u.Path, want)
		}
		if want != "/login" {
			back, err := url.Parse(u.Query().Get("return"))
			if err != nil || back.Path != "/wsfed" || back.Query().Get("wtrealm") != rf.own {
				t.Errorf("whr=%s comes back to %q", whr, u.Query().Get("return"))
			}
			if back.Query().Has("whr") || back.Query().Has("wfresh") {
				t.Errorf("whr=%s comes back still asking: %q", whr, u.Query().Get("return"))
			}
		}
	}

	// A hint is for somebody who has to sign in. Somebody who has is answered.
	if root := wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(url.Values{"whr": {corp}}), true)); root == nil {
		t.Error("a live session was sent to a provider")
	}
}

// wsfedSignOut confirms a sign-out as a person does, on the page it is asked on.
func (rf *realmFixture) wsfedSignOut(t *testing.T, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	h := rf.f.srv.Routes()
	session := &http.Cookie{Name: SessionCookieName, Value: rf.cookie}
	page := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "/wsfed?"+q.Encode(), nil)
	get.AddCookie(session)
	h.ServeHTTP(page, get)
	action := regexp.MustCompile(`<form method="post" action="([^"]*)"`).FindStringSubmatch(page.Body.String())
	csrf := regexp.MustCompile(`name="` + csrfFormField + `" value="([^"]*)"`).FindStringSubmatch(page.Body.String())
	if action == nil || csrf == nil {
		t.Fatalf("no confirmation form: %d %.300s", page.Code, page.Body.String())
	}
	post := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]),
		strings.NewReader(url.Values{csrfFormField: {csrf[1]}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(session)
	for _, c := range page.Result().Cookies() {
		post.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, post)
	return rec
}

func (rf *realmFixture) sessionLive(t *testing.T) bool {
	t.Helper()
	_, live, err := store.ResolveSessionCookie(context.Background(), rf.f.pool, store.HashToken(rf.cookie), rf.f.srv.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	return live
}

// Where a sign-out lands is held to the same list a token is, because it is the same
// kind of link. One that fails is dropped and not refused: the person asked to sign
// out, and they are.
func TestAWSFederationSignOutLandsOnAReplyURL(t *testing.T) {
	rf := newRealmFixture(t)
	const reply = "https://sp.test/acs"
	// The same person's other browser holds the application, which says nothing of
	// the session signing out.
	wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true))

	cases := []struct {
		name string
		q    url.Values
		// tokenFirst gives the session the application the reply URL is of.
		tokenFirst bool
		landing    string
	}{
		{"the realm's own", url.Values{"wtrealm": {rf.own}, "wreply": {reply}}, false, reply},
		{"a URL the realm has not", url.Values{"wtrealm": {rf.own}, "wreply": {"https://attacker.test/"}}, false, ""},
		{"a realm nobody registered", url.Values{"wtrealm": {"urn:nobody"}, "wreply": {reply}}, false, ""},
		{"an application of this session", url.Values{"wreply": {reply}}, true, reply},
		{"an application this session never used", url.Values{"wreply": {reply}}, false, ""},
		{"a URL no application of this session has", url.Values{"wreply": {"https://attacker.test/"}}, true, ""},
		{"nowhere", url.Values{}, true, ""},
		// The OIDC parameter is not a way round any of this.
		{"the other protocol's parameter", url.Values{"post_logout_redirect_uri": {"https://attacker.test/"}}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rf.cookie = rf.f.signInAndReturnCookie(t)
			if c.tokenFirst {
				wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true))
			}
			q := url.Values{"wa": {"wsignout1.0"}}
			for name, given := range c.q {
				q[name] = given
			}
			rec := rf.wsfedSignOut(t, q)
			if got := rec.Header().Get("Location"); got != c.landing {
				t.Errorf("landed on %q: %d %.200s", got, rec.Code, rec.Body.String())
			}
			if rec.Code >= http.StatusBadRequest {
				t.Errorf("answered %d %.200s", rec.Code, rec.Body.String())
			}
			if rf.sessionLive(t) {
				t.Error("the person asked to sign out, and is still signed in")
			}
		})
	}
}

// An application's own form is a request to sign out and not the confirmation: without
// that, a page anywhere could end a session by posting to this endpoint.
func TestAnApplicationsFormDoesNotConfirmASignOut(t *testing.T) {
	rf := newRealmFixture(t)
	rec := rf.wsfed(http.MethodPost, url.Values{"wa": {"wsignout1.0"}}, true)
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || u.Path != "/wsfed" || u.Query().Get("wa") != "wsignout1.0" {
		t.Fatalf("answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !rf.sessionLive(t) {
		t.Error("a form ended the session")
	}
	if page := rf.wsfed(http.MethodGet, u.Query(), true); !strings.Contains(page.Body.String(), csrfFormField) {
		t.Errorf("the person was not asked: %d %.200s", page.Code, page.Body.String())
	}
	if !rf.sessionLive(t) {
		t.Error("asking ended the session")
	}
}

// A provider that has its Response signed and not its assertion is one choice among
// two. A WS-Federation answer has no Response, so the assertion went out signed by
// nothing.
func TestAWSFederationTokenIsSignedWhateverAResponseWouldBe(t *testing.T) {
	rf := newRealmFixture(t)
	if _, err := rf.f.pool.Exec(context.Background(), `UPDATE core.saml_providers
		SET sign_assertions = false, sign_responses = true WHERE entity_id = $1`, rf.own); err != nil {
		t.Fatal(err)
	}
	root := wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true))
	assertion := root.FindElement("RequestedSecurityToken/Assertion")
	if assertion == nil {
		t.Fatal("no assertion")
	}
	if assertion.SelectElement("Signature") == nil {
		t.Error("the token is signed by nothing")
	}
}

// One application moved to the older form, end to end, and the setting's limits.
func TestARealmCanTakeASAML11Token(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	providerID := rf.providerID(t, rf.own)
	set := func(org, id, version string) error {
		tx, err := rf.f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := store.SetSAMLWSFedVersion(ctx, tx, org, id, version); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	old := wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true))
	if got := old.SelectElement("TokenType").Text(); got != "urn:oasis:names:tc:SAML:2.0:assertion" {
		t.Errorf("the default says %q", got)
	}

	if err := set(rf.f.orgID, providerID, "3.0"); !errors.Is(err, store.ErrSAMLInvalid) {
		t.Errorf("a version there is none of: %v", err)
	}
	var otherOrg string
	if err := rf.f.pool.QueryRow(ctx, `SELECT org_id::text FROM core.saml_providers WHERE entity_id = $1`, rf.foreign).
		Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	if err := set(otherOrg, providerID, saml.WSFedSAML11); !errors.Is(err, store.ErrSAMLProviderUnknown) {
		t.Errorf("another organisation's provider: %v", err)
	}
	if err := set(rf.f.orgID, providerID, saml.WSFedSAML11); err != nil {
		t.Fatal(err)
	}

	root := wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true))
	if got := root.SelectElement("TokenType").Text(); !strings.HasSuffix(got, "#SAMLV1.1") {
		t.Errorf("the answer says %q", got)
	}
	assertion := root.FindElement("RequestedSecurityToken/Assertion")
	if assertion == nil {
		t.Fatal("no assertion")
	}
	if got := assertion.SelectAttrValue("xmlns:saml", ""); got != "urn:oasis:names:tc:SAML:1.0:assertion" {
		t.Errorf("the assertion is in %q", got)
	}
	if got := assertion.FindElement("Conditions/AudienceRestrictionCondition/Audience"); got == nil || got.Text() != rf.own {
		t.Errorf("the audience is %v", got)
	}
	if assertion.SelectElement("Signature") == nil {
		t.Error("the token is signed by nothing")
	}

	// SAML 2.0 at the same provider is not moved by this.
	if doc := rf.samlResponse(t); !strings.Contains(doc, "urn:oasis:names:tc:SAML:2.0:assertion") {
		t.Errorf("the provider's SAML changed: %.200s", doc)
	}

	// A certificate added afterwards cannot leave it going out in the clear.
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET sp_encryption_cert = 'pem' WHERE id = $1::uuid`,
		providerID); err != nil {
		t.Fatal(err)
	}
	if err := set(rf.f.orgID, providerID, saml.WSFedSAML11); !errors.Is(err, store.ErrSAMLInvalid) {
		t.Errorf("set with a certificate held: %v", err)
	}
	rec := rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true)
	if rec.Code != http.StatusInternalServerError || wresultField.MatchString(rec.Body.String()) {
		t.Errorf("answered %d: %.300s", rec.Code, rec.Body.String())
	}
}

// What an import reads, and that the key it pins is the one tokens are signed with.
func TestAWSFederationApplicationCanImportThisServer(t *testing.T) {
	rf := newRealmFixture(t)
	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}
	const path = "/FederationMetadata/2007-06/FederationMetadata.xml"
	rec := get(path)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/samlmetadata+xml") {
		t.Fatalf("answered %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(rec.Body.String()); err != nil {
		t.Fatal(err)
	}
	issuer := rf.f.srv.cfg.Issuer
	if got := doc.Root().SelectAttrValue("entityID", ""); got != issuer+"/saml" {
		t.Errorf("the entity is %q", got)
	}
	if got := doc.FindElement("//PassiveRequestorEndpoint/EndpointReference/Address"); got == nil || got.Text() != issuer+"/wsfed" {
		t.Errorf("requests go to %v", got)
	}

	root := wsfedToken(t, rf.wsfed(http.MethodGet, rf.wsfedAsk(nil), true))
	used := root.FindElement("RequestedSecurityToken/Assertion/Signature/KeyInfo/X509Data/X509Certificate")
	if used == nil {
		t.Fatal("the token names no certificate")
	}
	if got := root.FindElement("RequestedSecurityToken/Assertion/Issuer"); got == nil || got.Text() != issuer+"/saml" {
		t.Errorf("the token's issuer is %v, and an import will hold it to the entity", got)
	}
	var pinned bool
	for _, c := range doc.FindElements("//X509Certificate") {
		pinned = pinned || c.Text() == used.Text()
	}
	if !pinned {
		t.Error("the document does not carry the certificate tokens are signed with")
	}

	// A realm is named as /saml/metadata's sp is, and an unknown one says nothing of
	// which exist.
	if got := get(path + "?wtrealm=" + url.QueryEscape("urn:nobody")); got.Code != http.StatusOK || got.Body.String() != rec.Body.String() {
		t.Errorf("an unknown realm answered %d", got.Code)
	}
	ctx := context.Background()
	es, err := rf.f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rf.f.srv.cfg.Keys.Active(keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rf.f.pool.Exec(ctx, `INSERT INTO core.signing_keys (kid, instance_id, algorithm, state, public_jwk, key_ref)
		SELECT $1, instance_id, 'ES256', 'passive', '{}', 'test:in-memory'
		  FROM core.organizations WHERE id = $2::uuid`, es.KID(), rf.f.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := rf.f.pool.Exec(ctx, `UPDATE core.saml_providers SET signature_alg = 'ecdsa-sha256' WHERE entity_id = $1`,
		rf.own); err != nil {
		t.Fatal(err)
	}
	own := get(path + "?wtrealm=" + url.QueryEscape(rf.own))
	if certs := certificatesIn(t, own.Body.String()); !holdsKey(certs, es.Signer().Public()) || holdsKey(certs, rs.Signer().Public()) {
		t.Error("a realm signed with ES256 is not told the certificate it will see")
	}
	if certs := certificatesIn(t, get(path).Body.String()); !holdsKey(certs, rs.Signer().Public()) {
		t.Error("the default document moved")
	}
}
