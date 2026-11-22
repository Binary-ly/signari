package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// brandedTenants is one hostname with an appearance of its own and two
// organisations on it: the fixture's, in its own colours, and a neighbour that set
// a logo and a name and left the colours to the instance.
type brandedTenants struct {
	f                  *signInFixture
	neighbour          string
	neighbourClient    string
	neighbourAuthz     string
	instance, own, its *brand.Brand
}

func newBrandedTenants(t *testing.T) *brandedTenants {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT i.id::text, i.issuer FROM core.instances i
		JOIN core.organizations o ON o.instance_id = i.id WHERE o.id = $1::uuid`, f.orgID).
		Scan(&instanceID, &f.srv.cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	b := &brandedTenants{f: f,
		instance: &brand.Brand{ProductName: "Hostname", Primary: "#112233", OnPrimary: "#ffffff",
			Background: "#fdfdfd", Text: "#202020"},
		own: &brand.Brand{ProductName: "Acme", LogoURL: "https://acme.example.test/logo.svg",
			Primary: "#aa0000", OnPrimary: "#ffffff", Background: "#fafafa", Text: "#101010"},
		its: &brand.Brand{ProductName: "Bravo", LogoURL: "https://bravo.example.test/logo.svg"},
	}
	if err := store.SaveBrand(ctx, f.pool, instanceID, b.instance); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1::uuid, 'n' || substr(gen_random_uuid()::text, 1, 8), 'Neighbour') RETURNING id::text`,
		instanceID).Scan(&b.neighbour); err != nil {
		t.Fatal(err)
	}
	b.neighbourClient = f.clientID + "-n"
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash,
		                          grant_types, scopes, require_pkce)
		VALUES ($1, $2::uuid, 'N', 'public', '', ARRAY['authorization_code'], ARRAY['openid'], true)`,
		b.neighbourClient, b.neighbour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)`,
		b.neighbourClient, "https://rp.test/cb"); err != nil {
		t.Fatal(err)
	}
	b.neighbourAuthz = strings.ReplaceAll(f.plainAuthz(), url.QueryEscape(f.clientID), url.QueryEscape(b.neighbourClient))
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, b.neighbourClient)
		_, _ = f.pool.Exec(c, `DELETE FROM core.organizations WHERE id = $1::uuid`, b.neighbour)
		_, _ = f.pool.Exec(c, `DELETE FROM core.brands WHERE instance_id = $1::uuid`, instanceID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.org_brands WHERE org_id = $1::uuid`, f.orgID)
	})
	if err := store.SaveOrgBrand(ctx, f.pool, f.orgID, b.own); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOrgBrand(ctx, f.pool, b.neighbour, b.its); err != nil {
		t.Fatal(err)
	}
	return b
}

// login is the sign-in page for an authorization query.
func (b *brandedTenants) login(t *testing.T, authz string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/login"
	if authz != "" {
		target += "?authz=" + url.QueryEscape(authz)
	}
	rec := httptest.NewRecorder()
	b.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the sign-in page answered %d", rec.Code)
	}
	return rec
}

// wears checks a page for a brand's name and colour. The built-in layout says a
// brand's name only as its logo's alternative text, so a brand with no logo is
// told by its colours and name is "".
func wears(t *testing.T, page *httptest.ResponseRecorder, what string, name, colour string) {
	t.Helper()
	body := page.Body.String()
	if name != "" && !strings.Contains(body, name) {
		t.Errorf("%s does not say %q", what, name)
	}
	if colour != "" && !strings.Contains(body, colour) {
		t.Errorf("%s is not in %s", what, colour)
	}
}

func TestTwoOrganisationsOnOneHostnameRenderDifferently(t *testing.T) {
	b := newBrandedTenants(t)

	own := b.login(t, b.f.plainAuthz())
	wears(t, own, "the fixture's page", "Acme", "#aa0000")
	if body := own.Body.String(); strings.Contains(body, "Bravo") || strings.Contains(body, "#112233") {
		t.Error("one organisation's page shows another's appearance")
	}

	// What the neighbour left out is the instance's, the four colours together.
	its := b.login(t, b.neighbourAuthz)
	wears(t, its, "the neighbour's page", "Bravo", "#112233")
	if body := its.Body.String(); strings.Contains(body, "Acme") || strings.Contains(body, "#aa0000") {
		t.Error("the neighbour's page shows the fixture's appearance")
	}
	if !strings.Contains(its.Body.String(), b.its.LogoURL) {
		t.Error("the neighbour's logo is not on its page")
	}
	if got := its.Header().Get("Content-Security-Policy"); !strings.Contains(got, "img-src https:") {
		t.Errorf("the page with a logo has a policy that blocks it: %s", got)
	}

	// Nobody has said who this is, and a guess shows one customer another's logo.
	bare := b.login(t, "")
	wears(t, bare, "a bare page", "", "#112233")
	if body := bare.Body.String(); strings.Contains(body, "Acme") || strings.Contains(body, "Bravo") ||
		strings.Contains(body, "#aa0000") {
		t.Error("a bare page guessed an organisation")
	}
	if got := bare.Header().Get("Content-Security-Policy"); strings.Contains(got, "img-src") {
		t.Errorf("a page with no logo was given one in its policy: %s", got)
	}

	// Taking the brand off is the instance's appearance on the next render.
	if _, err := store.RemoveOrgBrand(context.Background(), b.f.pool, b.f.orgID); err != nil {
		t.Fatal(err)
	}
	unbranded := b.login(t, b.f.plainAuthz())
	wears(t, unbranded, "the unbranded organisation's page", "", "#112233")
	if body := unbranded.Body.String(); strings.Contains(body, "Acme") || strings.Contains(body, "#aa0000") {
		t.Error("the unbranded organisation's page still wears its brand")
	}
}

func TestAPageKeepsItsOrganisationAllTheWayThrough(t *testing.T) {
	b := newBrandedTenants(t)
	f := b.f
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	giveTOTP(t, f)

	// The authorization request itself, which answers with the sign-in page.
	wears(t, f.authorizeWith(t, "", nil), "the page an authorization request answers with", "Acme", "#aa0000")

	form := b.login(t, f.plainAuthz())
	wears(t, form, "the sign-in page", "Acme", "#aa0000")

	// A wrong password goes back to the page it came from.
	wrong := url.Values{"username": {f.email}, "password": {"not the password"}, "authz": {f.plainAuthz()},
		csrfFormField: {csrfValue.FindStringSubmatch(form.Body.String())[1]}}
	post := func(values url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = testClientIP(t) + ":5555"
		for _, c := range cookies {
			r.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}
	wears(t, post(wrong, cookieFrom(form, CSRFCookieName)), "the page after a wrong password", "Acme", "#aa0000")

	// The code page, first from the form that carried the request, then from a
	// form that carries nothing but the half-finished sign-in.
	right := url.Values{"username": {f.email}, "password": {signInTestPassword}, "authz": {f.plainAuthz()},
		csrfFormField: wrong[csrfFormField]}
	code := post(right, cookieFrom(form, CSRFCookieName))
	wears(t, code, "the code page", "Acme", "#aa0000")
	wears(t, f.postCode(t, code, "000000"), "the code page after a wrong code", "Acme", "#aa0000")
}

func TestASignedInPageIsItsSessionsOrganisation(t *testing.T) {
	b := newBrandedTenants(t)
	f := b.f
	cookie := f.signInAndReturnCookie(t)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	account := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(account, req)
	if account.Code != http.StatusOK {
		t.Fatalf("the account page answered %d", account.Code)
	}
	wears(t, account, "the account page", "Acme", "#aa0000")

	// Following the neighbour's application is the neighbour's page, whoever
	// is signed in here.
	req = httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+b.neighbourAuthz, nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	there := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(there, req)
	wears(t, there, "the page of another organisation's application", "Bravo", "#112233")

	// And so is any page answering that request, not only the sign-in form.
	req = httptest.NewRequest(http.MethodGet, "/consent?authz="+url.QueryEscape(b.neighbourAuthz), nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	if got := f.srv.pageOrg(req); got != b.neighbour {
		t.Errorf("a page answering the neighbour's request is %q, want %q", got, b.neighbour)
	}
}

func TestMailWearsItsOrganisationsLook(t *testing.T) {
	b := newBrandedTenants(t)
	f := b.f
	ctx := context.Background()
	mailer := &captureMailer{}
	f.srv.mailer = mailer

	if err := f.srv.sendMailTo(ctx, f.userID, mail.Message{To: f.email, Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.sendMail(ctx, b.neighbour, mail.Message{To: "n@example.test", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	sent := mailer.messages()
	if got := sent[0].Look; got.Product != "Acme" || got.Link != "#aa0000" {
		t.Errorf("a person's message looks like %+v", got)
	}
	if got := sent[1].Look; got.Product != "Bravo" || got.Link != "#112233" {
		t.Errorf("the neighbour's message looks like %+v", got)
	}
}
