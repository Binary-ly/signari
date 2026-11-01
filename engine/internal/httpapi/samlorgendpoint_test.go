package httpapi

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// sharedProvider is one service provider two organisations hold: the first at the
// deployment's endpoints and the second, having registered it later, at its own.
type sharedProvider struct {
	rf          *realmFixture
	entity      string
	other       *signInFixture
	otherCookie string
	otherSlug   string
	otherACS    string
	// asks goes in a request, for one that asks for something.
	asks string
}

func newSharedProvider(t *testing.T) *sharedProvider {
	t.Helper()
	ctx := context.Background()
	rf := newRealmFixture(t)
	other := newSignInFixture(t)
	sp := &sharedProvider{rf: rf, entity: rf.own, other: other, otherACS: "https://sp.test/other/acs"}
	sp.otherCookie = other.signInAndReturnCookie(t)
	if err := rf.f.pool.QueryRow(ctx, `SELECT slug FROM core.organizations WHERE id = $1::uuid`, other.orgID).
		Scan(&sp.otherSlug); err != nil {
		t.Fatal(err)
	}
	tx, err := rf.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := store.AddSAMLProvider(ctx, tx, other.orgID, store.SAMLProviderSpec{EntityID: rf.own, Name: "SP", ACSURL: sp.otherACS})
	if err != nil {
		t.Fatal(err)
	}
	on, err := store.SAMLOnOrgEndpoint(ctx, tx, id)
	if err != nil || !on {
		t.Fatalf("a provider somebody else holds is not at its own endpoints: %v %v", on, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return sp
}

// signIn sends an AuthnRequest to a path, and answers with what came of it.
func (sp *sharedProvider) signIn(t *testing.T, path, destination, acs, cookie string) (int, string) {
	t.Helper()
	doc := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_org-%d" Version="2.0"
 IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer>%s</samlp:AuthnRequest>`,
		time.Now().UnixNano(), time.Now().UTC().Format(time.RFC3339), destination, acs, sp.entity, sp.asks)
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(doc))
	_ = w.Close()
	r := httptest.NewRequest(http.MethodGet, path+"?SAMLRequest="+url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())), nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	sp.rf.f.srv.Routes().ServeHTTP(rec, r)
	m := samlResponseField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		return rec.Code, rec.Header().Get("Location")
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return rec.Code, string(xml)
}

func issuerAndDestination(t *testing.T, raw string) (issuer, destination, audience string) {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatalf("%v: %.300s", err, raw)
	}
	root := doc.Root()
	if a := root.FindElement("//Audience"); a != nil {
		audience = a.Text()
	}
	return root.SelectElement("Issuer").Text(), root.SelectAttrValue("Destination", ""), audience
}

// Two organisations, one entity ID: each signs in its own people, at its own address,
// as its own issuer. What was once answered at random must not be answered across.
func TestTwoOrganisationsHoldOneServiceProvider(t *testing.T) {
	sp := newSharedProvider(t)
	issuer := sp.rf.f.srv.cfg.Issuer
	global, own := issuer+"/saml/sso", issuer+"/saml/org/"+sp.otherSlug+"/sso"
	orgPath := "/saml/org/" + sp.otherSlug + "/sso"
	firstSlug := ""
	if err := sp.rf.f.pool.QueryRow(context.Background(), `SELECT slug FROM core.organizations WHERE id = $1::uuid`,
		sp.rf.f.orgID).Scan(&firstSlug); err != nil {
		t.Fatal(err)
	}

	// The first, untouched: still where it was, as what it was.
	code, raw := sp.signIn(t, "/saml/sso", global, "https://sp.test/acs", sp.rf.cookie)
	if code != http.StatusOK {
		t.Fatalf("the first organisation answered %d %q", code, raw)
	}
	if who, to, _ := issuerAndDestination(t, raw); who != issuer+"/saml" || to != "https://sp.test/acs" {
		t.Errorf("it was answered as %q, to %q", who, to)
	}

	// The second, at its own.
	code, raw = sp.signIn(t, orgPath, own, sp.otherACS, sp.otherCookie)
	if code != http.StatusOK {
		t.Fatalf("the second organisation answered %d %q", code, raw)
	}
	who, to, audience := issuerAndDestination(t, raw)
	if who != issuer+"/saml/org/"+sp.otherSlug || to != sp.otherACS || audience != sp.entity {
		t.Errorf("it was answered as %q, to %q, for %q", who, to, audience)
	}
	if !strings.Contains(raw, "<ds:Signature") {
		t.Error("no signature")
	}

	for name, c := range map[string]struct{ path, destination, acs, cookie string }{
		"the second's person at the deployment's endpoints": {"/saml/sso", global, "https://sp.test/acs", sp.otherCookie},
		"the first's person at the second's endpoints":      {orgPath, own, sp.otherACS, sp.rf.cookie},
		"the first's reply URL at the second's endpoints":   {orgPath, own, "https://sp.test/acs", sp.otherCookie},
		"the second's reply URL at the deployment's":        {"/saml/sso", global, sp.otherACS, sp.rf.cookie},
		"a request for the deployment sent to the second":   {orgPath, global, sp.otherACS, sp.otherCookie},
		"an organisation that is not here":                  {"/saml/org/nobody/sso", own, sp.otherACS, sp.otherCookie},
		"the second's own request at the first's endpoints": {"/saml/org/" + firstSlug + "/sso", own, sp.otherACS, sp.otherCookie},
	} {
		if code, raw := sp.signIn(t, c.path, c.destination, c.acs, c.cookie); strings.Contains(raw, "AuthnStatement") {
			t.Errorf("%s was given an assertion: %d", name, code)
		}
	}

	// Somebody who has to sign in comes back to the path they came to.
	code, location := sp.signIn(t, orgPath, own, sp.otherACS, "")
	if code != http.StatusSeeOther || !strings.Contains(location, url.QueryEscape(url.QueryEscape(orgPath))) {
		t.Errorf("parked as %d %q", code, location)
	}
}

// A provider at one set of endpoints is nobody at the other, whichever organisation.
func TestAProviderAnswersAtOneSetOfEndpoints(t *testing.T) {
	sp := newSharedProvider(t)
	issuer := sp.rf.f.srv.cfg.Issuer
	ownSlug := ""
	ctx := context.Background()
	if err := sp.rf.f.pool.QueryRow(ctx, `SELECT slug FROM core.organizations WHERE id = $1::uuid`, sp.rf.f.orgID).Scan(&ownSlug); err != nil {
		t.Fatal(err)
	}
	if code, raw := sp.signIn(t, "/saml/org/"+ownSlug+"/sso", issuer+"/saml/org/"+ownSlug+"/sso", "https://sp.test/acs", sp.rf.cookie); strings.Contains(raw, "AuthnStatement") {
		t.Errorf("a provider of the deployment's endpoints was answered at its organisation's: %d", code)
	}

	// Moved, it is the other way round, and it is told so by who the assertion is from.
	id := sp.rf.providerID(t, sp.entity)
	if err := store.SetSAMLOrgEndpoint(ctx, sp.rf.f.pool, sp.other.orgID, id, true); !errors.Is(err, store.ErrSAMLProviderUnknown) {
		t.Errorf("moving another organisation's provider: %v", err)
	}
	if err := store.SetSAMLOrgEndpoint(ctx, sp.rf.f.pool, sp.rf.f.orgID, id, true); err != nil {
		t.Fatal(err)
	}
	if code, raw := sp.signIn(t, "/saml/sso", issuer+"/saml/sso", "https://sp.test/acs", sp.rf.cookie); strings.Contains(raw, "AuthnStatement") {
		t.Errorf("moved, it was still answered at the deployment's: %d", code)
	}
	code, raw := sp.signIn(t, "/saml/org/"+ownSlug+"/sso", issuer+"/saml/org/"+ownSlug+"/sso", "https://sp.test/acs", sp.rf.cookie)
	if code != http.StatusOK {
		t.Fatalf("moved, it answered %d %q", code, raw)
	}
	if who, _, _ := issuerAndDestination(t, raw); who != issuer+"/saml/org/"+ownSlug {
		t.Errorf("moved, it was answered as %q", who)
	}
}

// What a provider imports says the same as what it will be sent.
func TestAnOrganisationsMetadataNamesItsOwnEndpoints(t *testing.T) {
	sp := newSharedProvider(t)
	issuer := sp.rf.f.srv.cfg.Issuer
	base := issuer + "/saml/org/" + sp.otherSlug
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		sp.rf.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	rec := get("/saml/org/" + sp.otherSlug + "/metadata")
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d", rec.Code)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(rec.Body.String()); err != nil {
		t.Fatal(err)
	}
	if got := doc.Root().SelectAttrValue("entityID", ""); got != base {
		t.Errorf("the entity is %q", got)
	}
	for _, e := range doc.FindElements("//SingleSignOnService") {
		if e.SelectAttrValue("Location", "") != base+"/sso" {
			t.Errorf("sign-in goes to %q", e.SelectAttrValue("Location", ""))
		}
	}
	for _, e := range doc.FindElements("//SingleLogoutService") {
		if e.SelectAttrValue("Location", "") != base+"/slo" {
			t.Errorf("logout goes to %q", e.SelectAttrValue("Location", ""))
		}
	}
	if got := get("/saml/org/nobody/metadata"); got.Code != http.StatusNotFound {
		t.Errorf("an organisation that is not here answered %d", got.Code)
	}

	wsfed := get("/wsfed/org/" + sp.otherSlug + "/FederationMetadata.xml")
	if wsfed.Code != http.StatusOK || !strings.Contains(wsfed.Body.String(), issuer+"/wsfed/org/"+sp.otherSlug+"<") ||
		!strings.Contains(wsfed.Body.String(), `entityID="`+base+`"`) {
		t.Errorf("the WS-Federation document: %d %.300s", wsfed.Code, wsfed.Body.String())
	}
	if got := get("/wsfed/org/nobody/FederationMetadata.xml"); got.Code != http.StatusNotFound {
		t.Errorf("an organisation that is not here answered %d", got.Code)
	}
}

// The same application over WS-Federation, and where a sign-in comes back to.
func TestWSFederationAnswersAtAnOrganisationsEndpoint(t *testing.T) {
	sp := newSharedProvider(t)
	h := sp.rf.f.srv.Routes()
	ask := func(path string, q url.Values, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	path := "/wsfed/org/" + sp.otherSlug
	q := url.Values{"wa": {"wsignin1.0"}, "wtrealm": {sp.entity}}

	rec := ask(path, q, sp.otherCookie)
	assertion := wsfedToken(t, rec).FindElement("RequestedSecurityToken/Assertion")
	if assertion == nil {
		t.Fatal("no assertion")
	}
	if got := assertion.SelectElement("Issuer"); got == nil || got.Text() != sp.rf.f.srv.cfg.Issuer+"/saml/org/"+sp.otherSlug {
		t.Errorf("the token is from %v", got)
	}
	if !strings.Contains(html.UnescapeString(rec.Body.String()), sp.otherACS) {
		t.Errorf("it did not go to this organisation's reply URL: %.300s", rec.Body.String())
	}
	if rec := ask("/wsfed", q, sp.otherCookie); wresultField.MatchString(rec.Body.String()) {
		t.Error("a person of the second organisation was given a token at the deployment's endpoint")
	}
	if rec := ask(path, q, sp.rf.cookie); wresultField.MatchString(rec.Body.String()) {
		t.Error("a person of the first organisation was given a token at the second's")
	}
	if rec := ask("/wsfed/org/nobody", q, sp.otherCookie); rec.Code != http.StatusNotFound {
		t.Errorf("an organisation that is not here answered %d", rec.Code)
	}

	back := ask(path, url.Values{"wa": {"wsignin1.0"}, "wtrealm": {sp.entity}, "wfresh": {"0"}}, sp.otherCookie)
	u, err := url.Parse(back.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	dest, ok := parkedReturn(u.Query().Get("authz"))
	if !ok || !strings.HasPrefix(dest, path+"?") {
		t.Errorf("a sign-in comes back to %q", dest)
	}
}

// A logout goes out as who the provider knows us as, on either road.
func TestALogoutRequestIsFromWhoTheProviderKnows(t *testing.T) {
	sp := newSharedProvider(t)
	ctx := context.Background()
	id := sp.rf.providerID(t, sp.entity)
	var otherID string
	if err := sp.rf.f.pool.QueryRow(ctx, `SELECT id::text FROM core.saml_providers WHERE org_id = $1::uuid AND entity_id = $2`,
		sp.other.orgID, sp.entity).Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ provider, want string }{
		"the deployment's": {id, sp.rf.f.srv.cfg.Issuer + "/saml"},
		"its own":          {otherID, sp.rf.f.srv.cfg.Issuer + "/saml/org/" + sp.otherSlug},
	} {
		redirect, err := sp.rf.f.srv.logoutRedirectFor(ctx, store.LogoutStep{ProviderID: c.provider, EntityID: sp.entity,
			SLOURL: "https://sp.test/slo", NameID: "n", SessionIndex: "s"}, "token")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(redirect)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
		if err != nil {
			t.Fatal(err)
		}
		var doc bytes.Buffer
		if _, err := doc.ReadFrom(flate.NewReader(bytes.NewReader(raw))); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(doc.String(), c.want+"</saml:Issuer>") {
			t.Errorf("%s endpoints: the request is %.300s", name, doc.String())
		}
	}
}

// A service provider's own signed LogoutRequest, at the address and as the provider
// its organisation holds. Nothing in this package had sent one to either address.
func TestALogoutArrivesAtAnOrganisationsEndpoint(t *testing.T) {
	sp := newSharedProvider(t)
	ctx := context.Background()
	pool := sp.rf.f.pool
	issuer := sp.rf.f.srv.cfg.Issuer
	base := issuer + "/saml/org/" + sp.otherSlug

	pkcs8, certPEM, err := saml.NewSPKey("https://sp.test", saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	key, err := saml.ParseSPKey(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	const replyTo = "https://sp.test/other/slo"
	var providerID string
	if err := pool.QueryRow(ctx, `UPDATE core.saml_providers SET sp_signing_cert = $3 WHERE org_id = $1::uuid AND entity_id = $2
		RETURNING id::text`, sp.other.orgID, sp.entity, certPEM).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core.saml_slo_urls (provider_id, url, binding) VALUES ($1::uuid, $2, 'HTTP-Redirect')`,
		providerID, replyTo); err != nil {
		t.Fatal(err)
	}
	if code, raw := sp.signIn(t, "/saml/org/"+sp.otherSlug+"/sso", base+"/sso", sp.otherACS, sp.otherCookie); code != http.StatusOK {
		t.Fatalf("signing in: %d %q", code, raw)
	}
	var nameID, format, index string
	if err := pool.QueryRow(ctx, `SELECT name_id, COALESCE(name_id_format, ''), session_index FROM core.saml_session_participants
		WHERE provider_id = $1::uuid`, providerID).Scan(&nameID, &format, &index); err != nil {
		t.Fatal(err)
	}

	logout := func(path, destination string) *httptest.ResponseRecorder {
		t.Helper()
		doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: sp.entity, Destination: destination, NameID: nameID,
			NameIDFormat: format, SessionIndex: index, Now: time.Now()}, key, block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := saml.EncodeRedirect(doc)
		if err != nil {
			t.Fatal(err)
		}
		query, err := saml.SignRedirectQuery("SAMLRequest", encoded, "relay", key)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		sp.rf.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"?"+query, nil))
		return rec
	}
	live := func() bool {
		t.Helper()
		_, live, err := store.ResolveSessionCookie(ctx, pool, store.HashToken(sp.otherCookie), sp.rf.f.srv.instanceID)
		if err != nil {
			t.Fatal(err)
		}
		return live
	}

	// At the deployment's address the entity ID is the first organisation's provider,
	// whose key this is not; and a request for that address proves nothing here.
	logout("/saml/slo", issuer+"/saml/slo")
	logout("/saml/org/"+sp.otherSlug+"/slo", issuer+"/saml/slo")
	if !live() {
		t.Fatal("a logout not meant for this provider ended the session")
	}

	rec := logout("/saml/org/"+sp.otherSlug+"/slo", base+"/slo")
	if live() {
		t.Fatalf("the provider's own logout ended nothing: %d %.200s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(rec.Header().Get("Location"), replyTo) {
		t.Fatalf("answered %d %q", rec.Code, rec.Header().Get("Location"))
	}
	raw, err := saml.DecodeRedirect(u.Query().Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), base+"</saml:Issuer>") {
		t.Errorf("the response is from %.300s", raw)
	}
}

// A refusal comes from who the provider knows us as too.
func TestAStatusComesFromWhoTheProviderKnows(t *testing.T) {
	sp := newSharedProvider(t)
	sp.asks = `<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>urn:nobody:offers:this</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`
	base := sp.rf.f.srv.cfg.Issuer + "/saml/org/" + sp.otherSlug
	code, raw := sp.signIn(t, "/saml/org/"+sp.otherSlug+"/sso", base+"/sso", sp.otherACS, sp.otherCookie)
	if code != http.StatusOK || !strings.Contains(raw, saml.StatusNoAuthnContext) {
		t.Fatalf("answered %d %.300s", code, raw)
	}
	if who, _, _ := issuerAndDestination(t, raw); who != base {
		t.Errorf("the status is from %q", who)
	}
}

// By name alone, two organisations' entity ID is a question, not a guess.
func TestACommandSaysWhichOrganisationWhenTwoHoldAnEntityID(t *testing.T) {
	sp := newSharedProvider(t)
	ctx := context.Background()
	if _, _, err := store.SAMLProviderByEntity(ctx, sp.rf.f.pool, "", sp.entity); err != store.ErrSAMLEntityAmbiguous {
		t.Errorf("with no organisation: %v", err)
	}
	id, org, err := store.SAMLProviderByEntity(ctx, sp.rf.f.pool, sp.other.orgID, sp.entity)
	if err != nil || org != sp.other.orgID || id == "" {
		t.Errorf("naming one: %q %q %v", id, org, err)
	}
	if _, _, err := store.SAMLProviderByEntity(ctx, sp.rf.f.pool, sp.other.orgID, "urn:nobody"); err != store.ErrSAMLProviderUnknown {
		t.Errorf("nobody holds it: %v", err)
	}
}
