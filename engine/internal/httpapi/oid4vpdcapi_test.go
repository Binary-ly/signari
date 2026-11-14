package httpapi

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vp"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// A wallet sign-in through the browser's Digital Credentials API (12.12): the page holds
// the request for navigator.credentials.get, and posts back what the browser brought, which
// is checked as made for this origin. The browser and the wallet are played here; the
// page, its form and every route are the real ones.

var (
	dcProtocol = regexp.MustCompile(`data-protocol="([^"]*)"`)
	dcRequest  = regexp.MustCompile(`data-request="([^"]*)"`)
	dcState    = regexp.MustCompile(`name="state" value="([^"]*)"`)
)

// dcPage is a browser opening the sign-in page with the API turned on: the protocol, the
// request the page would hand the API, the sign-in's state, and the cookies.
type dcPage struct {
	protocol, state, csrf string
	request               map[string]any
	binding               *http.Cookie
}

func (f *signInFixture) openDCAPI(t *testing.T, slug string) dcPage {
	t.Helper()
	ret := url.QueryEscape(oidc.PathAuthorize + "?" + f.plainAuthz())
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/start?return="+ret, nil))
	body := rec.Body.String()
	p, r, s, c := dcProtocol.FindStringSubmatch(body), dcRequest.FindStringSubmatch(body),
		dcState.FindStringSubmatch(body), csrfValue.FindStringSubmatch(body)
	if rec.Code != http.StatusOK || p == nil || r == nil || s == nil || c == nil {
		t.Fatalf("the page (%d) does not carry a request for the browser", rec.Code)
	}
	page := dcPage{protocol: p[1], state: s[1], csrf: c[1]}
	if err := json.Unmarshal([]byte(html.UnescapeString(r[1])), &page.request); err != nil {
		t.Fatalf("the request in the page is not JSON: %v", err)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == FederationCookieName {
			page.binding = ck
		}
	}
	if page.binding == nil {
		t.Fatal("no binding cookie")
	}
	if csp := rec.Result().Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("the page's policy %q runs no script of its own", csp)
	}
	if !strings.Contains(body, `src="/static/wallet-dcapi.js"`) {
		t.Error("the page loads no script to ask the browser with")
	}
	return page
}

// answer is the page posting back what the browser brought, as data, in its own form.
func (f *signInFixture) answerDCAPI(t *testing.T, slug string, page dcPage, data string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"state": {page.state}, "response": {data}, csrfFormField: {page.csrf}}
	req := httptest.NewRequest(http.MethodPost, "/oid4vp/"+slug+"/dcapi", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: page.csrf})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// walletSees is the wallet reading the signed request the page handed the browser.
func walletSees(t *testing.T, f *signInFixture, page dcPage, slug string) map[string]any {
	t.Helper()
	v, err := store.LoadVPVerifier(context.Background(), f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := page.request["request"].(string)
	tok, err := jose.ParseSigned(signed, oid4vp.Algorithms())
	if err != nil {
		t.Fatalf("the page's request is not a signed request object: %v", err)
	}
	payload, err := tok.Verify(v.Chain[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	return p
}

func TestAWalletThroughTheBrowserSignsThePersonIn(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, _ := newVPFixture(t, wl)
	on := true
	if err := store.ChangeIdentityProvider(context.Background(), f.pool, f.orgID, slug,
		store.IdentityProviderChange{DCAPI: &on}); err != nil {
		t.Fatal(err)
	}
	origin := oid4vp.OriginAudience(f.srv.vpOrigin())

	page := f.openDCAPI(t, slug)
	if page.protocol != oid4vp.ProtocolSigned {
		t.Fatalf("a signing verifier handed the browser %q", page.protocol)
	}
	p := walletSees(t, f, page, slug)
	if eo, _ := p["expected_origins"].([]any); len(eo) != 1 || eo[0] != f.srv.vpOrigin() {
		t.Errorf("expected_origins %v, want this origin alone", p["expected_origins"])
	}
	if _, ok := p["state"]; ok || p["response_mode"] != oid4vp.ModeDCAPI || p["response_uri"] != nil {
		t.Errorf("the request object %v", p)
	}
	nonce := p["nonce"].(string)

	// Never fetched, never answered at the response URI.
	req := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(req, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/request/"+url.PathEscape(page.state), nil))
	if req.Code != http.StatusNotFound {
		t.Errorf("a request for the browser was fetched by its state: %d", req.Code)
	}
	vp := wl.present(origin, nonce)
	if rec := f.postVP(t, f.srv.vpBase(slug)+"/response", url.Values{"state": {page.state}, "vp_token": {vp}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a request for the browser was answered at the response URI: %d", rec.Code)
	}

	// From another browser, the answer is nobody's.
	data := `{"vp_token":` + vp + `}`
	if rec := f.answerDCAPI(t, slug, page, data, &http.Cookie{Name: FederationCookieName, Value: "not-this-one"}); hasSession(rec) {
		t.Fatal("an answer posted by another browser signed somebody in")
	}

	// Made for the client identifier rather than this origin: refused (:2663).
	page = f.openDCAPI(t, slug)
	nonce = walletSees(t, f, page, slug)["nonce"].(string)
	clientID, _ := walletSees(t, f, page, slug)["client_id"].(string)
	if rec := f.answerDCAPI(t, slug, page, `{"vp_token":`+wl.present(clientID, nonce)+`}`, page.binding); hasSession(rec) {
		t.Fatal("a presentation made for the client identifier was taken through the browser")
	}

	// The wallet declined: no session, and the page says so.
	page = f.openDCAPI(t, slug)
	if rec := f.answerDCAPI(t, slug, page, `{"error":"access_denied"}`, page.binding); hasSession(rec) ||
		!strings.Contains(rec.Body.String(), f.srv.pageSet().Bundle().For("en").Text("federr.cancelled")) {
		t.Errorf("a declined request answered %d", rec.Code)
	}

	// Made for this origin, posted by the browser that asked: the linked person.
	page = f.openDCAPI(t, slug)
	nonce = walletSees(t, f, page, slug)["nonce"].(string)
	rec := f.answerDCAPI(t, slug, page, `{"vp_token":`+wl.present(origin, nonce)+`}`, page.binding)
	if rec.Code != http.StatusSeeOther || !hasSession(rec) || !strings.HasPrefix(rec.Header().Get("Location"), oidc.PathAuthorize) {
		t.Fatalf("the answer answered %d to %q: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions WHERE user_id = $1::uuid`,
		f.userID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("the linked person has %d sessions: %v", sessions, err)
	}
	// Once.
	if again := f.answerDCAPI(t, slug, page, `{"vp_token":`+wl.present(origin, nonce)+`}`, page.binding); hasSession(again) {
		t.Error("an answer through the browser was taken twice")
	}
}

// Each way answers its own requests alone: a sign-in begun for the wallet on this device
// is not finished by an answer posted as the browser's, and a request handed to the
// browser never has a response code minted for it, whichever handler asks.
func TestABrowserRequestAndAnotherAreNotEachOthers(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, leaf := newVPFixture(t, wl)
	on := true
	if err := store.ChangeIdentityProvider(context.Background(), f.pool, f.orgID, slug,
		store.IdentityProviderChange{DCAPI: &on}); err != nil {
		t.Fatal(err)
	}
	ret := url.QueryEscape(oidc.PathAuthorize + "?" + f.plainAuthz())
	start := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/start?device=this&return="+ret, nil))
	loc, err := url.Parse(start.Header().Get("Location"))
	if err != nil || start.Code != http.StatusSeeOther {
		t.Fatalf("this device answered %d", start.Code)
	}
	var binding *http.Cookie
	for _, ck := range start.Result().Cookies() {
		if ck.Name == FederationCookieName {
			binding = ck
		}
	}
	p := f.fetchVP(t, loc, leaf)
	page := f.openDCAPI(t, slug)
	same := dcPage{state: p["state"].(string), csrf: page.csrf}
	data := `{"vp_token":` + wl.present(oid4vp.OriginAudience(f.srv.vpOrigin()), p["nonce"].(string)) + `}`
	if rec := f.answerDCAPI(t, slug, same, data, binding); hasSession(rec) {
		t.Fatal("a sign-in begun for this device was finished as the browser's")
	}

	v, err := store.LoadVPVerifier(context.Background(), f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PresentVP(context.Background(), f.pool, v.ProviderID, page.state, []byte(`{}`)); err != store.ErrVPRequestGone {
		t.Errorf("a response code was minted for a request handed to the browser: %v", err)
	}
}
