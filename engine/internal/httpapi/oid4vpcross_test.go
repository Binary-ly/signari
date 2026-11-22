package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// The wallet on another device (12.12). The page a sign-in begins on offers a code to
// scan; the wallet answers from elsewhere and is given no response code; the account
// linked to the credential is emailed a code, once; and only that code, typed in the
// browser that began it, signs that account in. These tests are the attack the BCP
// describes as much as the flow: somebody else's browser, a credential linked to nobody,
// an unlink in between, a wrong code.

// crossDevice turns the fixture's wallet sign-in over to another device too.
func crossDevice(t *testing.T, f *signInFixture, slug string) {
	t.Helper()
	on := true
	if err := store.ChangeIdentityProvider(context.Background(), f.pool, f.orgID, slug,
		store.IdentityProviderChange{CrossDevice: &on}); err != nil {
		t.Fatal(err)
	}
}

var waitState = regexp.MustCompile(`data-wait="[^"]*\?state=([^"&]+)"`)

// codeField is the code page's input. The shared stylesheet names input[name="code"]
// too, so a bare name="code" is on every page.
const codeField = `<input id="c" name="code"`

// beginCross is a browser opening the sign-in: the page with a code to scan, its
// state, and the cookie that binds the sign-in to this browser.
func (f *signInFixture) beginCross(t *testing.T, slug string) (string, *http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()
	// Begun from an application's authorization request, as a sign-in is.
	ret := url.QueryEscape(oidc.PathAuthorize + "?" + f.plainAuthz())
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/start?return="+ret, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("start answered %d: %.300s", rec.Code, rec.Body)
	}
	m := waitState.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("the page carries no wait address")
	}
	state, err := url.QueryUnescape(m[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == FederationCookieName {
			return state, c, rec
		}
	}
	t.Fatal("no binding cookie")
	return "", nil, nil
}

// walletAnswers is the wallet on the other device: it fetches the request the code
// names and posts the credential, returning what the response URI answered.
func (f *signInFixture) walletAnswers(t *testing.T, wl *holderWallet, slug, state string) map[string]any {
	t.Helper()
	v, err := store.LoadVPVerifier(context.Background(), f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := f.srv.vpClientID(v)
	if err != nil {
		t.Fatal(err)
	}
	loc := &url.URL{Scheme: "openid4vp", RawQuery: url.Values{"request_uri_method": {"post"}, "client_id": {clientID},
		"request_uri": {f.srv.vpBase(slug) + "/request/" + url.PathEscape(state)}}.Encode()}
	p := f.fetchVP(t, loc, v.Chain[0])
	rec := f.postVP(t, p["response_uri"].(string), url.Values{"state": {state},
		"vp_token": {wl.present(p["client_id"].(string), p["nonce"].(string))}})
	if rec.Code != http.StatusOK {
		t.Fatalf("the presentation answered %d: %s", rec.Code, rec.Body)
	}
	var answer map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &answer)
	return answer
}

func (f *signInFixture) waitFor(t *testing.T, slug, state string, cookie *http.Cookie) map[string]bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/wait?"+url.Values{"state": {state}}.Encode(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var got map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("wait answered %d %s", rec.Code, rec.Body)
	}
	return got
}

func (f *signInFixture) confirmPage(t *testing.T, slug, state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/confirm?"+url.Values{"state": {state}}.Encode(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// typeCode posts code on the code page page is, with the binding cookie.
func (f *signInFixture) typeCode(t *testing.T, slug, state string, page *httptest.ResponseRecorder,
	cookie *http.Cookie, code string) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("the code page carries no CSRF field: %d %.300s", page.Code, page.Body)
	}
	form := url.Values{"state": {state}, "code": {code}, csrfFormField: {m[1]}}
	req := httptest.NewRequest(http.MethodPost, "/oid4vp/"+slug+"/confirm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
	req.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// walletCodes is how many confirmation codes have been queued for the account, and the
// code for the live one, minted as the outbox would mint it.
func (f *signInFixture) walletCodes(t *testing.T, state string) (int, string) {
	t.Helper()
	ctx := context.Background()
	var queued int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.outbox WHERE topic = $1
		AND payload->>'notice' = $2 AND payload->>'user_id' = $3`, store.AccountNoticeTopic,
		store.NoticeWalletConfirm, f.userID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(state))
	var attempt string
	if err := f.pool.QueryRow(ctx, `SELECT COALESCE(vp_confirm_attempt::text, '') FROM core.federated_logins
		WHERE state_hash = $1`, h[:]).Scan(&attempt); err != nil || attempt == "" {
		return queued, ""
	}
	code, _, err := store.MintEmailSignInCode(ctx, f.pool, attempt)
	if err != nil {
		t.Fatal(err)
	}
	return queued, code
}

func clearWalletCodes(t *testing.T, f *signInFixture) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1
			AND payload->>'user_id' = $2`, store.AccountNoticeTopic, f.userID)
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.email_sign_in_codes WHERE user_id = $1::uuid`, f.userID)
	})
}

func TestAWalletOnAnotherDeviceSignsInOnlyWithTheAccountsEmailedCode(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, _ := newVPFixture(t, wl)
	clearWalletCodes(t, f)

	// Off, the button goes straight to the wallet, as it always did.
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/start", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("with the other device off, start answered %d", rec.Code)
	}
	crossDevice(t, f, slug)

	// On, a page: this device, or a code to scan, its script allowed and nothing else.
	state, cookie, page := f.beginCross(t, slug)
	body := page.Body.String()
	if !strings.Contains(body, "<svg") || !strings.Contains(body, "/start?device=this") ||
		!strings.Contains(body, `src="/static/wallet-wait.js"`) {
		t.Errorf("the page lacks a code, this device's way, or its script: %.800s", body)
	}
	if csp := page.Result().Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") ||
		!strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("the page's policy %q does not let its script ask", csp)
	}
	// This device is the flow it always was.
	here := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(here, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/start?device=this", nil))
	if here.Code != http.StatusSeeOther {
		t.Errorf("this device answered %d", here.Code)
	}

	if got := f.waitFor(t, slug, state, cookie); got["answered"] || got["gone"] {
		t.Fatalf("before the wallet answered, wait said %v", got)
	}
	// Another browser asking learns nothing.
	if got := f.waitFor(t, slug, state, &http.Cookie{Name: FederationCookieName, Value: "not-this-one"}); !got["gone"] {
		t.Errorf("another browser was told %v", got)
	}

	// The wallet answers from the other device and is sent nowhere: no response code
	// exists for this sign-in.
	if answer := f.walletAnswers(t, wl, slug, state); len(answer) != 0 {
		t.Fatalf("the wallet was answered %v; a cross-device request hands out no redirect", answer)
	}
	if got := f.waitFor(t, slug, state, cookie); !got["answered"] {
		t.Fatalf("after the wallet answered, wait said %v", got)
	}

	// The code page sends one code, however often it is asked for.
	codePage := f.confirmPage(t, slug, state, cookie)
	if codePage.Code != http.StatusOK || !strings.Contains(codePage.Body.String(), codeField) {
		t.Fatalf("the code page answered %d: %.400s", codePage.Code, codePage.Body)
	}
	if strings.Contains(codePage.Body.String(), f.email) {
		t.Error("the code page names the address, which whoever began the sign-in may not own")
	}
	codePage = f.confirmPage(t, slug, state, cookie)
	queued, code := f.walletCodes(t, state)
	if queued != 1 || code == "" {
		t.Fatalf("%d codes were queued, the live one %q", queued, code)
	}
	// Another browser cannot take the code page.
	if other := f.confirmPage(t, slug, state, &http.Cookie{Name: FederationCookieName, Value: "not-this-one"}); hasSession(other) ||
		strings.Contains(other.Body.String(), codeField) {
		t.Error("another browser was shown the code page")
	}

	// A wrong code signs nobody in and is counted.
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if rec := f.typeCode(t, slug, state, codePage, cookie, wrong); hasSession(rec) {
		t.Fatal("a wrong code signed somebody in")
	}
	// The right one signs in the linked person, and nobody made for the occasion.
	rec = f.typeCode(t, slug, state, codePage, cookie, code)
	if rec.Code != http.StatusSeeOther || !hasSession(rec) {
		t.Fatalf("the right code answered %d: %.400s", rec.Code, rec.Body)
	}
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions WHERE user_id = $1::uuid`,
		f.userID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("the linked person has %d sessions: %v", sessions, err)
	}
	// Once.
	if again := f.typeCode(t, slug, state, codePage, cookie, code); hasSession(again) {
		t.Error("the code finished the sign-in twice")
	}
}

// A credential linked to nobody: no code goes anywhere, and nobody is made, since a
// code can only go to an address an account has shown is its own.
func TestAWalletOnAnotherDeviceMakesNobody(t *testing.T) {
	wl := newHolderWallet(t, "person-nobody")
	f, slug, _ := newVPFixture(t, wl)
	clearWalletCodes(t, f)
	crossDevice(t, f, slug)
	ctx := context.Background()
	var before int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE org_id = $1::uuid`, f.orgID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	state, cookie, _ := f.beginCross(t, slug)
	f.walletAnswers(t, wl, slug, state)
	page := f.confirmPage(t, slug, state, cookie)
	if strings.Contains(page.Body.String(), codeField) || hasSession(page) {
		t.Fatalf("a credential linked to nobody reached the code page: %d", page.Code)
	}
	if !strings.Contains(page.Body.String(), f.srv.pageSet().Bundle().For("en").Text("federr.crossnoaccount")) {
		t.Errorf("the refusal does not say why: %.400s", page.Body)
	}
	var after int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE org_id = $1::uuid`, f.orgID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if queued, _ := f.walletCodes(t, state); queued != 0 || after != before {
		t.Errorf("%d codes queued and %d people made for a credential linked to nobody", queued, after-before)
	}
}

// The link goes between the code and the sign-in: the code is right, and it still
// signs nobody in, as nobody else and as nobody new.
func TestAnUnlinkBetweenTheCodeAndTheSignInEndsIt(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, _ := newVPFixture(t, wl)
	clearWalletCodes(t, f)
	crossDevice(t, f, slug)
	state, cookie, _ := f.beginCross(t, slug)
	f.walletAnswers(t, wl, slug, state)
	codePage := f.confirmPage(t, slug, state, cookie)
	_, code := f.walletCodes(t, state)
	v, err := store.LoadVPVerifier(context.Background(), f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	// Moved to somebody else's account, under the same subject.
	var other string
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'x-' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
		        decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'))
		RETURNING id::text`, f.orgID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.federated_identities SET user_id = $3::uuid
		WHERE provider_id = $1::uuid AND subject = $2`, v.ProviderID, store.VPSubject(walletIssuer, "person-1"), other); err != nil {
		t.Fatal(err)
	}
	rec := f.typeCode(t, slug, state, codePage, cookie, code)
	if hasSession(rec) {
		t.Fatal("a code sent to one account signed in the account the link moved to")
	}
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions WHERE user_id = $1::uuid`,
		other).Scan(&sessions); err != nil || sessions != 0 {
		t.Errorf("the account the link moved to has %d sessions: %v", sessions, err)
	}
}

// The guard at the end of the path, called as the confirm handler calls it: a sign-in
// told which account it must end at refuses every other outcome, read in the
// transaction that would sign in. The handler's own lookup meets a moved link first,
// so only this reaches the window between the code and the sign-in.
func TestASignInConfirmedForOneAccountEndsAsNoOther(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, _ := newVPFixture(t, wl)
	ctx := context.Background()
	v, err := store.LoadVPVerifier(ctx, f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &federation.Config{ID: v.ProviderID, OrgID: v.OrgID, Slug: v.Slug, DisplayName: v.DisplayName,
		Policy: v.Policy, Kind: federation.KindOID4VP}
	var other string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'y-' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
		        decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'))
		RETURNING id::text`, f.orgID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	finish := func(require, subject string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.srv.completeFederation(rec, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/confirm", nil), cfg,
			&store.PendingLogin{ProviderID: v.ProviderID, OrgID: v.OrgID, RequireUserID: require},
			federation.ExternalIdentity{Subject: subject, Email: "new-" + subject + "@example.test"})
		return rec
	}
	linked := store.VPSubject(walletIssuer, "person-1")
	if rec := finish(other, linked); hasSession(rec) {
		t.Error("a sign-in confirmed for one account signed in the account its subject is linked to")
	}
	var before int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE org_id = $1::uuid`, f.orgID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if rec := finish(f.userID, store.VPSubject(walletIssuer, "person-unlinked")); hasSession(rec) {
		t.Error("a sign-in confirmed for an account made somebody new")
	}
	var after int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.users WHERE org_id = $1::uuid`, f.orgID).Scan(&after); err != nil ||
		after != before {
		t.Errorf("%d people were made for a confirmed sign-in", after-before)
	}
	// And the account it was confirmed for signs in.
	if rec := finish(f.userID, linked); !hasSession(rec) {
		t.Errorf("the confirmed account was not signed in: %d %.300s", rec.Code, rec.Body)
	}
}

// A request marked for another device never takes a response code, whatever asks.
func TestACrossDeviceRequestTakesNoResponseCode(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, _ := newVPFixture(t, wl)
	crossDevice(t, f, slug)
	state, _, _ := f.beginCross(t, slug)
	v, err := store.LoadVPVerifier(context.Background(), f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PresentVP(context.Background(), f.pool, v.ProviderID, state, []byte(`{}`)); err != store.ErrVPRequestGone {
		t.Fatalf("a response code was minted for a cross-device request: %v", err)
	}
}

// Only a signed request may go to another device: an unsigned one shows the wallet
// nobody it can check.
func TestAnUnsignedWalletSignInStaysOnOneDevice(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	slug := "wallet-unsigned-" + strings.TrimPrefix(f.clientID, "si-")
	spec := store.IdentityProviderSpec{Slug: slug, Kind: "oid4vp", VP: &store.VPSpec{Prefix: "redirect_uri",
		VCTValues: []string{walletVCT}, SubjectClaim: "personal_id", CrossDevice: true}}
	if err := spec.Validate(); err == nil {
		t.Error("an unsigned wallet sign-in was let go to another device")
	}
	spec.VP.CrossDevice = false
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.AddIdentityProvider(ctx, tx, nil, f.orgID, spec); err != nil {
		t.Fatal(err)
	}
	on := true
	if err := store.ChangeIdentityProvider(ctx, tx, f.orgID, slug, store.IdentityProviderChange{CrossDevice: &on}); err == nil {
		t.Error("an unsigned wallet sign-in was turned over to another device")
	}
}
