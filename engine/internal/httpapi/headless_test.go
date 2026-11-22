package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/oidc"
)

const headlessPage = "https://app.example.test/login"

// newHeadlessFixture is a person with a second factor, and a client that names a
// sign-in page of its own and asks for a scope that wants consent.
func newHeadlessFixture(t *testing.T) (*signInFixture, []byte) {
	t.Helper()
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	secret := giveTOTP(t, f)
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE core.clients SET login_ui_url = $2, scopes = ARRAY['openid', 'profile'] WHERE client_id = $1`,
		f.clientID, headlessPage); err != nil {
		t.Fatal(err)
	}
	return f, secret
}

func (f *signInFixture) consentAuthz(t *testing.T) string {
	t.Helper()
	q, err := url.ParseQuery(f.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	q.Set("scope", "openid profile")
	return q.Encode()
}

func (f *signInFixture) headless(t *testing.T, path string, body any) (int, headlessStep, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = testClientIP(t) + ":5555"
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	var step headlessStep
	_ = json.Unmarshal(rec.Body.Bytes(), &step)
	return rec.Code, step, rec.Body.String()
}

func headlessSubmit(state, action string, fields map[string]string) map[string]any {
	return map[string]any{"state": state, "action": action, "fields": fields}
}

// journey is what a person is asked along a walk: each form's action and the
// fields it wants, in order, and it is the same for either driver.
type journey []string

func (j *journey) saw(forms []headlessForm) headlessForm {
	var main headlessForm
	for _, form := range forms {
		names := []string{}
		for _, field := range form.Fields {
			names = append(names, field.Name)
		}
		*j = append(*j, form.Action+" "+strings.Join(names, ","))
		if main.Action == "" {
			main = form
		}
	}
	return main
}

// browser walks the HTML pages as a browser does: cookies, redirects, hidden
// fields. It is the other driver of the contract.
type browser struct {
	t       *testing.T
	f       *signInFixture
	cookies map[string]string
	seen    journey
	hidden  map[string]url.Values
	forms   []headlessForm
	left    string
}

func (b *browser) request(method, target string, form url.Values) {
	b.t.Helper()
	for range 8 {
		var body *strings.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader("")
		}
		r := httptest.NewRequest(method, target, body)
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.RemoteAddr = testClientIP(b.t) + ":5555"
		for name, value := range b.cookies {
			r.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		rec := httptest.NewRecorder()
		b.f.srv.Routes().ServeHTTP(rec, r)
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge < 0 || c.Value == "" {
				delete(b.cookies, c.Name)
			} else {
				b.cookies[c.Name] = c.Value
			}
		}
		if location := rec.Header().Get("Location"); location != "" && rec.Code >= 300 && rec.Code < 400 {
			if !strings.HasPrefix(location, "/") {
				b.left = location
				return
			}
			method, target, form = http.MethodGet, location, nil
			continue
		}
		b.forms, b.hidden = readForms(rec.Body.String(), target)
		b.seen.saw(b.forms)
		return
	}
	b.t.Fatal("the pages did not settle")
}

func (b *browser) submit(fields map[string]string) {
	b.t.Helper()
	action := b.forms[0].Action
	form := url.Values{}
	for name, value := range fields {
		form.Set(name, value)
	}
	for name, values := range b.hidden[action] {
		form[name] = values
	}
	b.request(http.MethodPost, action, form)
}

// The contract: the JSON driver and a browser on the HTML pages are asked the same
// things in the same order, refusals included, and both end at a code the client
// redeems with its verifier.
func TestTheJSONAndHTMLDriversWalkTheSameStages(t *testing.T) {
	f, secret := newHeadlessFixture(t)
	code := func() string {
		return mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.DefaultDigits)
	}

	// The HTML pages. /login, because this client's authorize goes to its own page.
	web := &browser{t: t, f: f, cookies: map[string]string{}}
	web.request(http.MethodGet, "/login?authz="+url.QueryEscape(f.consentAuthz(t)), nil)
	web.submit(map[string]string{"username": f.email, "password": "not the password"})
	web.submit(map[string]string{"username": f.email, "password": signInTestPassword})
	web.submit(map[string]string{"code": "000000"})
	web.submit(map[string]string{"code": code()})
	web.submit(map[string]string{"decision": "allow"})
	if !strings.HasPrefix(web.left, "https://rp.test/cb?") {
		t.Fatalf("the pages ended at %q, having seen %v", web.left, web.seen)
	}

	// The same person, the same answers, over JSON. The code is spent, so the next.
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.sessions WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.consents WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.totp_credentials SET last_used_counter = 0 WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	var seen journey
	status, step, raw := f.headless(t, pathHeadlessStart, map[string]string{"authz": f.consentAuthz(t)})
	if status != http.StatusOK || step.Page != "login" {
		t.Fatalf("starting answered %d: %.300s", status, raw)
	}
	form := seen.saw(step.Forms)
	walk := func(fields map[string]string) {
		t.Helper()
		status, step, raw = f.headless(t, pathHeadlessSubmit, headlessSubmit(step.State, form.Action, fields))
		if status != http.StatusOK {
			t.Fatalf("a step answered %d: %.300s", status, raw)
		}
		form = seen.saw(step.Forms)
	}
	walk(map[string]string{"username": f.email, "password": "not the password"})
	if step.Page != "login" || step.Message == "" {
		t.Errorf("a wrong password answered %q, saying %q", step.Page, step.Message)
	}
	walk(map[string]string{"username": f.email, "password": signInTestPassword})
	if step.Page != "mfa" {
		t.Errorf("the password led to %q", step.Page)
	}
	walk(map[string]string{"code": "000000"})
	if step.Page != "mfa" || step.Message == "" {
		t.Errorf("a wrong code answered %q, saying %q", step.Page, step.Message)
	}
	walk(map[string]string{"code": code()})
	if step.Page != "consent" {
		t.Errorf("the code led to %q", step.Page)
	}
	walk(map[string]string{"decision": "allow"})
	if !step.Done || !strings.HasPrefix(step.RedirectTo, "https://rp.test/cb?") {
		t.Fatalf("the walk ended at %+v", step)
	}

	if !slices.Equal(web.seen, seen) {
		t.Errorf("the two drivers were asked different things:\n pages %v\n json  %v", web.seen, seen)
	}

	// A code, redeemed with the verifier, is the only way out.
	rec := httptest.NewRecorder()
	rec.Header().Set("Location", step.RedirectTo)
	tokens := f.redeemPlain(t, rec)
	if claims := claimsOfJWT(t, tokens["id_token"].(string)); claims["sub"] == "" {
		t.Errorf("the walk's tokens name nobody: %v", claims)
	}
}

// Each is a way into this that must not be one.
func TestAWalkIsRefusedOutsideWhatItIsFor(t *testing.T) {
	f, _ := newHeadlessFixture(t)
	good := f.plainAuthz()
	without := func(key, value string) string {
		q, err := url.ParseQuery(good)
		if err != nil {
			t.Fatal(err)
		}
		if value == "" {
			q.Del(key)
		} else {
			q.Set(key, value)
		}
		return q.Encode()
	}
	for name, c := range map[string]struct {
		authz string
		want  string
	}{
		"no challenge":         {without("code_challenge", ""), "invalid_request"},
		"a plain challenge":    {without("code_challenge_method", "plain"), "invalid_request"},
		"an implicit response": {without("response_type", "token"), "invalid_request"},
		"a posted response":    {without("response_mode", "form_post"), "invalid_request"},
		"no such client":       {without("client_id", "nobody"), "invalid_client"},
	} {
		if status, _, raw := f.headless(t, pathHeadlessStart, map[string]string{"authz": c.authz}); status == http.StatusOK ||
			!strings.Contains(raw, c.want) {
			t.Errorf("%s answered %d: %.200s", name, status, raw)
		}
	}

	// One more place a password is typed, so a client asks for it.
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET login_ui_url = NULL WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if status, _, raw := f.headless(t, pathHeadlessStart, map[string]string{"authz": good}); status != http.StatusForbidden {
		t.Errorf("a client with no page of its own answered %d: %.200s", status, raw)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET login_ui_url = $2 WHERE client_id = $1`, f.clientID, headlessPage); err != nil {
		t.Fatal(err)
	}

	_, step, _ := f.headless(t, pathHeadlessStart, map[string]string{"authz": good})
	action := step.Forms[0].Action
	right := map[string]string{"username": f.email, "password": "not the password"}
	for name, c := range map[string]struct {
		body map[string]any
		want string
	}{
		"a state nobody made":   {headlessSubmit("bm90IHNlYWxlZA", action, right), "invalid_state"},
		"a state changed":       {headlessSubmit(step.State[:len(step.State)-4]+"AAAA", action, right), "invalid_state"},
		"a form it was offered": {headlessSubmit(step.State, "/account/delete", right), "invalid_action"},
	} {
		if status, _, raw := f.headless(t, pathHeadlessSubmit, c.body); status != http.StatusBadRequest ||
			!strings.Contains(raw, c.want) {
			t.Errorf("%s answered %d: %.200s", name, status, raw)
		}
	}

	// What the application holds says nothing: not the session, not the token.
	raw, err := base64.RawURLEncoding.DecodeString(step.State)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(CSRFCookieName)) || bytes.Contains(raw, []byte("cookies")) {
		t.Error("the state can be read by what holds it")
	}

	// A hidden field is the page's, however the application asks: this request is
	// the one the walk began with, not the one a step names.
	evil := map[string]string{"username": f.email, "password": "not the password", "authz": "client_id=evil"}
	if status, next, raw := f.headless(t, pathHeadlessSubmit, headlessSubmit(step.State, action, evil)); status != http.StatusOK ||
		next.Page != "login" {
		t.Fatalf("a step answered %d: %.200s", status, raw)
	} else if st, err := f.srv.openHeadless(next.State); err != nil || !strings.Contains(st.Forms[action].Get("authz"), f.clientID) {
		t.Errorf("the parked request became the application's: %+v, %v", st, err)
	}

	// Past its life it is nobody's.
	st := headlessState{Expiry: time.Now().Add(-time.Minute).Unix()}
	plain, _ := json.Marshal(st)
	sealed, err := f.srv.cfg.Root.Seal(plain, headlessStateContext)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, raw := f.headless(t, pathHeadlessSubmit, headlessSubmit(base64.RawURLEncoding.EncodeToString(sealed), action, right)); status != http.StatusBadRequest {
		t.Errorf("a state past its life answered %d: %.200s", status, raw)
	}

	// With nothing to seal under, it is plainly not offered.
	f.srv.cfg.Root = nil
	if status, _, _ := f.headless(t, pathHeadlessStart, map[string]string{"authz": good}); status != http.StatusServiceUnavailable {
		t.Errorf("with no root key it answered %d", status)
	}
}

// An application's own page is where the request goes, and this server's stays for
// everybody else.
func TestAClientWithItsOwnPageIsSentThere(t *testing.T) {
	f, _ := newHeadlessFixture(t)
	rec := f.authorizeWith(t, "", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("authorize answered %d: %.200s", rec.Code, rec.Body)
	}
	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || to.Scheme+"://"+to.Host+to.Path != headlessPage {
		t.Fatalf("it went to %q", rec.Header().Get("Location"))
	}
	if q, err := url.ParseQuery(to.Query().Get("authz")); err != nil || q.Get("client_id") != f.clientID {
		t.Errorf("the page was not given the request: %q", to.RawQuery)
	}
	if got := loginUIRedirect("https://a.test/login?tenant=1", "a=b"); got != "https://a.test/login?tenant=1&authz=a%3Db" {
		t.Errorf("a page with a query got %q", got)
	}

	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET login_ui_url = NULL WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if rec := f.authorizeWith(t, "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Errorf("a client with no page answered %d", rec.Code)
	}
}

// A page is read the way a browser reads it.
func TestAPageIsReadAsItsForms(t *testing.T) {
	forms, hidden := readForms(`
		<form method="get" action="/search"><input name="q"></form>
		<form method="POST" action="/login/mfa?a=1&amp;b=2">
			<input type="hidden" name="csrf" value="tok&amp;en">
			<label for="c">Code <b>here</b></label>
			<input id="c" name="code" required value="12">
			<select name="kind"></select>
			<input name="" value="nameless">
			<button type="submit" name="how" value="sms">By <i>text</i></button>
			<button type="submit">Plain</button>
		</form>
		<form method="post"><input name="x"></form>`, "/here")
	if len(forms) != 2 {
		t.Fatalf("read %d forms: %+v", len(forms), forms)
	}
	mfaForm := forms[0]
	if mfaForm.Action != "/login/mfa?a=1&b=2" || hidden[mfaForm.Action].Get("csrf") != "tok&en" {
		t.Errorf("the form read as %+v, hidden %v", mfaForm, hidden)
	}
	if len(mfaForm.Fields) != 2 || mfaForm.Fields[0] != (headlessField{Name: "code", Type: "input", Label: "Code here",
		Value: "12", Required: true}) || mfaForm.Fields[1].Type != "select" {
		t.Errorf("the fields read as %+v", mfaForm.Fields)
	}
	if len(mfaForm.Buttons) != 1 || mfaForm.Buttons[0] != (headlessButton{Name: "how", Value: "sms", Label: "By text"}) {
		t.Errorf("the buttons read as %+v", mfaForm.Buttons)
	}
	if forms[1].Action != "/here" {
		t.Errorf("a form with no action posts to its page, not %q", forms[1].Action)
	}
}

// CORS for the two routes follows the origins clients registered, as the token
// endpoint's does, or a page of its own could not call them.
func TestTheWalkIsCalledFromARegisteredOrigin(t *testing.T) {
	for _, path := range []string{pathHeadlessStart, pathHeadlessSubmit} {
		if corsPolicyFor(path) != corsClientOrigin {
			t.Errorf("%s is not open to a registered origin", path)
		}
	}
	if corsPolicyFor(oidc.PathAuthorize) != corsNone {
		t.Error("the authorization endpoint must stay closed to scripts")
	}
}
