package httpapi

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
)

// The request parameters of 9.11, through the authorization endpoint.

func (f *signInFixture) authorizeWith(t *testing.T, cookie string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	q, err := url.ParseQuery(f.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range extra {
		q[name] = values
	}
	req := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	f.srv.handleAuthorize(rec, req)
	return rec
}

func (f *signInFixture) redeemPlain(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("no code came back (%d, %q): %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	return f.redeemCode(t, loc.Query().Get("code"))
}

func (f *signInFixture) redeemCode(t *testing.T, code string) map[string]any {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, req)
	var body map[string]any
	if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil || out.Code != http.StatusOK {
		t.Fatalf("the redemption answered %d: %.300s", out.Code, out.Body.String())
	}
	return body
}

func redirected(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "https://rp.test/cb") {
		t.Fatalf("not sent back to the client (%d, %q): %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	return loc.Query()
}

// max_age, against when the session actually signed in: older than asked for is
// a sign-in, however live the session is.
func TestMaxAgeIsMeasuredFromTheSessionsSignIn(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET first_party = true
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	cookie := f.signInAndReturnCookie(t)
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET auth_time = now() - interval '1 hour'
		WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if redirected(t, f.authorizeWith(t, cookie, url.Values{"max_age": {"7200"}})).Get("code") == "" {
		t.Error("a session younger than max_age got no code")
	}
	if rec := f.authorizeWith(t, cookie, url.Values{"max_age": {"60"}}); strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Error("a code came back for a session older than max_age")
	}
}

func TestALoginHintFillsInTheSignInBox(t *testing.T) {
	f := newSignInFixture(t)
	page := f.authorizeWith(t, "", url.Values{"login_hint": {`ada"><script>alert(1)</script>@corp.example`}}).Body.String()
	if !strings.Contains(page, `value="ada&#34;&gt;&lt;script&gt;`) {
		t.Errorf("the box does not hold the hint, escaped: %.1200s", page)
	}
	if strings.Contains(page, "<script>alert") {
		t.Error("the hint reached the page as markup")
	}
	plain := f.authorizeWith(t, "", url.Values{"login_hint": {"ada@corp.example"}}).Body.String()
	if !strings.Contains(plain, `value="ada@corp.example"`) {
		t.Error("a plain hint is not in the box")
	}

	// As it comes back from a page that parked the request.
	if got := loginHint(url.Values{"return": {oidc.PathAuthorize + "?login_hint=ada%40corp.example&client_id=c"}}.Encode()); got != "ada@corp.example" {
		t.Errorf("a parked hint read as %q", got)
	}
	if got := loginHint("login_hint=" + strings.Repeat("a", loginHintMax+1)); got != "" {
		t.Errorf("a hint no name is that long was kept: %d bytes", len(got))
	}
}

func TestAnIDTokenHintHoldsTheSessionToThePersonItNames(t *testing.T) {
	f := newSignInFixture(t)
	// A second person in the organisation, so that who holds the session is a
	// question with more than one answer.
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'o' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
		        decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text) ||
		               md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'))`, f.orgID); err != nil {
		t.Fatal(err)
	}
	cookie := f.signInAndReturnCookie(t)
	body := f.redeemPlain(t, f.authorizePlain(t, cookie))
	hint, _ := body["id_token"].(string)
	if hint == "" {
		t.Fatal("no ID token to hint with")
	}

	if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"id_token_hint": {hint}, "prompt": {"none"}})); q.Get("code") == "" {
		t.Errorf("the person it names, signed in, got %v", q)
	}

	// Long past its expiry it still says who.
	key, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(subject, audience string, age time.Duration) string {
		t.Helper()
		then := time.Now().Add(-age)
		raw, err := tokens.NewSigner(key).SignIDToken(tokens.IDTokenClaims{Issuer: f.srv.cfg.Issuer, Subject: subject,
			Audience: audience, IssuedAt: then.Unix(), Expiry: then.Add(time.Minute).Unix(), AuthTime: then.Unix()})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"id_token_hint": {sign(f.userID, f.clientID, 48*time.Hour)},
		"prompt": {"none"}})); q.Get("code") == "" {
		t.Errorf("an expired hint for the right person got %v", q)
	}

	someoneElse := sign("00000000-0000-4000-8000-000000000000", f.clientID, 0)
	if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"id_token_hint": {someoneElse}, "prompt": {"none"}})); q.Get("error") != "login_required" || q.Get("code") != "" {
		t.Errorf("with somebody else signed in and no way to ask, got %v", q)
	}
	rec := f.authorizeWith(t, cookie, url.Values{"id_token_hint": {someoneElse}})
	if strings.Contains(rec.Header().Get("Location"), "code=") || !strings.Contains(rec.Body.String(), "asking for somebody else") {
		t.Errorf("with somebody else signed in, got %d %q: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}

	for name, bad := range map[string]string{
		"nothing like a token":    "garbage",
		"an ID token for another": sign(f.userID, "another-client", 0),
		"an access token instead": body["access_token"].(string),
	} {
		if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"id_token_hint": {bad}})); q.Get("error") != "invalid_request" {
			t.Errorf("%s answered %v", name, q)
		}
	}
}

func TestTheClaimsParameterAsksForWhatScopesRelease(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET scopes = ARRAY['openid','email'] WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	cookie := f.signInAndReturnCookie(t)

	ask := func(claims string) *httptest.ResponseRecorder {
		t.Helper()
		return f.authorizeWith(t, cookie, url.Values{"claims": {claims}})
	}
	const emailed = `{"userinfo":{"email":{"essential":true}},"id_token":{"groups":{"essential":true}}}`

	// A claim gets no further than its scope would: the person is asked for it.
	consent := ask(emailed)
	parked := parkedAuthz.FindStringSubmatch(consent.Body.String())
	if consent.Header().Get("Location") != "" || parked == nil ||
		!strings.Contains(html.UnescapeString(parked[1]), "scope=openid+email") {
		t.Fatalf("a claim nobody consented to answered %d %q", consent.Code, consent.Header().Get("Location"))
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET first_party = true WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	body := f.redeemPlain(t, ask(emailed))
	scope, _ := body["scope"].(string)
	if !strings.Contains(scope, "email") {
		t.Errorf("a claim did not ask for its scope: %q", scope)
	}
	if strings.Contains(scope, "groups") {
		t.Errorf("a claim released a scope the client is not registered for: %q", scope)
	}

	if q := redirected(t, ask(`{"userinfo":`)); q.Get("error") != "invalid_request" {
		t.Errorf("a claims parameter that is not JSON answered %v", q)
	}

	// A step-up asked for this way is the step-up asked for any way.
	rec := ask(`{"id_token":{"acr":{"essential":true,"values":["2"]}}}`)
	if strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Errorf("an essential acr of a second factor got a code from a password session: %q", rec.Header().Get("Location"))
	}

	// And a subject holds the session as a hint does.
	if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"prompt": {"none"},
		"claims": {`{"id_token":{"sub":{"value":"00000000-0000-4000-8000-000000000000"}}}`}})); q.Get("error") != "login_required" {
		t.Errorf("a claims parameter naming somebody else answered %v", q)
	}

	var meta map[string]any
	rec = httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["claims_parameter_supported"] != true {
		t.Errorf("discovery says claims_parameter_supported is %v", meta["claims_parameter_supported"])
	}
}
