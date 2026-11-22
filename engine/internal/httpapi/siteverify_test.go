package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/captcha"
)

func setSiteverifyEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"SIGNARI_CAPTCHA_MODE": "always", "SIGNARI_CAPTCHA_PROVIDER": "siteverify",
		"SIGNARI_CAPTCHA_SITE_KEY": "site", "SIGNARI_CAPTCHA_SECRET": "secret",
		"SIGNARI_CAPTCHA_VERIFY_URL":     "https://captcha.example.test/siteverify",
		"SIGNARI_CAPTCHA_WIDGET_URL":     "https://cdn.captcha.example.test/widget.js",
		"SIGNARI_CAPTCHA_WIDGET_CLASS":   "my-captcha",
		"SIGNARI_CAPTCHA_RESPONSE_FIELD": "my-captcha-response",
	} {
		t.Setenv(k, v)
	}
}

// A self-hosted challenge is configured whole or not at all: a part of one would
// render an empty box and refuse every sign-in, and the same settings beside a
// vendor would be ignored by somebody who believes they apply.
func TestASiteverifyServiceIsConfiguredWhole(t *testing.T) {
	setSiteverifyEnv(t)
	v, err := captchaFromEnv()
	if err != nil {
		t.Fatalf("a whole configuration was refused: %v", err)
	}
	if v.Widget().Class != "my-captcha" || v.Provider() != captcha.Siteverify {
		t.Errorf("it read as %+v", v.Widget())
	}

	t.Setenv("SIGNARI_CAPTCHA_WIDGET_CLASS", "")
	if _, err := captchaFromEnv(); err == nil {
		t.Error("a widget with no class was accepted")
	}
	t.Setenv("SIGNARI_CAPTCHA_WIDGET_CLASS", "my-captcha")
	t.Setenv("SIGNARI_CAPTCHA_VERIFY_URL", "http://captcha.example.test/siteverify")
	if _, err := captchaFromEnv(); err == nil {
		t.Error("a plain verify address, which would carry the secret, was accepted")
	}
	t.Setenv("SIGNARI_CAPTCHA_VERIFY_URL", "https://captcha.example.test/siteverify")
	t.Setenv("SIGNARI_CAPTCHA_PROVIDER", "turnstile")
	if _, err := captchaFromEnv(); err == nil || !strings.Contains(err.Error(), "ignore") {
		t.Errorf("settings a vendor would ignore answered %v", err)
	}
}

// The page draws the operator's widget, admits the origin of its script and no
// vendor's, and the answer is read from the field the operator named, alone.
func TestASelfHostedWidgetIsDrawnAndItsAnswerRead(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	before := f.srv.captcha
	f.srv.captcha = captcha.New(captcha.Config{Mode: captcha.ModeAlways, Provider: captcha.Siteverify,
		SiteKey: "site-key-for-the-test", Secret: "secret", Widget: captcha.Widget{
			VerifyURL: "https://captcha.example.test/siteverify",
			ScriptURL: "https://cdn.captcha.example.test/widget.js",
			Class:     "my-captcha", ResponseField: "my-captcha-response"}}, nil)
	t.Cleanup(func() { f.srv.captcha = before })

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/signup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /signup answered %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`class="my-captcha"`, `data-sitekey="site-key-for-the-test"`,
		`src="https://cdn.captcha.example.test/widget.js"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page has no %s", want)
		}
	}
	if strings.Contains(body, "g-recaptcha") {
		t.Error("the page drew a vendor's widget")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "https://cdn.captcha.example.test") {
		t.Errorf("the policy does not admit the widget's origin: %q", csp)
	}
	if strings.Contains(csp, "captcha.example.test/widget.js") {
		t.Errorf("the policy names a path rather than the origin: %q", csp)
	}

	r := httptest.NewRequest(http.MethodPost, "/signup", nil)
	r.PostForm = url.Values{"my-captcha-response": {"from-the-widget"}, "cf-turnstile-response": {"from-elsewhere"}}
	if got := f.srv.captchaResponse(r); got != "from-the-widget" {
		t.Errorf("read %q", got)
	}
	r.PostForm = url.Values{"cf-turnstile-response": {"from-elsewhere"}}
	if got := f.srv.captchaResponse(r); got != "" {
		t.Errorf("a field the service never set was read as %q", got)
	}
}
