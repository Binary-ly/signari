package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The forms that set a password say the floor the policy holds it to, in their
// hint and their minlength. They said 8, in a fixed hint and attribute, while
// the policy refused anything under 15, so a person who followed the form's own
// advice was refused by the server.
func TestThePasswordFormsStateThePolicysMinimum(t *testing.T) {
	for _, c := range []struct{ name, env, want string }{
		{"by default", "", "15"},
		{"with a raised floor", "20", "20"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Read by New, which the journey calls. Empty is unset.
			t.Setenv("SIGNARI_PASSWORD_MIN_LENGTH", c.env)
			j := newPasskeyJourney(t)
			j.openSignup(t)

			page := newTestBrowser(t, j.h).get("/signup").Body.String()
			// The number is a substituted value, so the hint wraps it in
			// bidirectional isolates (i18n's isolate).
			for _, s := range []string{
				`minlength="` + c.want + `"`,
				"At least ⁨" + c.want + "⁩ characters.",
			} {
				if !strings.Contains(page, s) {
					t.Errorf("the sign-up form lacks %q: %s", s, truncate(page, 600))
				}
			}

			rec := httptest.NewRecorder()
			j.srv.renderPage(rec, httptest.NewRequest(http.MethodGet, "/recover/reset", nil), "reset",
				map[string]any{"Ready": true, "Token": "t", "CSRF": "c", "CSRFField": csrfFormField})
			if body := rec.Body.String(); !strings.Contains(body, `minlength="`+c.want+`"`) {
				t.Errorf("the reset form lacks minlength=%q: %s", c.want, truncate(body, 600))
			}
		})
	}
}
