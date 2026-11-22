package httpapi

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var scriptNonce = regexp.MustCompile(`<script nonce="([^"]+)">document\.forms\[0\]\.submit\(\);</script>`)

// A bridge page exists to do what the ordinary policy forbids, and a page can
// render perfectly and do none of it. Each of these is read as a browser reads it:
// the script the page submits itself with has to be one its policy lets run, and
// the form has to be allowed to go where it goes and on from there.
// interop/form-redirect-e2e.mjs proves the same journeys in a real browser.
func TestABridgePageIsAllowedToDoItsOneJob(t *testing.T) {
	f := newSignInFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/x", nil)

	for name, send := range map[string]func(http.ResponseWriter){
		"form_post": func(w http.ResponseWriter) {
			f.srv.postAuthzResponse(w, r, "https://rp.test/cb", responseParams{Code: "c", State: "s"})
		},
		"SAML":          func(w http.ResponseWriter) { f.srv.postSAMLResponse(w, r, "https://sp.test/acs", "<r/>", "relay") },
		"WS-Federation": func(w http.ResponseWriter) { f.srv.wsFedPost(w, r, "https://rp.test/reply", "<r/>", "ctx") },
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			send(rec)
			csp := rec.Header().Get("Content-Security-Policy")
			m := scriptNonce.FindStringSubmatch(rec.Body.String())
			if m == nil {
				t.Fatalf("the page does not submit itself: %s", rec.Body.String())
			}
			if !strings.Contains(csp, "script-src 'nonce-"+m[1]+"'") {
				t.Errorf("the policy will not run the page's own script (nonce %s): %s", m[1], csp)
			}
			// Chrome applies form-action to every redirect the form starts, so naming
			// the relying party would stop it redirecting anywhere of its own.
			if strings.Contains(csp, "form-action") {
				t.Errorf("the policy restricts a form whose purpose is another origin: %s", csp)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control %q on a page holding a credential", got)
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("the page can be framed: %q", csp)
			}
		})
	}

	t.Run("front-channel logout", func(t *testing.T) {
		rec := httptest.NewRecorder()
		f.srv.renderFrontChannelLogout(rec, r, []frontChannelTarget{{URL: "https://rp.test/fc"}}, "/login")
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-src https:") {
			t.Errorf("the policy will not load the page's frames: %s", csp)
		}
		if !strings.Contains(rec.Body.String(), `src="https://rp.test/fc"`) {
			t.Errorf("no frame: %s", rec.Body.String())
		}
	})
}
