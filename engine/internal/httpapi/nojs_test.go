package httpapi

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)


// loginPage renders the sign-in form.
func renderedLoginPage(t *testing.T, s *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	s.handleLoginGet(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login answered %d", rec.Code)
	}
	return rec.Body.String()
}

// TestTheSignInFormNeedsNoJavaScript.
func TestTheSignInFormNeedsNoJavaScript(t *testing.T) {
	body := renderedLoginPage(t, newCSRFServer())

	// A real form with a real method and action, not a div wired up by script.
	if !regexp.MustCompile(`(?i)<form[^>]*method="POST"[^>]*action="/login"`).MatchString(body) {
		t.Error("the sign-in form is not a plain POST form; a driver that does not " +
			"run scripts cannot submit it")
	}
	// A real submit button. type="button" would need a handler to do anything.
	if !strings.Contains(body, `<button type="submit">`) {
		t.Error("the form has no submit button, so nothing submits it without script")
	}
	for _, field := range []string{`name="username"`, `name="password"`, `name="` + csrfFormField + `"`} {
		if !strings.Contains(body, field) {
			t.Errorf("the form does not carry %s, so a scriptless submission is incomplete", field)
		}
	}
}

// TestNoControlOnTheSignInPageIsInertWithoutScript.
//
// A button that is visible and does nothing when pressed is worse than one that
// is absent: it reads as broken software rather than as a feature this browser
// does not have.
//
// The passkey button used to be exactly that. It is `type="button"`, so it does
// nothing on its own; passkey.js attached a click listener but never revealed it,
// so with scripting off -- or on a browser without WebAuthn -- it sat there
// inviting a press that did nothing. It is now hidden in the markup and revealed
// by the script only when PublicKeyCredential exists.
func TestNoControlOnTheSignInPageIsInertWithoutScript(t *testing.T) {
	body := renderedLoginPage(t, newCSRFServer())

	// Every button that is not a submit must be hidden until script reveals it.
	buttons := regexp.MustCompile(`<button[^>]*>`).FindAllString(body, -1)
	if len(buttons) == 0 {
		t.Fatal("the page has no buttons at all, which cannot be right")
	}
	for _, b := range buttons {
		if strings.Contains(b, `type="submit"`) {
			continue
		}
		id := regexp.MustCompile(`id="([^"]*)"`).FindStringSubmatch(b)
		name := "(unnamed)"
		if len(id) > 1 {
			name = id[1]
		}
		// Its row must carry `hidden`, so a scriptless browser never shows it.
		if !hiddenRowFor(body, name) {
			t.Errorf("the %s button is type=\"button\" and its row is not hidden; "+
				"without script it is a control that does nothing when pressed", name)
		}
	}
}

// hiddenRowFor reports whether the element wrapping a button carries `hidden`.
func hiddenRowFor(body, buttonID string) bool {
	i := strings.Index(body, `id="`+buttonID+`"`)
	if i < 0 {
		return false
	}
	// Look back to the enclosing tag and check for a hidden attribute on it.
	start := strings.LastIndex(body[:i], "<p ")
	if start < 0 {
		return false
	}
	return strings.Contains(body[start:i], "hidden")
}
