package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Each place error_description is written either says something fixed or goes through
// oauth.ErrorText, so that no sentence built anywhere can put a quote in the field.
// Read from the source, so a new writer cannot be left off a list.
func TestEveryErrorDescriptionIsWrittenThroughErrorText(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	writer := regexp.MustCompile(`"error_description"(?:: *|, *)([^,}\n]+)`)
	fixed := regexp.MustCompile(`^"[^"\\]*"\)?$`)
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range writer.FindAllStringSubmatch(string(source), -1) {
			checked++
			value := strings.TrimSpace(m[1])
			if !strings.HasPrefix(value, "oauth.ErrorText(") && !fixed.MatchString(value) {
				t.Errorf("%s writes error_description from %s, which can hold what RFC 6749 §5.2 forbids; "+
					"go through oauth.ErrorText", file, value)
			}
		}
	}
	if checked < 8 {
		t.Fatalf("only %d writers were found: this is reading the source wrong", checked)
	}
}

// The characters reach the wire as the RFC has them, whichever way a refusal goes.
func TestARefusalCarriesOnlyWhatTheRFCAllows(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "invalid_request", `the value "x\y" is wrong`)
	if body := rec.Body.String(); strings.Contains(body, `\"`) || strings.Contains(body, `\\`) {
		t.Errorf("writeError sent %s", body)
	}
	if got := (responseParams{Error: "invalid_request", ErrorDescription: `the value "x"`}).values().Get("error_description"); strings.ContainsAny(got, `"\`) {
		t.Errorf("a redirect carries %q", got)
	}
}

// What a request says goes back to the client that sent the person here, on the front
// channel, so none of it is repeated: a link could otherwise have a client's own page
// show whatever the link says.
func TestARedirectDoesNotRepeatWhatTheRequestSaid(t *testing.T) {
	f := newSignInFixture(t)
	cookie := f.signInAndReturnCookie(t)
	const planted = "Call-0800-now"
	for name, extra := range map[string]url.Values{
		"response_type":         {"response_type": {planted}},
		"response_mode":         {"response_mode": {planted}},
		"code_challenge_method": {"code_challenge_method": {planted}},
	} {
		rec := f.authorizeWith(t, cookie, extra)
		location := rec.Header().Get("Location")
		if !strings.Contains(location, "error=") {
			t.Fatalf("%s came to %d %q", name, rec.Code, location)
		}
		if strings.Contains(location, planted) {
			t.Errorf("%s was repeated: %s", name, location)
		}
	}
}
