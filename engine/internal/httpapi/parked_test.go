package httpapi

import (
	"net/url"
	"testing"

	"signari.dev/engine/internal/oidc"
)

// TestParkedReturnRefusesAnythingOffOrigin.
//
// This runs immediately after a successful sign-in, which makes it a prime
// phishing sink: the user checked the URL, saw our domain, typed their
// password, and is then handed to somebody else.
func TestParkedReturnRefusesAnythingOffOrigin(t *testing.T) {
	attacks := []string{
		"https://evil.test/",
		"//evil.test/",
		"///evil.test",
		"/\\evil.test",
		"/\\/evil.test",
		"\\\\evil.test",
		"http:/evil.test",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"//evil.test/%2e%2e",
		" //evil.test",
	}
	for _, a := range attacks {
		q := url.Values{"return": {a}}.Encode()
		if dest, ok := parkedReturn(q); ok {
			t.Errorf("ACCEPTED %q -> would redirect a just-authenticated user to %q", a, dest)
		}
	}
}

func TestParkedReturnAcceptsLocalPaths(t *testing.T) {
	for _, good := range []string{
		"/proxy/start",
		"/proxy/start?rd=http%3A%2F%2Fn8n.localhost%3A5678%2Fworkflows",
		"/saml/sso?SAMLRequest=abc&RelayState=xyz",
		"/",
	} {
		q := url.Values{"return": {good}}.Encode()
		dest, ok := parkedReturn(q)
		if !ok {
			t.Errorf("refused the local path %q", good)
			continue
		}
		if dest != good {
			t.Errorf("parkedReturn(%q) = %q", good, dest)
		}
	}
}

// TestResumeAfterSignInStillReplaysOIDC -- the ordinary case must not regress.
func TestResumeAfterSignInStillReplaysOIDC(t *testing.T) {
	q := "response_type=code&client_id=web&scope=openid"
	if got := resumeAfterSignIn(q); got != oidc.PathAuthorize+"?"+q {
		t.Errorf("resumeAfterSignIn = %q, want the authorization endpoint replay", got)
	}
}

// TestResumeAfterSignInHonoursReturn is the bug this was written for: forward
// auth parked a return path and sign-in sent the browser to the authorization
// endpoint instead, so the entire not-yet-signed-in half of forward auth was
// broken. No test caught it because every test signed in first.
func TestResumeAfterSignInHonoursReturn(t *testing.T) {
	q := url.Values{"return": {"/proxy/start?rd=http%3A%2F%2Fn8n.localhost%3A5678%2F"}}.Encode()
	got := resumeAfterSignIn(q)
	want := "/proxy/start?rd=http%3A%2F%2Fn8n.localhost%3A5678%2F"
	if got != want {
		t.Errorf("resumeAfterSignIn = %q, want %q", got, want)
	}
}
