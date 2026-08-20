package clients

import (
	"strings"
	"testing"
)


func TestValidateRedirectURIRefusesTheDangerousShapes(t *testing.T) {
	for _, c := range []struct{ name, uri, want string }{
		{
			"a wildcard", "https://app.example/*", "wildcard",
		},
		{
			// CVE-2026-7504 defeated Java's parse of exactly this component.
			"user-info before the host",
			"https://good.example@evil.example/cb", "user information",
		},
		{
			"several @, the CVE-2026-7504 shape",
			"https://good.example@@evil.example/cb", "user information",
		},
		{
			// The response appends `code`; a relying party reading the FIRST
			// occurrence reads the registered one instead.
			"code in the query", "https://app.example/cb?code=attacker", "code",
		},
		{
			"state in the query", "https://app.example/cb?state=fixed", "state",
		},
		{
			"id_token in the fragment",
			"https://app.example/cb#id_token=attacker", "id_token",
		},
		{
			"iss in the query, the mix-up parameter",
			"https://app.example/cb?iss=https://evil.example", "iss",
		},
		{
			"http on a non-loopback host",
			"http://app.example/cb", "in the clear",
		},
		{
			"relative", "/callback", "absolute",
		},
		{
			"empty", "", "required",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRedirectURI(c.uri)
			if err == nil {
				t.Fatalf("%q was accepted", c.uri)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// Refusing the dangerous shapes is easy; the work is not refusing the ordinary
// ones. A validator that rejects legitimate registrations is one an operator
// works around.
func TestValidateRedirectURIAcceptsTheOrdinaryShapes(t *testing.T) {
	for _, uri := range []string{
		"https://app.example/callback",
		"https://app.example/callback?tenant=acme",  // a query, just not a response param
		"https://app.example/cb#section",            // a plain fragment
		"http://localhost:8080/callback",            // RFC 8252 native app
		"http://127.0.0.1:1234/cb",                  // RFC 8252, ephemeral port
		"com.example.app:/oauth2redirect",           // RFC 8252 private-use scheme
		"https://app.example/cb?code_challenge=abc", // not `code`; must not false-positive
	} {
		if err := ValidateRedirectURI(uri); err != nil {
			t.Errorf("%q was refused: %v", uri, err)
		}
	}
}

// Exact matching, with nothing clever about it.
func TestHasRedirectURIIsExact(t *testing.T) {
	c := &Client{RedirectURIs: []string{"https://app.example/cb"}}
	if !c.HasRedirectURI("https://app.example/cb") {
		t.Fatal("the registered URI did not match itself")
	}
	for _, near := range []string{
		"https://app.example/cb/",     // trailing slash
		"https://app.example/cb?x=1",  // extra query
		"https://app.example:443/cb",  // default port spelled out
		"https://APP.EXAMPLE/cb",      // different case
		"https://app.example/CB",      // different path case
		"https://app.example/cb#f",    // fragment
		"https://app.example.evil/cb", // suffix attack
		"https://app.example/cb%2f",   // percent-encoded
	} {
		if c.HasRedirectURI(near) {
			t.Errorf("%q matched a registration it is not identical to", near)
		}
	}
}

// The one exception to exact matching, and it is a MUST in two specifications.
//
// RFC 9700 §4.1.3: "The only exception is native apps using a localhost URI: In
// this case, the authorization server MUST allow variable port numbers as
// described in Section 7.3 of [RFC8252]."
//
// RFC 8252 §7.3: "The authorization server MUST allow any port to be specified
// at the time of the request for loopback IP redirect URIs, to accommodate
// clients that obtain an available ephemeral port from the operating system at
// the time of the request."
//
// Pure string equality refused this, which does not make a native app's flow
// stricter -- it makes it impossible. A desktop app cannot know its port before
// asking the operating system for one.
func TestALoopbackRedirectMayUseAnyPort(t *testing.T) {
	c := &Client{RedirectURIs: []string{"http://127.0.0.1:1234/cb"}}

	for _, ok := range []string{
		"http://127.0.0.1:51004/cb", // the ephemeral port RFC 8252 gives as its example shape
		"http://127.0.0.1:1234/cb",  // the registered one still matches
		"http://127.0.0.1:65535/cb",
	} {
		if !c.HasRedirectURI(ok) {
			t.Errorf("%q was refused; RFC 8252 §7.3 requires any port to be allowed", ok)
		}
	}

	// The port is the ONLY thing that may vary.
	for _, bad := range []string{
		"http://127.0.0.1:51004/other",  // different path
		"http://127.0.0.1:51004/cb?x=1", // added query
		"http://127.0.0.1:51004/cb#f",   // added fragment
		"https://127.0.0.1:51004/cb",    // different scheme
		"http://[::1]:51004/cb",         // a DIFFERENT loopback address
		"http://localhost:51004/cb",     // also a different host
		"http://127.0.0.2:51004/cb",     // not loopback at all
		"http://evil.example:51004/cb",  // certainly not
	} {
		if c.HasRedirectURI(bad) {
			t.Errorf("%q matched a loopback registration it differs from by more "+
				"than the port", bad)
		}
	}
}

// The exception must not leak into non-loopback registrations. A client
// registered for a public host gets exact matching and nothing else.
func TestThePortExceptionIsOnlyForLoopback(t *testing.T) {
	c := &Client{RedirectURIs: []string{"https://app.example/cb"}}
	for _, bad := range []string{
		"https://app.example:8443/cb",
		"http://app.example:80/cb",
		"http://127.0.0.1:9000/cb", // a loopback CANDIDATE against a public registration
	} {
		if c.HasRedirectURI(bad) {
			t.Errorf("%q matched a non-loopback registration on a port variation; "+
				"the exception is for native apps, not a general relaxation", bad)
		}
	}

	// And the reverse: a loopback registration must not authorise a public host.
	loop := &Client{RedirectURIs: []string{"http://127.0.0.1:1234/cb"}}
	if loop.HasRedirectURI("http://evil.example:1234/cb") {
		t.Error("a loopback registration authorised a public host")
	}
}

// TestOnlyTheThreePermittedSchemesAreAccepted.
//
// A redirect URI is where the authorization code is delivered, so the set of
// schemes that may appear in one is a security boundary rather than a matter of
// taste. RFC 8252 names the three: https, http on a loopback address for native
// apps, and a private-use scheme in reverse-domain form.
//
// This rule existed only in the dynamic-registration path, whose comment claimed
// it "applies the same rules an operator-registered client gets". It did not:
// there were two validators and this one -- used by the CLI and the admin API --
// checked only that http was confined to loopback. Everything else passed,
// including `javascript:`, `data:` and `file:`.
//
// It takes an operator to register one, and a browser will not navigate to
// `javascript:` from a Location header, so nothing was on fire. The code is
// still appended to whatever is registered, and an embedded webview is far less
// careful than a browser.
func TestOnlyTheThreePermittedSchemesAreAccepted(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"ftp://example.com/cb",
	} {
		if err := ValidateRedirectURI(bad); err == nil {
			t.Errorf("%q was accepted as a redirect URI; the authorization code is "+
				"appended to whatever is registered here", bad)
		}
	}

	for _, good := range []string{
		"https://app.example/cb",
		"http://127.0.0.1:8080/cb",
		"http://localhost:3000/callback",
		"http://[::1]:9000/cb",
		"com.example.app:/oauth2redirect",
	} {
		if err := ValidateRedirectURI(good); err != nil {
			t.Errorf("%q is a legitimate redirect URI and was refused: %v", good, err)
		}
	}
}
