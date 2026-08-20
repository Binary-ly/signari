package clients

import "testing"

// RFC 8252 §7.3's port exception, and the boundary of it.
//
// §7.3: "the authorization server MUST allow any port to be specified at the
// time of the request for loopback IP redirect URIs, to accommodate clients that
// obtain an available ephemeral port from the operating system at the time of
// the request."
//
// The exception exists because a native app cannot know its port in advance. It
// is scoped to loopback for exactly that reason, and ASVS 5.0 V10.4.1 otherwise
// requires exact string comparison.
//
// The guard that keeps it scoped -- isLoopbackHost on both sides -- survived
// mutation against the ENTIRE test suite, not merely this package's: disabling
// it broke nothing. So the property was implemented and unconstrained, which is
// the state a refactor removes silently.
//
// Without it, any http URI matches port-agnostically on the same host, and a
// client registered for http://app.example.com/cb also accepts a code at
// http://app.example.com:9999/cb -- which matters wherever somebody else can
// listen on another port of the same name: shared hosting, a corporate host with
// user-run services, a compromised sidecar.
func TestThePortExceptionAppliesOnlyToLoopback(t *testing.T) {
	// A non-loopback host gets no latitude, whatever the port.
	nonLoopback := &Client{RedirectURIs: []string{"http://app.example.com/cb"}}
	for _, candidate := range []string{
		"http://app.example.com:9999/cb",
		"http://app.example.com:80/cb",
		"http://app.example.com:8080/cb",
	} {
		if nonLoopback.HasRedirectURI(candidate) {
			t.Errorf("%q was accepted against a registered http://app.example.com/cb; "+
				"RFC 8252 §7.3's any-port rule is for loopback only, and anyone able "+
				"to listen on another port of that host would receive the code",
				candidate)
		}
	}

	// Loopback keeps the exception, or native apps break.
	for _, reg := range []string{"http://127.0.0.1:1234/cb", "http://[::1]:1234/cb"} {
		c := &Client{RedirectURIs: []string{reg}}
		var candidate string
		if reg == "http://127.0.0.1:1234/cb" {
			candidate = "http://127.0.0.1:54321/cb"
		} else {
			candidate = "http://[::1]:54321/cb"
		}
		if !c.HasRedirectURI(candidate) {
			t.Errorf("registered %q refused %q; §7.3 requires any port to be allowed "+
				"for loopback, because the app takes an ephemeral one at request time",
				reg, candidate)
		}
	}

	// The two loopback addresses are different addresses. Registering one is not
	// asking for the other.
	v4 := &Client{RedirectURIs: []string{"http://127.0.0.1:1234/cb"}}
	if v4.HasRedirectURI("http://[::1]:1234/cb") {
		t.Error("a client registered for 127.0.0.1 accepted ::1")
	}

	// https loopback is not the native-app pattern and gets no latitude.
	tls := &Client{RedirectURIs: []string{"https://127.0.0.1:1234/cb"}}
	if tls.HasRedirectURI("https://127.0.0.1:54321/cb") {
		t.Error("an https loopback URI was matched port-agnostically; §7.3 " +
			"constructs the exception as http://127.0.0.1:{port}/{path}")
	}
}
