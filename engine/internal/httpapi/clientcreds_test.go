package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No handler may read client credentials out of the form by itself.
//
// Every endpoint a client calls directly has to resolve credentials the same
// way, because each specification says so about its own endpoint:
//
//	RFC 9126 §2 (PAR): "The rules for client authentication as defined in
//	[RFC6749] for token endpoint requests, including the applicable
//	authentication methods, apply for the PAR endpoint as well."
//	RFC 8628 §3.1 (device authorization): a confidential client authenticates
//	as described in RFC 6749 §3.2.1 -- the token endpoint's rule.
//
// The resolution lived inside oauth.ParseTokenRequest, so only the token
// endpoint had it. PAR and the device authorization endpoint each did
// `r.PostForm.Get("client_secret")` and nothing else, which meant a client
// registered for client_secret_basic -- the one method RFC 6749 §2.3.1 says a
// server MUST support -- could not use either endpoint, while discovery
// advertised the method.
//
// A comment saying "use the shared resolver" does not survive the next handler
// somebody adds. This does: reading the secret directly is the shape of the
// bug, so the shape is what is banned.
func TestNoHandlerReadsClientCredentialsDirectly(t *testing.T) {
	// The one legitimate reader is the shared resolver itself, which lives in
	// package oauth, not here.
	const banned = `PostForm.Get("client_secret")`

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, banned) {
				t.Errorf("%s:%d reads the client secret straight out of the "+
					"form:\n\t%s\nUse oauth.ParseClientCredentials, which also "+
					"understands HTTP Basic, refuses credentials presented in "+
					"two places, and refuses a body client_id naming a "+
					"different client than the header.",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// The endpoints that must use the shared resolver, named explicitly.
//
// The test above bans the wrong shape; this one requires the right one, so an
// endpoint cannot pass by simply not authenticating anybody at all.
func TestDirectRequestEndpointsUseTheSharedResolver(t *testing.T) {
	for _, file := range []string{
		"par.go",    // RFC 9126 §2
		"device.go", // RFC 8628 §3.1
	} {
		src, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "oauth.ParseClientCredentials(") {
			t.Errorf("%s does not call oauth.ParseClientCredentials. A client "+
				"registered for client_secret_basic cannot authenticate to this "+
				"endpoint, and discovery advertises that method.", file)
		}
	}
}
