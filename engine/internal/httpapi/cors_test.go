package httpapi

import (
	"os"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oidc"
)

// RFC 9700 §2.6, and it is the only MUST NOT in the section:
//
//	"CORS MUST NOT be supported at the authorization endpoint, as the client
//	does not access this endpoint directly; instead, the client redirects the
//	user agent to it."
//
// The authorization endpoint is reached by navigation, never by fetch. Its
// response may already carry an authorization code, so a script able to read it
// cross-origin turns a redirect-based flow into a readable one.
//
// This is a test rather than a comment because the policy is a switch statement,
// and the natural way to add the next OAuth endpoint to it is to widen a case
// that already lists several `/oauth2/...` paths.
func TestTheAuthorizationEndpointNeverGetsCORS(t *testing.T) {
	if mode := corsPolicyFor(oidc.PathAuthorize); mode != corsNone {
		t.Fatalf("CORS policy for the authorization endpoint is %v, want none. "+
			"RFC 9700 §2.6 makes this a MUST NOT: the endpoint is reached by "+
			"navigation, and its response can carry an authorization code.", mode)
	}
	// The screens a person interacts with are in the same category and for the
	// same reason.
	for _, p := range []string{"/login", "/device", "/account", oidc.PathEndSession} {
		if corsPolicyFor(p) != corsNone {
			t.Errorf("%s has a CORS policy; browser-facing screens must not", p)
		}
	}
}

// The endpoints a client's own script legitimately calls.
func TestTheClientFacingEndpointsGetCORS(t *testing.T) {
	for _, p := range []string{
		oidc.PathToken, oidc.PathUserinfo, oidc.PathRevocation,
		oidc.PathIntrospection, "/oauth2/par", "/oauth2/device_authorization",
	} {
		if corsPolicyFor(p) != corsClientOrigin {
			t.Errorf("%s does not allow a registered client origin; a "+
				"single-page application cannot call it", p)
		}
	}
	// Public documents a library must read before it knows any origin.
	for _, p := range []string{oidc.PathDiscovery, oidc.PathJWKS} {
		if corsPolicyFor(p) != corsPublic {
			t.Errorf("%s is not readable cross-origin; a client library cannot "+
				"configure itself from it", p)
		}
	}
}

// An Origin is scheme://host[:port] and nothing else. Anything with a path,
// query, fragment or user-info is not one, and matching a malformed value
// against a derived list is how a suffix match gets in.
func TestOnlyAWellFormedOriginCanMatch(t *testing.T) {
	s := &Server{}
	// Prime the cache directly so this needs no database.
	s.originsCache = []string{"https://app.example"}
	s.originsExpire = farFuture()

	for _, ok := range []string{"https://app.example"} {
		if !s.originRegistered(t.Context(), ok) {
			t.Errorf("%q was refused but is registered", ok)
		}
	}
	for _, bad := range []string{
		"https://app.example.evil",     // suffix attack
		"https://evil.app.example",     // prefix attack
		"http://app.example",           // different scheme
		"https://app.example:8443",     // different port
		"https://app.example/callback", // an Origin has no path
		"https://user@app.example",     // user-info
		"https://app.example?x=1",
		"https://app.example#f",
		"null",
		"",
		"*",
	} {
		if s.originRegistered(t.Context(), bad) {
			t.Errorf("%q was accepted as a registered origin", bad)
		}
	}
}

// Credentials are never allowed, on any endpoint.
//
// Our session cookie is `__Host-` and SameSite=Lax so it does not travel
// cross-site. Setting Access-Control-Allow-Credentials would undo that on
// exactly the endpoints where it matters, and no real OAuth client needs it:
// clients authenticate with a secret or an assertion in the request itself.
func TestCredentialsAreNeverAllowed(t *testing.T) {
	// Comment lines are skipped: cors.go names the header in prose precisely to
	// record why it is absent, and a test that cannot tell an explanation from
	// an implementation would force the explanation to be deleted.
	for i, line := range strings.Split(readSource(t, "cors.go"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if strings.Contains(line, "Access-Control-Allow-Credentials") {
			t.Fatalf("cors.go:%d sets Access-Control-Allow-Credentials:\n\t%s\n"+
				"Combined with a reflected origin this lets a cross-origin script "+
				"make credentialed requests carrying the user's session cookie, "+
				"which is what __Host- and SameSite=Lax exist to prevent.",
				i+1, strings.TrimSpace(line))
		}
	}
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
