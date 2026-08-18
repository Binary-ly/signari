package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
)

func prServer() *Server {
	return &Server{cfg: oidc.Config{Issuer: "https://id.example"}}
}

// RFC 9728 §2: `resource` is REQUIRED. The MCP authorization specification adds
// that the document "MUST include the `authorization_servers` field containing
// at least one authorization server" — without it, an MCP client that reaches
// this document still has nowhere to go.
func TestTheProtectedResourceMetadataCarriesWhatDiscoveryNeeds(t *testing.T) {
	w := httptest.NewRecorder()
	prServer().handleProtectedResourceMetadata(w, httptest.NewRequest("GET", "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var md map[string]any
	if err := json.NewDecoder(w.Body).Decode(&md); err != nil {
		t.Fatal(err)
	}

	if md["resource"] != "https://id.example" {
		t.Errorf("resource = %v, want the resource identifier", md["resource"])
	}
	as, ok := md["authorization_servers"].([]any)
	if !ok || len(as) == 0 {
		t.Fatal("no authorization_servers; an MCP client reaching this document " +
			"would still not know which authorization server to use")
	}
	if as[0] != "https://id.example" {
		t.Errorf("authorization_servers[0] = %v", as[0])
	}
}

// The document is built from the configured issuer, never the Host header.
//
// It tells a client which authorization servers to trust for this resource. A
// caller who could influence that address would be choosing the answer to the
// question the document exists to answer.
func TestTheMetadataIgnoresTheHostHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	r.Host = "evil.example"
	r.Header.Set("X-Forwarded-Host", "evil.example")

	w := httptest.NewRecorder()
	prServer().handleProtectedResourceMetadata(w, r)

	body := w.Body.String()
	if strings.Contains(body, "evil.example") {
		t.Fatalf("the Host header reached the metadata document:\n%s", body)
	}
	if !strings.Contains(body, "https://id.example") {
		t.Errorf("the configured issuer is absent: %s", body)
	}
}

// RFC 9728 §5.1: the 401 carries `resource_metadata` naming where to find the
// document. This is the first step of MCP's discovery flow — without it a 401 is
// just a refusal, and a client that was never configured for this server has
// nothing to act on.
func TestTheChallengeNamesTheMetadataURL(t *testing.T) {
	s := prServer()
	got := s.resourceMetadataChallenge()

	const want = `resource_metadata="https://id.example/.well-known/oauth-protected-resource"`
	if got != want {
		t.Fatalf("challenge = %s\nwant       = %s", got, want)
	}
	// The path is §3's default well-known URI, spelled exactly.
	if protectedResourcePath != "/.well-known/oauth-protected-resource" {
		t.Errorf("well-known path = %q", protectedResourcePath)
	}
}

// The unauthenticated 401 from userinfo must carry it, since that is the
// response an MCP client's very first request receives.
func TestTheUnauthenticatedChallengePointsAtTheMetadata(t *testing.T) {
	src := readSource(t, "userinfo.go")
	if !strings.Contains(src, "resourceMetadataChallenge()") {
		t.Fatal("userinfo's 401 does not carry resource_metadata, so a client " +
			"with no prior configuration cannot discover the authorization server")
	}
}
