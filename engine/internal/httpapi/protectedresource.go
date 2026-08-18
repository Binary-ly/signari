package httpapi

import (
	"net/http"
	"strings"

	"signari.dev/engine/internal/dpop"
)

// OAuth 2.0 Protected Resource Metadata (RFC 9728).
//
// # Why an authorization server publishes this
//
// Signari is not only an authorization server. It is also a protected resource
// for its own `/oauth2/userinfo`, which takes an access token and returns
// claims. RFC 9728 is how a resource tells a client which authorization servers
// can issue tokens for it, and §3 makes publishing it a MUST for any protected
// resource that supports metadata.
//
// # The reason this matters beyond conformance
//
// The Model Context Protocol authorization specification builds its entire
// discovery flow on this document:
//
//	"MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728).
//	MCP clients MUST use OAuth 2.0 Protected Resource Metadata for authorization
//	server discovery."
//
// An MCP client's first request arrives with no token, gets a 401, reads
// `resource_metadata` out of the WWW-Authenticate header, fetches that document,
// finds the authorization server, and only then begins an OAuth flow. Without
// the header and the document, that discovery has nowhere to start -- so an MCP
// server protected by Signari cannot be reached by a conformant client at all.

// protectedResourcePath is §3's default well-known URI.
const protectedResourcePath = "/.well-known/oauth-protected-resource"

// resourceMetadataURL is the absolute URL of our own metadata document.
//
// Built from the configured issuer, never the Host header. A client is told
// where to fetch a document that names which authorization servers to trust; a
// caller who could influence that address would be choosing the answer.
func (s *Server) resourceMetadataURL() string {
	return strings.TrimRight(s.cfg.Issuer, "/") + protectedResourcePath
}

// handleProtectedResourceMetadata serves RFC 9728 §2 metadata.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.cfg.Issuer, "/")

	md := map[string]any{
		// REQUIRED (§2). The resource identifier, which for us is the issuer:
		// a token audienced to it is one this server will accept at its own
		// resource endpoints.
		"resource": base,
		// The authorization server that can issue tokens for this resource is
		// this same deployment. MCP's discovery flow requires at least one.
		"authorization_servers": []string{base},

		// RECOMMENDED (§2). Only the scopes that actually mean something at a
		// resource endpoint -- advertising every scope the authorization server
		// knows would tell a client to ask for grants this resource ignores.
		"scopes_supported": []string{"openid", "profile", "email", "groups"},

		// Both schemes, because both are accepted at /oauth2/userinfo. RFC 9449
		// §7.1 requires a sender-constrained token to be presented with the DPoP
		// scheme, and §7.2 requires us to refuse one presented as Bearer -- so
		// naming only one here would misdescribe what the resource accepts.
		"bearer_methods_supported":          []string{"header"},
		"dpop_signing_alg_values_supported": strings.Split(dpop.SupportedAlgs(), " "),
		// §7.2 of RFC 9449: a resource that requires DPoP says so. We do not
		// require it -- a token without `cnf` is accepted as a bearer token --
		// so this is deliberately absent rather than false.

		"resource_documentation": base + "/.well-known/openid-configuration",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSONBody(w, md)
}

// resourceMetadataChallenge returns the WWW-Authenticate parameter §5.1 defines.
//
// §5.1: "This specification introduces a new parameter in the WWW-Authenticate
// HTTP response header field to indicate the protected resource metadata URL."
//
// It is what turns a 401 into something a client can act on without being
// configured in advance: the client reads this, fetches the document, learns
// which authorization server to talk to, and starts a flow. Without it a 401 is
// just a refusal.
func (s *Server) resourceMetadataChallenge() string {
	return `resource_metadata="` + s.resourceMetadataURL() + `"`
}
