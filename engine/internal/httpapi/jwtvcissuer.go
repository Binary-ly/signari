package httpapi

import (
	"net/http"

	"net/url"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
	"strings"
)

func jwtVCIssuerPath(issuer string) string {
	const wk = "/.well-known/jwt-vc-issuer"
	u, err := url.Parse(issuer)
	if err != nil {
		return wk
	}
	// §3.1: "If the iss value contains a path component, any terminating / MUST
	// be removed before inserting /.well-known/ and the well-known URI suffix".
	p := strings.TrimSuffix(u.Path, "/")
	if p == "" {
		return wk
	}
	return wk + p
}

// handleJWTVCIssuerMetadata serves §3.2's configuration.
func (s *Server) handleJWTVCIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	// Published only when this deployment issues credentials, the same rule the
	// credential issuer metadata follows: a document naming a capability is one a
	// verifier will act on, and an issuer with no configurations has no
	// credentials for anybody to verify.
	configs, err := store.AllCredentialConfigurations(r.Context(), s.db)
	if err != nil {
		s.log.Error("loading credential configurations", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if len(configs) == 0 {
		writeError(w, http.StatusNotFound, "not_found",
			"this deployment issues no credentials")
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		// §3.2: REQUIRED, and §3.3 makes it the check a verifier performs —
		// "The issuer value returned MUST be identical to the iss value of the
		// Issuer-signed JWT. If these values are not identical, the data
		// contained in the response MUST NOT be used." So this must be the same
		// string the credential carries, not a normalised variant of it.
		"issuer": s.cfg.Issuer,
		// §3.2: "MUST include either jwks_uri or jwks in their JWT VC Issuer
		// Metadata, BUT NOT BOTH." By reference rather than by value, so key
		// rotation is visible at one URL rather than needing this document
		// re-fetched — and so there is one place a verifier and a relying party
		// both read our keys from.
		"jwks_uri": s.cfg.Issuer + oidc.PathJWKS,
	})
}
