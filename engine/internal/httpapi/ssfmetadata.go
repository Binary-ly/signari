package httpapi

import (
	"net/http"
	"strings"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/ssf"
)

func (s *Server) handleSSFMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.cfg.Issuer, "/")
	md := ssf.Metadata(issuer, issuer+oidc.PathJWKS)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, md)
}
