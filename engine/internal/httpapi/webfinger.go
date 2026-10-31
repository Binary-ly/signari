package httpapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

const (
	webFingerIssuerRel = "http://openid.net/specs/connect/1.0/issuer"
	// webFingerResourceLimit is more than an account URI needs.
	webFingerResourceLimit = 1024
)

// handleWebFinger answers which issuer speaks for an account, the first step of OpenID
// Connect discovery (9.13). The same answer whoever is named, since an instance has one
// issuer: nothing is looked up, so this cannot be asked who exists here. RFC 7033 and
// OIDC Discovery are not in specs/; the shape was read from another implementation
// (`providers/oauth2/models.py:485`, `brands/views/webfinger.py`).
func (s *Server) handleWebFinger(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	resource := query.Get("resource")
	if resource == "" || len(resource) > webFingerResourceLimit || !strings.Contains(resource, ":") {
		http.Error(w, "give a resource, as a URI", http.StatusBadRequest)
		return
	}
	links := []map[string]string{}
	if rels := query["rel"]; len(rels) == 0 || slices.Contains(rels, webFingerIssuerRel) {
		links = append(links, map[string]string{"rel": webFingerIssuerRel, "href": s.cfg.Issuer})
	}
	w.Header().Set("Content-Type", "application/jrd+json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]any{"subject": resource, "links": links})
}
