package adminapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Whose client_id URLs this instance will fetch a metadata document from, as `signari
// client-metadata` manages them. A rule can put a stranger's client in any organisation
// of the instance, so only a deployment-wide token touches the list.

type clientMetadataRuleView struct {
	URLPrefix string   `json:"url_prefix"`
	OrgID     string   `json:"org_id"`
	Scopes    []string `json:"scopes"`
}

// putClientMetadataRuleRequest is `client-metadata allow`.
type putClientMetadataRuleRequest struct {
	URLPrefix string   `json:"url_prefix"`
	OrgID     string   `json:"org_id"`
	Scopes    []string `json:"scopes"`
}

func (s *Server) listClientMetadataRules(w http.ResponseWriter, r *http.Request) {
	instanceID, _, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	got, err := store.ClientMetadataRules(r.Context(), s.db, instanceID)
	if err != nil {
		s.log.Error("listing client metadata rules", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]clientMetadataRuleView, 0, len(got))
	for _, rule := range got {
		out = append(out, clientMetadataRuleView{URLPrefix: rule.URLPrefix, OrgID: rule.OrgID, Scopes: nonNilStrings(rule.Scopes)})
	}
	s.writeList(w, r, map[string]any{"instance_id": instanceID, "rules": out})
}

func (s *Server) putClientMetadataRule(w http.ResponseWriter, r *http.Request) {
	instanceID, _, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req putClientMetadataRuleRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	rule := store.ClientMetadataRule{URLPrefix: strings.TrimSpace(req.URLPrefix), OrgID: req.OrgID, Scopes: req.Scopes}
	if err := rule.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_rule", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, rule.OrgID); err != nil {
			return err
		}
		if err := store.SetClientMetadataRule(ctx, tx, instanceID, rule); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.client_metadata_rule_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: rule.OrgID, Detail: map[string]any{"instance_id": instanceID, "url_prefix": rule.URLPrefix,
				"scopes": rule.Scopes}})
	})
	if errors.Is(err, store.ErrClientMetadataOrgElsewhere) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_rule", "detail": err.Error()})
		return
	}
	if writeOrgRefusal(w, err) || s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instanceID, "url_prefix": rule.URLPrefix,
		"config_version": version})
}

// deleteClientMetadataRule takes the rule ?url_prefix= names off the list, and with it
// every client it admitted.
func (s *Server) deleteClientMetadataRule(w http.ResponseWriter, r *http.Request) {
	instanceID, _, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	prefix := r.URL.Query().Get("url_prefix")
	if prefix == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_rule",
			"detail": "name the rule with ?url_prefix="})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var gone int64
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var rerr error
		if gone, rerr = store.RemoveClientMetadataRule(ctx, tx, instanceID, prefix); rerr != nil {
			return rerr
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.client_metadata_rule_removed", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "url_prefix": prefix, "clients_removed": gone}})
	})
	if errors.Is(err, store.ErrClientMetadataRuleUnknown) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule_not_found"})
		return
	}
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instanceID, "url_prefix": prefix, "removed": true,
		"clients_removed": gone, "config_version": version})
}
