package adminapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Which authorization servers a client may have an ID-JAG for (specs/id-jag.txt), as
// `signari client id-jag-allow` keeps them.

type idJAGAudienceView struct {
	Audience       string   `json:"audience"`
	RemoteClientID string   `json:"remote_client_id"`
	Resources      []string `json:"resources"`
	Scopes         []string `json:"scopes"`
	Alg            string   `json:"alg"`
}

// putIDJAGAudienceRequest is `client id-jag-allow`.
type putIDJAGAudienceRequest struct {
	Audience       string   `json:"audience"`
	RemoteClientID string   `json:"remote_client_id"`
	Resources      []string `json:"resources"`
	Scopes         []string `json:"scopes"`
	// Alg signs the grant, RS256 when empty.
	Alg string `json:"alg"`
}

func (s *Server) listIDJAGAudiences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.IDJAGAudiences(ctx, s.db, clientID)
	if err != nil {
		s.log.Error("listing id-jag audiences", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]idJAGAudienceView, 0, len(got))
	for _, a := range got {
		out = append(out, idJAGAudienceView{Audience: a.Audience, RemoteClientID: a.RemoteClientID,
			Resources: nonNilStrings(a.Resources), Scopes: nonNilStrings(a.Scopes), Alg: a.Alg})
	}
	s.writeList(w, r, map[string]any{"client_id": clientID, "audiences": out})
}

func (s *Server) putIDJAGAudience(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req putIDJAGAudienceRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	entry := store.IDJAGAudience{ClientID: clientID, Audience: strings.TrimSpace(req.Audience),
		RemoteClientID: strings.TrimSpace(req.RemoteClientID), Resources: req.Resources, Scopes: req.Scopes, Alg: req.Alg}
	if err := entry.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_audience", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		orgID, err := clientOrg(ctx, tx, clientID)
		if err != nil {
			return err
		}
		if err := store.SetIDJAGAudience(ctx, tx, entry); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.id_jag_audience_set", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			ClientID: clientID, Detail: map[string]any{"audience": entry.Audience, "remote_client_id": entry.RemoteClientID,
				"resources": entry.Resources, "scopes": entry.Scopes}})
	})
	if s.writeIDJAGFailure(w, err, clientID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"client_id": clientID, "audience": entry.Audience, "config_version": version})
}

// deleteIDJAGAudience takes the entry ?audience= names away. A grant already out lasts its
// few minutes.
func (s *Server) deleteIDJAGAudience(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	audience := r.URL.Query().Get("audience")
	if audience == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_audience",
			"detail": "name it with ?audience="})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		orgID, err := clientOrg(ctx, tx, clientID)
		if err != nil {
			return err
		}
		if err := store.RemoveIDJAGAudience(ctx, tx, clientID, audience); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.id_jag_audience_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID, Detail: map[string]any{"audience": audience}})
	})
	if s.writeIDJAGFailure(w, err, clientID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"client_id": clientID, "audience": audience, "removed": true,
		"config_version": version})
}

func (s *Server) writeIDJAGFailure(w http.ResponseWriter, err error, clientID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case errors.Is(err, errNotFound), errors.Is(err, store.ErrClientNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
	case errors.Is(err, store.ErrIDJAGAudienceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "audience_not_found"})
	case errors.Is(err, store.ErrInvalidClientSetting):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_audience", "detail": err.Error()})
	default:
		s.log.Error("writing an id-jag audience", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
