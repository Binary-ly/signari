package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/store"
)

// An organisation's own words on its pages and in its mail (10.09). A tenant's
// to change, as nobody else reads them: they are plain text, escaped on the way
// to a page, so a token that may set them still cannot put markup on one.

type orgMessageView struct {
	Locale string `json:"locale"`
	Key    string `json:"key"`
	Text   string `json:"text"`
}

// putOrgMessageRequest rewords one message in one language.
type putOrgMessageRequest struct {
	Text string `json:"text"`
}

func (s *Server) listOrgMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.OrgMessages(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing an organisation's messages", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]orgMessageView, 0, len(got))
	for _, m := range got {
		out = append(out, orgMessageView{Locale: m.Locale, Key: m.Key, Text: m.Body})
	}
	s.writeList(w, r, map[string]any{"messages": out})
}

func (s *Server) putOrgMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, locale, key := r.PathValue("orgID"), r.PathValue("locale"), r.PathValue("key")
	var req putOrgMessageRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	// Before the version is taken: wording nothing would render is refused here,
	// by name, rather than stored and reported as saved.
	if err := i18n.Shipped().CheckWords(locale, key, req.Text); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_message", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SetOrgMessage(ctx, tx, orgID, store.OrgMessage{Locale: locale, Key: key, Body: req.Text}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.org_message_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"locale": locale, "key": key}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("rewording a message", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"locale": locale, "key": key, "text": req.Text, "config_version": version})
}

func (s *Server) deleteOrgMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, locale, key := r.PathValue("orgID"), r.PathValue("locale"), r.PathValue("key")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		removed, err := store.RemoveOrgMessage(ctx, tx, orgID, locale, key)
		if err != nil {
			return err
		}
		if !removed {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.org_message_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"locale": locale, "key": key}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "message_not_found"})
		return
	case err != nil:
		s.log.Error("removing a message", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
