package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// /account/profile: the attributes an organisation declared, as their owner may
// see and set them (5.05).
//
// Each declaration says whether its subject may read it, write it, and must
// have it; the Admin API stored all three and nothing read them, so a person
// could see none of their profile and set none of it, and a required attribute
// was required of nobody. Now the page shows the readable ones, edits the
// writable ones through the same write the Admin API uses (typed, and sealed
// under the person's key when personal), refuses an attribute the person may
// not write and a required one left empty, and sign-up asks for the writable
// ones with the required ones marked.

// profileField is one attribute on the page, or on the sign-up form.
type profileField struct {
	Name, Label, Type, Value string
	Required, Writable       bool
}

// attributeFormPrefix names a field on the form, so an attribute cannot
// collide with the form's own fields.
const attributeFormPrefix = "attr."

// postedAttributes are the attribute values a form carried.
func postedAttributes(form url.Values) map[string]string {
	out := map[string]string{}
	for k, v := range form {
		if name, ok := strings.CutPrefix(k, attributeFormPrefix); ok && len(v) > 0 {
			out[name] = strings.TrimSpace(v[0])
		}
	}
	return out
}

// profileFields are the organisation's attributes the person may see, or with
// writableOnly those they may set, with their current values and any the form
// just posted.
func (s *Server) profileFields(ctx context.Context, userID, orgID string, writableOnly bool,
	posted map[string]string) ([]profileField, error) {

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	decl, err := store.Attributes(ctx, tx, orgID)
	if err != nil {
		return nil, err
	}
	held := map[string]string{}
	if userID != "" {
		vals, err := store.UserAttributes(ctx, tx, userID, orgID, s.cfg.Root)
		if err != nil {
			return nil, err
		}
		for _, v := range vals {
			if v.Readable {
				held[v.Name] = v.Value
			}
		}
	}
	var out []profileField
	for _, a := range decl {
		if !a.UserReadable || (writableOnly && !a.UserWritable) {
			continue
		}
		f := profileField{Name: a.Name, Label: a.DisplayName, Type: a.ValueType,
			Value: held[a.Name], Required: a.Required, Writable: a.UserWritable}
		if f.Label == "" {
			f.Label = a.Name
		}
		if v, ok := posted[a.Name]; ok && a.UserWritable {
			f.Value = v
		}
		out = append(out, f)
	}
	return out, nil
}

// handleProfile shows the page.
func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/profile"), http.StatusSeeOther)
		return
	}
	s.renderProfile(w, r, userID, orgID, nil, "", "")
}

func (s *Server) renderProfile(w http.ResponseWriter, r *http.Request, userID, orgID string,
	posted map[string]string, message, errMsg string) {

	fields, err := s.profileFields(r.Context(), userID, orgID, false, posted)
	if err != nil {
		s.log.Error("reading the profile", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	editable := false
	for _, f := range fields {
		editable = editable || f.Writable
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, r, "profile", map[string]any{
		"Fields": fields, "Editable": editable, "Message": message, "Error": errMsg,
		"CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleProfilePost saves what the person may set.
func (s *Server) handleProfilePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/profile"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; reload and try again")
		return
	}
	if s.credentialChangeRefused(w, r, sid, "/account/profile", false) {
		return
	}
	posted := postedAttributes(r.PostForm)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	changed, err := store.SetOwnAttributes(ctx, tx, userID, orgID, posted, s.cfg.Root)
	switch {
	case errors.Is(err, store.ErrNoSuchAttribute):
		writeError(w, http.StatusBadRequest, "invalid_request", "that form sets an attribute you cannot set")
		return
	case errors.Is(err, store.ErrAttributeRequired), errors.Is(err, store.ErrInvalidAttributeValue):
		_ = tx.Rollback(ctx)
		s.renderProfile(w, r, userID, orgID, posted, "", err.Error())
		return
	case err != nil:
		s.log.Error("saving the profile", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// Which attributes moved, never their values: the audit trail is
	// append-only, and a personal value in it would outlive the erasure that
	// was meant to destroy it.
	if len(changed) > 0 {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "user.attributes_updated", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"attributes": changed},
		}); err != nil {
			s.log.Error("auditing a profile change", "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.renderProfile(w, r, userID, orgID, nil, s.tr(r).Text("profile.saved"), "")
}
