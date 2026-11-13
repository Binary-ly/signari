package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
)

// Required attributes a person has no value for, asked at sign-in (5.05).
//
// Sign-up refuses an account without them, but an account made before an attribute
// was required, by an administrator, by an import or by a directory never met that
// check, and would carry the gap into every token. So the prompt stage asks for the
// ones the person may write, before any session, as it asks an operator's prompts.
// The answer is written as the person's own profile writes it (store.SetOwnAttributes:
// only what they may write, typed and sealed as declared), so this page cannot set
// anything the profile page could not. One the person may not write is an
// administrator's to fill, and is not asked.

// requiredAttributesPrompt is the prompt for the attributes missing. Its title and
// body are the reader's language's, filled in when it is shown (promptForPage).
func requiredAttributesPrompt(missing []store.Attribute) prompts.Prompt {
	p := prompts.Prompt{Slug: prompts.RequiredAttributesSlug}
	for _, a := range missing {
		f := prompts.Field{Name: a.Name, Label: store.AttributeLabel(a), Type: prompts.Text, Required: true}
		if a.ValueType == "boolean" {
			// Unticked is an answer too, false, so the box itself is not required.
			f.Type, f.Required = prompts.Checkbox, false
		}
		p.Fields = append(p.Fields, f)
	}
	return p
}

// promptForPage is p as the page shows it: an operator's prompt in the operator's
// words, and sign-in's own in the reader's language.
func (s *Server) promptForPage(r *http.Request, p prompts.Prompt) prompts.Prompt {
	if p.Slug == prompts.RequiredAttributesSlug {
		tr := s.tr(r)
		p.Title, p.Body = tr.Text("prompt.attributes.title"), tr.Text("prompt.attributes.body")
	}
	return p
}

// answerRequiredAttributes saves what the person gave for their missing required
// attributes and carries on with the sign-in, or shows the page again with why not.
func (s *Server) answerRequiredAttributes(w http.ResponseWriter, r *http.Request, pending *pendingClaims) {
	ctx := r.Context()
	// Read again rather than trusted from the form: what is missing now is what is
	// asked, and a field the form adds is not.
	missing, err := store.MissingRequiredAttributes(ctx, s.db, pending.OrgID, pending.Subject)
	if err != nil {
		s.log.ErrorContext(ctx, "reading missing attributes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p := s.promptForPage(r, requiredAttributesPrompt(missing))
	rerender := func(msg string) {
		csrf, _ := s.csrfToken(w, r)
		s.renderPage(w, r, "prompt", map[string]any{
			"Slug": p.Slug, "Title": p.Title, "Body": p.Body, "Fields": p.Fields, "Version": p.Version,
			"Error": msg, "CSRF": csrf, "CSRFField": csrfFormField,
		})
	}
	values := map[string]string{}
	for _, f := range p.Fields {
		v := strings.TrimSpace(r.PostFormValue(f.Name))
		if f.Type == prompts.Checkbox {
			v = strconv.FormatBool(v == "on")
		}
		values[f.Name] = v
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	written, err := store.SetOwnAttributes(ctx, tx, pending.Subject, pending.OrgID, values, s.root)
	switch {
	case errors.Is(err, store.ErrAttributeRequired), errors.Is(err, store.ErrInvalidAttributeValue),
		errors.Is(err, store.ErrNoSuchAttribute):
		_ = tx.Rollback(ctx)
		rerender(s.attributeRefusalText(r, err, ""))
		return
	case err != nil:
		s.log.ErrorContext(ctx, "saving required attributes at sign-in", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Which attributes, never their values, as the profile page records it.
	if len(written) > 0 {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "user.attributes_updated", OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"by": "sign-in", "attributes": written},
		}); err != nil {
			s.log.ErrorContext(ctx, "auditing attributes given at sign-in", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID,
		flow.Mark(pending.AMR, flow.StagePrompt, prompts.RequiredAttributesSlug), pending.Authz)
}
