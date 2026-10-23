package adminapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// A person's links to upstream providers (6.07), as `signari idp link`,
// `unlink` and `links` make and show them. A link is what the jwt-bearer grant
// resolves an assertion's sub against, so making one lets whoever controls that
// subject at the issuer mint tokens for the person: the write routes are
// privileged when the person is.

type identityLinkView struct {
	Provider     string     `json:"provider"`
	Kind         string     `json:"kind"`
	Subject      string     `json:"subject"`
	LinkedAt     time.Time  `json:"linked_at"`
	LastSignInAt *time.Time `json:"last_sign_in_at"`
}

type identityLinkRequest struct {
	Subject string `json:"subject"`
}

// errLinkUnchanged is a link that was already made.
var errLinkUnchanged = errors.New("the subject already acts as that person")

func (s *Server) listIdentityLinks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.consentUser(w, r); !ok {
		return
	}
	userID := r.PathValue("userID")
	got, err := store.IdentityLinks(r.Context(), s.db, userID)
	if err != nil {
		s.log.Error("listing a person's identity links", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]identityLinkView, 0, len(got))
	for _, l := range got {
		out = append(out, identityLinkView{Provider: l.Slug, Kind: l.Kind, Subject: l.Subject,
			LinkedAt: l.LinkedAt.UTC(), LastSignInAt: utcOrNil(l.LastSignInAt)})
	}
	s.writeList(w, r, map[string]any{"user_id": userID, "links": out})
}

// putIdentityLink makes the subject at the provider act as the person, as
// `signari idp link` does. A subject acting as somebody else, or a person
// known to the provider as another subject, is refused rather than moved.
func (s *Server) putIdentityLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, slug := r.PathValue("userID"), r.PathValue("slug")
	var req identityLinkRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_required",
			"detail": "give the subject, the exact sub the provider's assertions carry"})
		return
	}
	orgID, ok := s.consentUser(w, r)
	if !ok {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	// The same link made again changes nothing, so it is rolled back rather
	// than recorded and versioned.
	var already bool
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		if already, err = store.LinkSubject(ctx, tx, orgID, slug, userID, subject); err != nil {
			return err
		}
		if already {
			return errLinkUnchanged
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.identity_linked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID, Detail: map[string]any{"provider": slug, "subject": subject}})
	})
	if errors.Is(err, errLinkUnchanged) {
		version, err = store.CurrentConfigVersion(ctx, s.db)
	}
	if s.writeIdentityLinkFailure(w, err, userID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "provider": slug, "subject": subject,
		"linked": true, "changed": !already, "config_version": version})
}

// deleteIdentityLink detaches the person from the provider, as `signari idp
// unlink` does; the next assertion naming the subject is refused.
func (s *Server) deleteIdentityLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, slug := r.PathValue("userID"), r.PathValue("slug")
	orgID, ok := s.consentUser(w, r)
	if !ok {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var subject string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		if subject, err = store.UnlinkSubject(ctx, tx, orgID, slug, userID, ""); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.identity_unlinked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID, Detail: map[string]any{"provider": slug, "subject": subject}})
	})
	if s.writeIdentityLinkFailure(w, err, userID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "provider": slug, "subject": subject,
		"linked": false, "config_version": version})
}

// writeIdentityLinkFailure answers a refused or failed link write, and
// reports whether it wrote anything.
func (s *Server) writeIdentityLinkFailure(w http.ResponseWriter, err error, userID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case errors.Is(err, store.ErrProviderUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider_not_found"})
	case errors.Is(err, store.ErrIdPLinkUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "link_not_found"})
	case errors.Is(err, store.ErrIdPLinkTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "link_taken", "detail": err.Error()})
	default:
		s.log.Error("writing an identity link", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
