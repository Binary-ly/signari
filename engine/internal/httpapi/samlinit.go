package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// pathSAMLInit starts a sign-in to a service provider from here (8.02): the tile on the
// portal, or a link an operator hands out, for an application with no sign-in page of
// its own to send anybody from.
const pathSAMLInit = "/saml/init/"

// handleSAMLInit answers a request nobody made.
//
// Everything a request would have decided comes from what the provider is registered
// with, and nothing comes from the URL but which provider: the assertion goes to its
// default URL, and the RelayState is the operator's. So a link can start a sign-in and
// cannot steer it. The person is signed in first, because whether an application exists
// is not something to tell somebody who is not, and the access policy is held by
// issueSAMLAssertion as for any other assertion.
func (s *Server) handleSAMLInit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
		s.samlRefuse(w, r, "no such application")
		return
	}
	session, ok := s.browserSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin(pathSAMLInit+id), http.StatusSeeOther)
		return
	}
	provider, err := s.loadSAMLProviderByID(ctx, id)
	if errors.Is(err, store.ErrSAMLProviderUnknown) {
		s.samlRefuse(w, r, "no such application")
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "loading a SAML provider", "provider", id, "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// The same words for another organisation's and for one that has not opted in,
	// so this does not list another tenant's applications by id.
	if provider.OrgID != session.OrgID {
		s.samlRefuse(w, r, "no such application")
		return
	}
	validated, err := saml.Unsolicited(provider, time.Now())
	if err != nil {
		s.samlRefuse(w, r, "no such application")
		return
	}
	doc, acs, err := s.issueSAMLAssertion(ctx, r, validated, provider, session)
	var denied *policyDenied
	if errors.As(err, &denied) {
		// Told here. There is no request to answer, and a refusal posted to a
		// provider that was not expecting anything has nowhere to show it.
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: session.OrgID, SubjectID: session.UserID,
			CorrelationID: correlationID(ctx),
			Detail: map[string]any{"reason": "access_policy", "rule": denied.d.Rule,
				"entity_id": provider.EntityID},
		})
		s.samlRefuse(w, r, denied.d.Message)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "issuing an unsolicited SAML assertion", "entity_id", provider.EntityID, "err", err,
			"correlation_id", correlationID(ctx))
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.postSAMLResponse(w, r, acs, doc, provider.DefaultRelayState)
}
