package httpapi

import (
	"context"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// Front-channel single logout, identity-provider initiated.
//
// # Why a redirect chain
//
// SAML has no usable back-channel. The SOAP binding exists and almost nothing
// implements it, so propagating a logout means walking the BROWSER through each
// service provider's logout endpoint in turn: we redirect to provider one, it
// ends its session and redirects back to us, we redirect to provider two, and
// so on until the list is empty.
//
// It is ugly, it is what every SAML deployment does, and it is the difference
// between signing out and appearing to sign out.
//
// # The ordering that matters
//
// OUR session is terminated BEFORE the chain starts, never at the end. A chain
// that ends the local session last would leave the user signed in here whenever
// a provider fails to redirect back -- and providers fail to redirect back all
// the time. The user closed the tab, the endpoint 500s, the network dropped.
//
// So by the time the first redirect is issued, signing out of Signari has
// already happened. Everything after that is best-effort notification, and what
// it could not reach is recorded rather than assumed.

// maxLogoutChain bounds how many providers a single logout walks through.
//
// A browser redirect chain is a bounded resource: each hop is a real page load,
// and a user signed in to thirty applications would sit through thirty
// redirects. Past this we notify what we can and record the rest, because a
// logout the user abandons halfway is worse than one that finishes and tells
// the truth about its coverage.
const maxLogoutChain = 10

// beginSAMLLogoutChain starts front-channel propagation.
//
// Returns the URL to redirect the browser to, or "" when there is nothing to
// propagate -- in which case the caller completes the logout normally.
func (s *Server) beginSAMLLogoutChain(ctx context.Context, sid, userID, orgID, finalRedirect string) string {
	if sid == "" {
		return ""
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return ""
	}
	defer func() { _ = tx.Rollback(ctx) }()

	parts, err := store.SAMLParticipantsForSession(ctx, tx, sid, "")
	if err != nil || len(parts) == 0 {
		return ""
	}

	var steps []store.LogoutStep
	var unreachable []string
	for _, p := range parts {
		if len(p.SLOURLs) == 0 {
			// No logout endpoint registered. Nothing to send to, and that is a
			// fact about the deployment the operator should hear about rather
			// than a silent omission.
			unreachable = append(unreachable, p.EntityID)
			continue
		}
		if len(steps) >= maxLogoutChain {
			unreachable = append(unreachable, p.EntityID)
			continue
		}
		steps = append(steps, store.LogoutStep{
			ProviderID: p.ProviderID, EntityID: p.EntityID, SLOURL: p.SLOURLs[0],
			NameID: p.NameID, SessionIndex: p.SessionIndex,
		})
	}
	if len(unreachable) > 0 {
		s.log.Warn("SAML providers that cannot be sent a logout",
			"providers", unreachable,
			"reason", "no SingleLogoutService URL registered, or the chain limit was reached")
	}
	if len(steps) == 0 {
		return ""
	}

	token, err := store.BeginLogoutChain(ctx, tx, store.LogoutChain{
		OrgID: orgID, SID: sid, UserID: userID,
		Remaining: steps, FinalRedirect: finalRedirect,
	})
	if err != nil {
		s.log.Error("starting a SAML logout chain", "err", err)
		return ""
	}
	if err := tx.Commit(ctx); err != nil {
		return ""
	}

	url, err := s.logoutRedirectFor(ctx, steps[0], token)
	if err != nil {
		s.log.Error("building the first logout request", "err", err)
		return ""
	}
	return url
}

// logoutRedirectFor builds a signed LogoutRequest for one provider.
func (s *Server) logoutRedirectFor(ctx context.Context, step store.LogoutStep, token string) (string, error) {
	key, err := s.samlSigningKey()
	if err != nil {
		return "", err
	}
	certDER, err := s.samlCertificateFor(ctx, key)
	if err != nil {
		return "", err
	}

	doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{
		Issuer:      s.samlEntityID(),
		Destination: step.SLOURL,
		// EXACTLY what the assertion carried. A service provider matches on these;
		// anything else is accepted and ends nothing, which reports success and
		// leaves the session live.
		NameID:       step.NameID,
		NameIDFormat: saml.NameIDFormatPersistent,
		SessionIndex: step.SessionIndex,
		Now:          time.Now(),
	}, key.Signer(), certDER)
	if err != nil {
		return "", err
	}

	encoded, err := saml.EncodeRedirect(doc)
	if err != nil {
		return "", err
	}
	// The chain token travels as RelayState, which the provider is required to
	// return unmodified. It is the only state carried across the hop, and it is
	// opaque -- the provider learns nothing from it and cannot forge another.
	query, err := saml.SignRedirectQuery("SAMLRequest", encoded, token, key.Signer())
	if err != nil {
		return "", err
	}

	sep := "?"
	if containsRune(step.SLOURL, '?') {
		sep = "&"
	}
	return step.SLOURL + sep + query, nil
}

// continueSAMLLogoutChain handles a provider redirecting back to us.
//
// Called from the SLO endpoint when a SAMLResponse arrives carrying a RelayState
// we recognise. Returns true when it handled the response.
func (s *Server) continueSAMLLogoutChain(w http.ResponseWriter, r *http.Request, token string, failed bool) bool {
	ctx := r.Context()
	if token == "" {
		return false
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback(ctx) }()

	chain, next, ok, err := store.AdvanceLogoutChain(ctx, tx, token, failed)
	if err != nil {
		s.log.Error("advancing the SAML logout chain", "err", err)
		return false
	}
	if !ok {
		// Unknown or expired token. NOT an error to the user: their session ended
		// before the chain started, so they are signed out either way. Answering
		// with a failure page would be alarming and wrong.
		return false
	}

	if next != nil {
		url, err := s.logoutRedirectFor(ctx, *next, token)
		if err != nil {
			s.log.Error("building the next logout request", "entity_id", next.EntityID, "err", err)
			// Skip the provider we cannot build for rather than stranding the
			// user mid-chain.
			if err := tx.Commit(ctx); err == nil {
				return s.continueSAMLLogoutChain(w, r, token, true)
			}
			return false
		}
		if err := tx.Commit(ctx); err != nil {
			return false
		}
		http.Redirect(w, r, url, http.StatusFound)
		return true
	}

	// Finished. Record what was actually reached -- the point of the whole
	// exercise is being able to say so.
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "saml.logout_propagated", OrgID: chain.OrgID, SubjectID: chain.UserID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"notified": entityIDs(chain.Notified),
			"failed":   entityIDs(chain.Failed),
		},
	}); err != nil {
		s.log.Error("recording logout propagation", "err", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false
	}
	if len(chain.Failed) > 0 {
		s.log.Warn("SAML logout could not be delivered to every provider",
			"failed", entityIDs(chain.Failed), "notified", entityIDs(chain.Notified))
	} else {
		s.log.Info("SAML logout propagated to every participating provider",
			"providers", entityIDs(chain.Notified))
	}

	if chain.FinalRedirect != "" {
		http.Redirect(w, r, chain.FinalRedirect, http.StatusFound)
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "signed out",
		"notified": entityIDs(chain.Notified),
		"failed":   entityIDs(chain.Failed),
	})
	return true
}

func entityIDs(steps []store.LogoutStep) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.EntityID)
	}
	return out
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
