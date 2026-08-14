package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// SAML single logout, service-provider initiated.
//
//	GET  /saml/slo   HTTP-Redirect binding
//	POST /saml/slo   HTTP-POST binding
//
// # The rule this endpoint exists to enforce
//
// A LogoutRequest is acted on ONLY when it carries a signature that verifies
// against a certificate registered for that service provider in advance.
// gosaml2 GHSA-pcgw-qcv5-h8ch accepted unsigned ones: anybody who could reach
// the endpoint could sign any user out of everything, needing no credential at
// all. It is the cheapest denial of service there is against an identity
// provider.
//
// A provider with no certificate on file therefore cannot use single logout.
// That is an inconvenience, chosen over the alternative.
func (s *Server) handleSAMLSLO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		// The POST binding carries an enveloped XML signature rather than signed
		// query octets, and verifying that is a different job with a different set
		// of failure modes -- the wrapping attacks live there. Refusing plainly
		// beats a half-implementation that accepts something it should not.
		s.samlRefuse(w, r, "single logout on the HTTP-POST binding is not implemented; "+
			"configure the service provider to use HTTP-Redirect")
		return
	}

	encoded := r.URL.Query().Get("SAMLRequest")
	if encoded == "" {
		if r.URL.Query().Get("SAMLResponse") != "" {
			// A response to a logout WE initiated. Nothing to do: the session is
			// already gone, and this only confirms delivery.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.samlRefuse(w, r, "no SAMLRequest")
		return
	}

	raw, err := saml.DecodeRedirect(encoded)
	if err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}
	var req saml.LogoutRequest
	if err := saml.Unmarshal(raw, &req); err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}

	provider, err := store.LoadSAMLProvider(ctx, s.db, req.Issuer)
	if err != nil {
		if errors.Is(err, store.ErrSAMLProviderUnknown) {
			s.samlRefuse(w, r, "no service provider is registered with that entity id")
			return
		}
		s.log.Error("loading SAML provider for logout", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// SIGNATURE FIRST, before anything else is believed about the request.
	//
	// Over the raw query octets, not any <ds:Signature> the document might
	// carry: on the redirect binding the signature is the query parameters, and
	// an embedded element proves nothing about what was actually sent.
	if err := saml.VerifyRedirectSignature(r.URL.RawQuery, provider.SPSigningCert, "SAMLRequest"); err != nil {
		s.log.Info("SAML logout refused", "entity_id", req.Issuer, "err", err,
			"correlation_id", correlationID(ctx))
		s.samlRefuse(w, r, err.Error())
		return
	}

	validated, err := saml.ValidateLogoutRequest(&req, provider, s.cfg.Issuer+"/saml/slo", time.Now())
	if err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}

	status, err := s.endSAMLSession(ctx, validated, provider)
	if err != nil {
		s.log.Error("ending a session for SAML logout", "err", err,
			"correlation_id", correlationID(ctx))
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	key, err := s.samlSigningKey()
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	certDER, err := s.samlCertificateFor(ctx, key)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	sloURL := firstSLOURL(ctx, s, provider.ID)
	if sloURL == "" {
		// Nowhere to answer. The session is still ended -- the logout succeeded,
		// we simply cannot say so.
		s.log.Info("SAML logout completed with no response endpoint registered",
			"entity_id", provider.EntityID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	doc, err := saml.BuildLogoutResponse(saml.LogoutResponseInput{
		Issuer:      s.samlEntityID(),
		Destination: sloURL,
		InResponse:  validated.RequestID,
		Status:      status,
		Now:         time.Now(),
	}, key.Signer(), certDER)
	if err != nil {
		s.log.Error("building a LogoutResponse", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	// The session cookie goes too. Ending the session in the database and
	// leaving the cookie in the browser means the next request presents a
	// credential for a session that no longer exists -- harmless, but it makes
	// every subsequent log line look like an attack.
	s.clearSessionCookie(w)
	s.postSAMLResponse(w, sloURL, doc, r.URL.Query().Get("RelayState"))
}

// endSAMLSession terminates the session a LogoutRequest names.
//
// Returns the SAML status to report. A request naming a session we do not have
// is answered with Success, not an error: the desired state -- that session not
// existing here -- already holds, and reporting failure would have service
// providers retrying something that is already done.
func (s *Server) endSAMLSession(ctx context.Context, v *saml.ValidatedLogout, p *saml.Provider) (string, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Replay protection. Without it a captured LogoutRequest stays valid
	// forever, and whoever saw it once can end that user's session whenever
	// they like -- the signature keeps verifying.
	fresh, err := store.MarkSAMLRequestSeen(ctx, tx, v.RequestID, p.OrgID, p.ID, samlRequestTTL)
	if err != nil {
		return "", err
	}
	if !fresh {
		return saml.StatusRequester, tx.Commit(ctx)
	}

	sid, userID, orgID, err := store.FindSAMLSession(ctx, tx, p.ID, v.NameID, v.SessionIndex)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return saml.StatusSuccess, tx.Commit(ctx)
		}
		return "", err
	}

	// Through the same termination path as every other logout, so relying
	// parties are notified by back-channel logout as well. A SAML logout that
	// ended only the SAML sessions would leave every OIDC application signed in.
	// By sid, not by user. A LogoutRequest ends the session it names, not every
	// session that person has -- they may be signed in on another device, and
	// one service provider's logout is not authority over all of them.
	_ = userID
	if _, err := store.TerminateSessions(ctx, tx, sid, "", store.ReasonLogout); err != nil {
		return "", err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "saml.logout_completed", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"entity_id": p.EntityID, "request_id": v.RequestID},
	}); err != nil {
		return "", err
	}
	return saml.StatusSuccess, tx.Commit(ctx)
}

func firstSLOURL(ctx context.Context, s *Server, providerID string) string {
	var u string
	_ = s.db.QueryRow(ctx, `
		SELECT url FROM core.saml_slo_urls
		WHERE provider_id = $1::uuid AND binding = 'HTTP-Redirect'
		ORDER BY url LIMIT 1`, providerID).Scan(&u)
	return u
}
