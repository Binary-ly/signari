package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// Single logout with a SAML upstream (8.04), in both directions, on the redirect
// binding and in the browser.
//
// A LogoutRequest has to carry exactly the NameID and SessionIndex the assertion did,
// or the upstream takes it and ends nothing. Like the slug beside it they are kept in
// this browser, which has them through every stage between the assertion and a
// session here, and need nothing kept against the session; sealed, since a NameID may
// be somebody's address. It follows that a request from the upstream cannot be matched
// to a session by its SessionIndex, and it ends every session that person has here
// through a provider: the upstream signed them all in, and has said they are signed out.

// samlSubjectCookieName holds who a browser is at the upstream it came through.
const samlSubjectCookieName = "signari_upstream_subject"

const sealContextSAMLSubject = "saml_upstream_subject"

// samlLogoutTTL bounds how long an upstream has to answer a sign-out.
const samlLogoutTTL = 10 * time.Minute

type samlSubject struct {
	NameID       string `json:"n"`
	Format       string `json:"f"`
	SessionIndex string `json:"s"`
}

func (s *Server) rememberSAMLSubject(ctx context.Context, w http.ResponseWriter, a *saml.InboundAssertion) {
	if s.root == nil {
		return
	}
	raw, err := json.Marshal(samlSubject{NameID: a.Subject, Format: a.SubjectFormat, SessionIndex: a.SessionIndex})
	if err != nil {
		return
	}
	sealed, err := s.root.Seal(raw, sealContextSAMLSubject)
	if err != nil {
		s.log.ErrorContext(ctx, "sealing who a person is upstream", "err", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: samlSubjectCookieName, Value: base64.RawURLEncoding.EncodeToString(sealed),
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) samlSubjectOf(r *http.Request) (samlSubject, bool) {
	var out samlSubject
	cookie, err := r.Cookie(samlSubjectCookieName)
	if err != nil || s.root == nil {
		return out, false
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return out, false
	}
	raw, err := s.root.Open(sealed, sealContextSAMLSubject)
	if err != nil || json.Unmarshal(raw, &out) != nil || out.NameID == "" {
		return samlSubject{}, false
	}
	return out, true
}

// samlUpstreamLogout is the address that ends a browser's session at a SAML upstream
// and comes back to target; empty when this sign-out has to stop here, which is the
// sign-out having happened all the same.
func (s *Server) samlUpstreamLogout(ctx context.Context, r *http.Request, slug, target string) string {
	subject, ok := s.samlSubjectOf(r)
	if !ok {
		return ""
	}
	src, err := s.loadSAMLSource(ctx, slug)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the upstream to sign out at", "slug", slug, "err", err)
		return ""
	}
	signer, cert, err := store.SAMLSourceSigner(ctx, s.db, s.root, src.ProviderID)
	if err != nil {
		// Unsigned, it would be nothing any upstream should act on.
		s.log.WarnContext(ctx, "no signing key to sign out at a SAML upstream with", "slug", slug, "err", err)
		return ""
	}
	doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: src.Provider.SPEntityID, Destination: src.SLOURL,
		NameID: subject.NameID, NameIDFormat: subject.Format, SessionIndex: subject.SessionIndex, Now: time.Now()}, signer, cert)
	if err != nil {
		s.log.ErrorContext(ctx, "building a LogoutRequest for an upstream", "slug", slug, "err", err)
		return ""
	}
	var sent saml.LogoutRequest
	if err := saml.Unmarshal([]byte(doc), &sent); err != nil {
		s.log.ErrorContext(ctx, "reading back a LogoutRequest", "err", err)
		return ""
	}
	relay, err := saml.RelayStateToken()
	if err != nil {
		return ""
	}
	if err := store.RecordSAMLRequest(ctx, s.db, src.ProviderID, sent.ID, relay, target, samlLogoutTTL); err != nil {
		s.log.ErrorContext(ctx, "recording a LogoutRequest", "err", err)
		return ""
	}
	encoded, err := saml.EncodeRedirect(doc)
	if err != nil {
		return ""
	}
	query, err := saml.SignRedirectQuery("SAMLRequest", encoded, relay, signer)
	if err != nil {
		s.log.ErrorContext(ctx, "signing a LogoutRequest for an upstream", "err", err)
		return ""
	}
	if strings.ContainsRune(src.SLOURL, '?') {
		return src.SLOURL + "&" + query
	}
	return src.SLOURL + "?" + query
}

// handleSAMLSourceSLO is an upstream's half of logout: its answer to a sign-out from
// here, or its own request to end a session.
func (s *Server) handleSAMLSourceSLO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := samlSourceSlug(r.URL.Path, "/slo")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	src, err := s.loadSAMLSource(ctx, slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	post := r.Method == http.MethodPost
	params := r.URL.Query()
	if post {
		if err := r.ParseForm(); err != nil {
			s.samlRefuse(w, r, "the request could not be parsed")
			return
		}
		params = r.PostForm
	}
	decode := saml.DecodeRedirect
	if post {
		decode = saml.DecodePOST
	}

	if encoded := params.Get("SAMLResponse"); encoded != "" {
		s.upstreamAnsweredLogout(w, r, src, decode, encoded, params.Get("RelayState"))
		return
	}
	encoded := params.Get("SAMLRequest")
	if encoded == "" {
		s.samlRefuse(w, r, "no SAMLRequest")
		return
	}
	raw, err := decode(encoded)
	if err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}
	var req saml.LogoutRequest
	if err := saml.Unmarshal(raw, &req); err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}

	// Signature first, and never optional: a LogoutRequest acted on unsigned lets
	// anybody sign anybody out. See handleSAMLSLO.
	if post {
		err = saml.VerifyEmbeddedSignature(raw, src.Provider.CertPEM, "LogoutRequest", req.ID)
	} else {
		err = saml.VerifyRedirectSignature(r.URL.RawQuery, src.Provider.CertPEM, "SAMLRequest")
	}
	if err != nil {
		s.log.InfoContext(ctx, "a logout from a SAML upstream was refused", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.samlRefuse(w, r, err.Error())
		return
	}
	validated, err := saml.ValidateLogoutRequest(&req, &saml.Provider{EntityID: src.Provider.EntityID, Enabled: true},
		s.cfg.Issuer+"/saml/source/"+slug+"/slo", time.Now())
	if err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}

	status := saml.StatusSuccess
	// A captured request would otherwise go on signing somebody out for as long as
	// its signature verifies. Claimed by the same table that spends an assertion.
	if store.RecordSAMLAssertion(ctx, s.db, src.ProviderID, "logout:"+validated.RequestID, time.Now().Add(samlRequestTTL)) != nil {
		status = saml.StatusRequester
	} else if err := s.endUpstreamSessions(ctx, src, validated); err != nil {
		s.log.ErrorContext(ctx, "ending sessions for an upstream's logout", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.clearSessionCookie(w)
	s.forgetUpstream(w)

	// With no key to sign an answer or nowhere to send it, the logout has happened
	// and cannot be said to have.
	signer, cert, err := store.SAMLSourceSigner(ctx, s.db, s.root, src.ProviderID)
	if err != nil || src.SLOURL == "" {
		s.log.InfoContext(ctx, "a logout from a SAML upstream had no answer to give", "slug", slug, "err", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doc, err := saml.BuildLogoutResponse(saml.LogoutResponseInput{Issuer: src.Provider.SPEntityID, Destination: src.SLOURL,
		InResponse: validated.RequestID, Status: status, Now: time.Now()}, signer, cert)
	if err != nil {
		s.log.ErrorContext(ctx, "building a LogoutResponse for an upstream", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	answer, err := saml.EncodeRedirect(doc)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	query, err := saml.SignRedirectQuery("SAMLResponse", answer, params.Get("RelayState"), signer)
	if err != nil {
		s.log.ErrorContext(ctx, "signing a LogoutResponse for an upstream", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	sep := "?"
	if strings.ContainsRune(src.SLOURL, '?') {
		sep = "&"
	}
	http.Redirect(w, r, src.SLOURL+sep+query, http.StatusSeeOther)
}

// endUpstreamSessions ends the sessions an upstream's request names, through the one
// path a session ends by, so applications are told as they are of any other logout.
// Somebody it knows and nobody here knows is the state it asked for already.
func (s *Server) endUpstreamSessions(ctx context.Context, src *store.SAMLSource, v *saml.ValidatedLogout) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sids, userID, err := store.FederatedSessions(ctx, tx, src.ProviderID, v.NameID)
	if err != nil {
		return err
	}
	if len(sids) == 0 {
		return nil
	}
	if _, err := store.TerminateEachSession(ctx, tx, sids, store.ReasonLogout); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "saml.logout_completed", OrgID: src.OrgID, SubjectID: userID,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"provider": src.Slug, "request_id": v.RequestID,
			"sessions": len(sids)}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// upstreamAnsweredLogout takes an upstream's answer to a sign-out from here. Its
// signature is not asked for, as at handleSAMLSLO: the session here ended before the
// browser left, so this ends nothing, and all it can do is send the browser on to the
// address recorded for a request only this deployment's token names. It has to be
// the answer to that request all the same, so that a request cannot be spent by
// anything else.
func (s *Server) upstreamAnsweredLogout(w http.ResponseWriter, r *http.Request, src *store.SAMLSource,
	decode func(string) ([]byte, error), encoded, relay string) {
	ctx := r.Context()
	var answer struct {
		InResponseTo string `xml:"InResponseTo,attr"`
		Issuer       string `xml:"Issuer"`
		Status       struct {
			StatusCode struct {
				Value string `xml:"Value,attr"`
			} `xml:"StatusCode"`
		} `xml:"Status"`
	}
	raw, err := decode(encoded)
	if err == nil {
		err = saml.Unmarshal(raw, &answer)
	}
	if err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}
	pending, err := store.ConsumeSAMLRequest(ctx, s.db, relay)
	if err != nil || pending.ProviderID != src.ProviderID || pending.ID != answer.InResponseTo ||
		answer.Issuer != src.Provider.EntityID {
		s.log.InfoContext(ctx, "an answer to a logout nobody asked for", "slug", src.Slug, "correlation_id", correlationID(ctx))
		s.samlRefuse(w, r, "this is not the answer to a sign-out in progress")
		return
	}
	if answer.Status.StatusCode.Value != saml.StatusSuccess {
		// Worth an operator's knowing and no reason to stop: the session here is over.
		s.log.WarnContext(ctx, "an upstream did not end its session", "slug", src.Slug, "status", answer.Status.StatusCode.Value)
	}
	if pending.ReturnPath != "" {
		http.Redirect(w, r, pending.ReturnPath, http.StatusSeeOther)
		return
	}
	s.signedOut(w, r, nil, nil)
}
