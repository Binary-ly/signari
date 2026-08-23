package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

	// Which binding this arrived on decides how it is decoded AND how its
	// signature is checked. The two are not interchangeable: HTTP-Redirect signs
	// the raw query octets, HTTP-POST signs the document itself, and checking the
	// wrong one proves nothing about what was actually sent.
	post := r.Method == http.MethodPost
	params := r.URL.Query()
	if post {
		if err := r.ParseForm(); err != nil {
			s.samlRefuse(w, r, "the request could not be parsed")
			return
		}
		params = r.PostForm
	}

	// The same 80-byte bound the SSO endpoint applies, which this path had been
	// missing. It matters more here now: a LogoutResponse on the redirect binding
	// carries RelayState in the URL rather than a form field, and an oversized one
	// produces a redirect that browsers and proxies silently truncate -- so the
	// provider receives a RelayState it never sent and fails in a way nothing here
	// would explain. Our own chain token is 32 characters, well inside this.
	if rs := params.Get("RelayState"); len(rs) > maxRelayState {
		s.samlRefuse(w, r, fmt.Sprintf("RelayState is %d bytes, over the %d the "+
			"specification allows", len(rs), maxRelayState))
		return
	}

	encoded := params.Get("SAMLRequest")
	if encoded == "" {
		if resp := params.Get("SAMLResponse"); resp != "" {
			// A provider answering a logout WE initiated. Move the chain along.
			//
			// The response signature is NOT required here, and that is deliberate:
			// this ends nothing. Our session was terminated before the chain
			// started, and the only thing a forged response could achieve is
			// advancing our own bookkeeping one step -- which costs an attacker a
			// valid chain token they do not have, to make us skip notifying a
			// provider we were about to notify anyway.
			//
			// Requiring a signature here would instead mean every provider that
			// answers unsigned strands the chain, and most answer unsigned.
			failed := logoutResponseFailed(resp)
			if s.continueSAMLLogoutChain(w, r, params.Get("RelayState"), failed) {
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.samlRefuse(w, r, "no SAMLRequest")
		return
	}

	var raw []byte
	var err error
	if post {
		raw, err = saml.DecodePOST(encoded)
	} else {
		raw, err = saml.DecodeRedirect(encoded)
	}
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
	// On the redirect binding that means the raw query octets, NOT any
	// <ds:Signature> the document might also carry -- an embedded element there
	// proves nothing about what was actually sent. On the POST binding it is the
	// enveloped signature, checked with the wrapping defences in
	// saml.VerifyEmbeddedSignature.
	//
	// Unlike AuthnRequests, this is never optional. A LogoutRequest acted on
	// unsigned lets anybody sign anybody out, needing no credential at all
	// (gosaml2 GHSA-pcgw-qcv5-h8ch).
	if post {
		err = saml.VerifyEmbeddedSignature(raw, provider.SPSigningCert, "LogoutRequest", req.ID)
	} else {
		err = saml.VerifyRedirectSignature(r.URL.RawQuery, provider.SPSigningCert, "SAMLRequest")
	}
	if err != nil {
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

	requestBinding := bindingRedirect
	if post {
		requestBinding = bindingPOST
	}
	sloURL, respBinding := sloEndpoint(ctx, s, provider.ID, requestBinding)
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

	relayState := params.Get("RelayState")

	// # Answer on the binding the endpoint was registered with
	//
	// Previously every LogoutResponse went out as an auto-submitting POST form,
	// including to endpoints registered as HTTP-Redirect -- which was every one of
	// them, since that was the only binding `saml add-sp` could store. A service
	// provider expecting `SAMLResponse`/`SigAlg`/`Signature` as query parameters
	// receives a form POST instead and has nothing to parse. Verified on the wire
	// before it was changed, because reading the code had not made it obvious.
	if respBinding == bindingPOST {
		s.postSAMLResponse(w, r, sloURL, doc, relayState)
		return
	}

	respEncoded, err := saml.EncodeRedirect(doc)
	if err != nil {
		s.log.Error("encoding a LogoutResponse for the redirect binding", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	query, err := saml.SignRedirectQuery("SAMLResponse", respEncoded, relayState, key.Signer())
	if err != nil {
		s.log.Error("signing a LogoutResponse query", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	sep := "?"
	if strings.ContainsRune(sloURL, '?') {
		sep = "&"
	}
	http.Redirect(w, r, sloURL+sep+query, http.StatusSeeOther)
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
	//
	// (userID is not discarded here: it names the subject of the audit event
	// below. A `_ = userID` sat at this line and did nothing, while telling a
	// reader the value was deliberately unused.)
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

// logoutResponseFailed reports whether a provider's LogoutResponse said it did
// not succeed.
//
// Best-effort by design: this only decides which bucket the provider lands in
// for the record. A response we cannot read counts as failed, because "we could
// not tell" and "it worked" must not be the same answer -- the whole purpose of
// this chain is being able to say what was actually reached.
func logoutResponseFailed(encoded string) bool {
	raw, err := saml.DecodeRedirect(encoded)
	if err != nil {
		return true
	}
	var lr struct {
		Status struct {
			StatusCode struct {
				Value string `xml:"Value,attr"`
			} `xml:"StatusCode"`
		} `xml:"Status"`
	}
	if err := saml.Unmarshal(raw, &lr); err != nil {
		return true
	}
	return lr.Status.StatusCode.Value != saml.StatusSuccess
}

// The two bindings, spelled once. They are stored in the database as these
// strings, and a typo in one comparison would silently select the wrong
// response format for every provider.
const (
	bindingRedirect = "HTTP-Redirect"
	bindingPOST     = "HTTP-POST"
)

// sloEndpoint picks where a LogoutResponse goes and on which binding.
//
// `prefer` is the binding the request arrived on. A provider that registered
// both is answered the way it asked, which is the least surprising thing to do
// and the only one that keeps a POST conversation on POST. Otherwise whatever is
// registered is used, because a response on the wrong binding is still better
// than no response at all -- and the alternative, refusing, would leave the
// provider believing the logout failed when the session is already gone.
func sloEndpoint(ctx context.Context, s *Server, providerID, prefer string) (string, string) {
	var u, binding string
	_ = s.db.QueryRow(ctx, `
		SELECT url, binding FROM core.saml_slo_urls
		WHERE provider_id = $1::uuid
		ORDER BY (binding = $2) DESC, url
		LIMIT 1`, providerID, prefer).Scan(&u, &binding)
	return u, binding
}
