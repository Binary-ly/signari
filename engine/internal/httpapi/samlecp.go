package httpapi

import (
	"errors"
	"io"
	"net/http"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// The Enhanced Client or Proxy profile, this side of it (8.08,
// saml-profiles-2.0-os §4.2):
//
//	POST /saml/ecp               an AuthnRequest in a SOAP body, the person by HTTP Basic
//	POST /saml/org/{org}/ecp     the same, at an organisation's entity
//
// The client is not a browser, so no page here can ask the person anything: the
// password comes in the Authorization header, and a second factor, when one is
// needed, after it as `password;123456`, as LDAP and RADIUS take it. It goes
// through the same authenticator they do, with the same failure budget, the same
// audit and the organisation's rule on password-only binds. A provider takes
// part by registering a PAOS endpoint; without one its requests are refused.
//
// The assertion carries no SessionIndex and is recorded against no session:
// there is no browser session for a logout here to end, so a logout started
// here does not reach it.
func (s *Server) handleSAMLECP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := s.pathOrg(w, r); !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		soapFault(w, "the request could not be read")
		return
	}
	in, err := saml.ReadECPRequest(body)
	if err != nil {
		soapFault(w, err.Error())
		return
	}
	provider, err := s.providerAt(r, in.Request.Issuer)
	if err != nil {
		if !errors.Is(err, store.ErrSAMLProviderUnknown) {
			s.log.ErrorContext(ctx, "loading a SAML provider for ECP", "err", err)
		}
		soapFault(w, "the AuthnRequest's issuer is not a service provider here")
		return
	}
	if provider.WantAuthnRequestsSigned || in.Request.Signature != nil {
		if err := in.VerifySignature(provider.SPSigningCert); err != nil {
			soapFault(w, err.Error())
			return
		}
	}
	endpoint := s.samlEntityID(provider) + "/ecp"
	validated, err := saml.ValidateAuthnRequest(in.Request, provider, endpoint, time.Now())
	if err != nil {
		soapFault(w, err.Error())
		return
	}
	// Only to a PAOS endpoint: what an ECP carries goes to one, and a provider
	// that registered none has not opted in.
	if validated.Binding != "PAOS" {
		soapFault(w, "the service provider has no PAOS endpoint for this AuthnRequest, so it takes no ECP sign-in")
		return
	}

	user, password, given := r.BasicAuth()
	if !given || user == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+endpoint+`", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	auth := NewLDAPAuthenticator(s.db, s.hasher, provider.OrgID, s.log).
		WithMFAGate(s.BindDemandsMFA).WithCodes(s.BindCodeOK).withVia("saml_ecp")
	id, err := auth.Authenticate(ctx, user, password)
	if err != nil {
		// One answer for every refusal, a wrong password and a missing second
		// factor alike, as the other password-only paths give.
		if !errors.Is(err, errLDAPInvalid) && !errors.Is(err, errMFARequired) {
			s.log.WarnContext(ctx, "an ECP sign-in was not authenticated", "err", err,
				"correlation_id", correlationID(ctx))
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="`+endpoint+`", charset="UTF-8"`)
		http.Error(w, "authentication refused", http.StatusUnauthorized)
		return
	}

	session := store.BrowserSession{UserID: id.UserID, OrgID: provider.OrgID, AuthTime: time.Now(), AMR: id.AMR}
	status := func(code, message string) {
		doc, err := saml.BuildStatusResponse(saml.StatusInput{Issuer: s.samlEntityID(provider),
			Destination: validated.ACSURL, InResponse: validated.RequestID, Status: code, Message: message,
			Now: time.Now()})
		if err != nil {
			soapFault(w, "the identity provider could not answer")
			return
		}
		soapHeaders(w)
		_, _ = io.WriteString(w, saml.ECPEnvelope(validated.ACSURL, doc))
	}
	// What the provider asked of the sign-in, as the browser path holds a
	// session to it: here the sign-in is this one, password and any code.
	rung, reachable := saml.RequestedRung(validated.RequestedACR, validated.ACRComparison)
	if !reachable || (rung >= 2 && !oauth.IsMultiFactor(id.AMR)) {
		status(saml.StatusNoAuthnContext, "the request asks for a second factor; give its code after the "+
			"password, separated by a semicolon")
		return
	}
	if err := checkSPUsable(provider, provider.OrgID); err != nil {
		status(saml.StatusRequestDenied, err.Error())
		return
	}
	if provider.WantAuthnRequestsSigned {
		fresh, err := s.markAuthnRequestAnswered(ctx, validated.RequestID, provider)
		if err != nil {
			soapFault(w, "the identity provider could not answer")
			return
		}
		if !fresh {
			status(saml.StatusRequester, "this AuthnRequest has been answered already")
			return
		}
	}
	doc, _, err := s.issueSAMLAssertion(ctx, r, validated, provider, session)
	var denied *policyDenied
	if errors.As(err, &denied) {
		status(saml.StatusRequestDenied, denied.d.Message)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "issuing a SAML assertion to an ECP", "entity_id", provider.EntityID,
			"err", err, "correlation_id", correlationID(ctx))
		soapFault(w, "the identity provider could not answer")
		return
	}
	soapHeaders(w)
	_, _ = io.WriteString(w, saml.ECPEnvelope(validated.ACSURL, doc))
}
