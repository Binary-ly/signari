package httpapi

import (
	"net/http"
	"time"

	"github.com/beevik/etree"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// WS-Federation, passive requestor profile.
//
// # What this is for, stated plainly
//
// SharePoint, older .NET applications built on Windows Identity Foundation, and
// anything that was federated to ADFS before SAML 2.0 was the default. It is a
// compatibility shim for an estate being migrated, not a protocol anybody
// should choose today, and the documentation says so rather than listing it as
// a feature.
//
// # How it works
//
// A sign-in is a redirect carrying `wa=wsignin1.0` and a `wtrealm` naming the
// application. The answer is an HTML form that posts a
// RequestSecurityTokenResponse to the application, containing a signed
// assertion.
//
// The assertion is built by the SAML package, using the same code path that
// builds one for a SAML 2.0 response. That is the point: a second assertion
// builder is a second place to forget an audience restriction, and everything
// that makes the SAML side safe lives in the code this reuses.
//
// # SAML 1.1 is not offered
//
// ADFS issues SAML 1.1 tokens for WS-Federation by default, and some very old
// relying parties accept nothing else. This issues SAML 2.0 assertions, which
// Windows Identity Foundation and every ADFS-era relying party configured for
// SAML 2.0 accept. A relying party that requires 1.1 will not work here, and
// the documentation says so plainly rather than leaving an operator to infer it
// from a failure that looks like a signature problem.

// handleWSFed serves the passive requestor endpoint.
func (s *Server) handleWSFed(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("wa") {
	case "wsignin1.0":
		s.wsFedSignIn(w, r)
	case "wsignout1.0", "wsignoutcleanup1.0":
		// Sign-out reuses the ordinary end-session path so one logout mechanism
		// covers every protocol. A separate implementation here would be a
		// second place for "which sessions does this end" to be answered
		// differently.
		s.handleEndSession(w, r)
	default:
		writeError(w, http.StatusBadRequest, "invalid_request",
			"wa must be wsignin1.0 or wsignout1.0")
	}
}

func (s *Server) wsFedSignIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	realm := q.Get("wtrealm")
	if realm == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"wtrealm is required: it names the application being signed in to")
		return
	}

	// The realm is the SAML entity id. Reusing the registry means a WS-Federation
	// application is configured, audited and released exactly like a SAML one.
	p, err := store.LoadSAMLProvider(ctx, s.db, realm)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found",
			"no application is registered with that wtrealm")
		return
	}

	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}

	// wreply names where the token is posted. Matched against the registered ACS
	// URLs rather than trusted: an unchecked wreply makes this endpoint a
	// redirector that delivers a signed assertion wherever a link says.
	reply := q.Get("wreply")
	dest, derr := wsFedDestination(p, reply)
	if derr != nil {
		s.log.Info("ws-federation wreply refused", "realm", realm, "wreply", reply)
		writeError(w, http.StatusBadRequest, "invalid_request", derr.Error())
		return
	}

	mfa, amr := sessionFactors(ctx, s.db, sid)
	if pd := s.checkAccessPolicy(ctx, r, orgID, realm, userID, "openid", mfa, amr); pd != nil {
		writeError(w, http.StatusForbidden, "access_denied", pd.Message)
		return
	}

	// The assertion is produced by the SAML path and lifted out of the response
	// it comes wrapped in.
	//
	// Reusing issueSAMLAssertion rather than rebuilding the assertion here is
	// the whole reason this endpoint is safe: the audience restriction, subject
	// confirmation, authentication context and attribute mapping are the ones
	// the SAML side already gets right, and encryption keeps working without a
	// second code path knowing about it.
	v := &saml.Validated{ACSURL: dest}
	doc, _, err := s.issueSAMLAssertion(ctx, v, p, sid, userID, orgID)
	if err != nil {
		s.log.Error("building the ws-federation assertion", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	assertion, err := extractAssertion(doc)
	if err != nil {
		s.log.Error("extracting the assertion for ws-federation", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	lifetime := time.Duration(p.LifetimeSeconds) * time.Second
	rstr, err := wsFedRSTR(assertion, realm, time.Now(), lifetime)
	if err != nil {
		s.log.Error("building the RSTR", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "wsfed.token_issued", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"wtrealm": realm, "wreply": dest},
	})

	s.wsFedPost(w, dest, rstr, q.Get("wctx"))
}

// wsFedDestination validates wreply against the registered ACS URLs.
func wsFedDestination(p *saml.Provider, reply string) (string, error) {
	// No wreply is normal: the default ACS URL is used, which is the safest
	// possible answer because it is the one the operator registered.
	if reply == "" {
		for _, a := range p.ACSURLs {
			if a.IsDefault {
				return a.URL, nil
			}
		}
		if len(p.ACSURLs) > 0 {
			return p.ACSURLs[0].URL, nil
		}
		return "", errNoACS
	}
	for _, a := range p.ACSURLs {
		if a.URL == reply {
			return reply, nil
		}
	}
	// Matched exactly, never by prefix. A prefix match on a URL is how a
	// redirector is built by accident.
	return "", errWReplyUnregistered
}

var (
	errNoACS              = &wsFedError{"this application has no reply URL registered"}
	errWReplyUnregistered = &wsFedError{
		"wreply is not one of the reply URLs registered for this application. " +
			"It is matched exactly, because anything looser would let a link decide " +
			"where a signed assertion is delivered"}
)

type wsFedError struct{ msg string }

func (e *wsFedError) Error() string { return e.msg }

// wsFedRSTR wraps an assertion in a RequestSecurityTokenResponse.
func wsFedRSTR(assertion *etree.Element, realm string, now time.Time,
	lifetime time.Duration) (string, error) {

	doc := etree.NewDocument()
	rstr := doc.CreateElement("t:RequestSecurityTokenResponse")
	// Every prefix declared on the ROOT.
	//
	// A namespace declared on the element that first uses it does not cover that
	// element's siblings, which is how <wsu:Created> can carry xmlns:wsu while
	// <wsu:Expires> beside it has an unbound prefix. The document then fails to
	// parse at the relying party, and the failure names a column number rather
	// than a cause.
	rstr.CreateAttr("xmlns:t", "http://schemas.xmlsoap.org/ws/2005/02/trust")
	rstr.CreateAttr("xmlns:wsu",
		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	rstr.CreateAttr("xmlns:wsp", "http://schemas.xmlsoap.org/ws/2004/09/policy")
	rstr.CreateAttr("xmlns:wsa", "http://www.w3.org/2005/08/addressing")

	lt := rstr.CreateElement("t:Lifetime")
	lt.CreateElement("wsu:Created").SetText(now.UTC().Format(time.RFC3339))
	lt.CreateElement("wsu:Expires").SetText(now.Add(lifetime).UTC().Format(time.RFC3339))

	ar := rstr.CreateElement("wsp:AppliesTo")
	epr := ar.CreateElement("wsa:EndpointReference")
	epr.CreateElement("wsa:Address").SetText(realm)

	rst := rstr.CreateElement("t:RequestedSecurityToken")
	rst.AddChild(assertion.Copy())

	rstr.CreateElement("t:TokenType").SetText("urn:oasis:names:tc:SAML:2.0:assertion")
	rstr.CreateElement("t:RequestType").
		SetText("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue")
	rstr.CreateElement("t:KeyType").
		SetText("http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey")

	// NOT indented, for the same reason the SAML response is not: whitespace
	// inserted after signing changes the bytes the digest covered.
	return doc.WriteToString()
}

// wsFedPost renders the form that delivers the token.
func (s *Server) wsFedPost(w http.ResponseWriter, dest, wresult, wctx string) {
	nonce, err := newCSPNonce()
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	setCSP(w, "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
		"form-action "+formActionOrigin(dest)+"; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	s.renderBare(w, "wsfed", map[string]any{
		"Action": dest, "WResult": wresult, "WCtx": wctx, "Nonce": nonce,
	})
}

// extractAssertion lifts the assertion out of a SAML Response document.
//
// Either form: a plain <saml:Assertion> or an <saml:EncryptedAssertion>, so a
// provider with an encryption certificate registered gets an encrypted token in
// its RSTR without this endpoint knowing anything about encryption.
func extractAssertion(doc string) (*etree.Element, error) {
	d := etree.NewDocument()
	if err := d.ReadFromString(doc); err != nil {
		return nil, err
	}
	root := d.Root()
	if root == nil {
		return nil, errNoAssertion
	}
	for _, child := range root.ChildElements() {
		switch child.Tag {
		case "Assertion", "EncryptedAssertion":
			return child, nil
		}
	}
	return nil, errNoAssertion
}

var errNoAssertion = &wsFedError{"the SAML response contained no assertion"}
