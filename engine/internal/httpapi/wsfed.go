package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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
// # SAML 1.1 is a choice per application
//
// ADFS issues SAML 1.1 tokens for WS-Federation by default, and some very old
// relying parties accept nothing else. SAML 2.0 stays the default here, because
// it says more: `signari saml wsfed-token` moves one application to 1.1, and
// saml.BuildSAML11Assertion says what that gives up.

// wsFedParams are the parameters this endpoint reads.
var wsFedParams = []string{"wa", "wauth", "wctx", "wfresh", "whr", "wreply", "wtrealm"}

// wsFedRequest reads a request from wherever it came, and leaves it on the URL, so
// that a request parked for a sign-in or a sign-out confirmation is the whole of it.
// Each parameter once: a wreply in both the URL and the body is two answers to where
// the token goes, and what was checked would not be sure to be what was used.
func wsFedRequest(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.New("the request could not be parsed")
	}
	q := url.Values{}
	for _, name := range wsFedParams {
		if given := r.Form[name]; len(given) > 1 {
			return nil, fmt.Errorf("%s was given more than once", name)
		} else if len(given) == 1 {
			q.Set(name, given[0])
		}
	}
	r.URL.RawQuery = q.Encode()
	return q, nil
}

// handleWSFed serves the passive requestor endpoint.
func (s *Server) handleWSFed(w http.ResponseWriter, r *http.Request) {
	q, err := wsFedRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// An application's form, posted across sites. The session cookie is SameSite=Lax
	// and stays behind on that POST, so this would read as nobody signed in: a sign-in
	// asked for again, and worse, a sign-out with nothing to end that tells the
	// application it was done. Sent back as a GET, the browser brings the cookie. The
	// one POST that stays is the sign-out page's own, which carries a token of ours.
	if r.Method == http.MethodPost && r.PostForm.Get(csrfFormField) == "" {
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
		return
	}
	switch q.Get("wa") {
	case "wsignin1.0":
		s.wsFedSignIn(w, r, q)
	case "wsignout1.0", "wsignoutcleanup1.0":
		// Sign-out reuses the ordinary end-session path so one logout mechanism
		// covers every protocol. A separate implementation here would be a
		// second place for "which sessions does this end" to be answered
		// differently.
		s.endSession(w, r, s.wsFedLanding(r, q))
	default:
		writeError(w, http.StatusBadRequest, "invalid_request",
			"wa must be wsignin1.0 or wsignout1.0")
	}
}

// wsFedLanding is where a sign-out may send the person, "" for nowhere. A wreply is a
// reply URL of the realm named or, as Windows Identity Foundation names none, of an
// application this session was given a token for. One that is neither is dropped
// rather than refused: the person asked to sign out, and that still happens.
func (s *Server) wsFedLanding(r *http.Request, q url.Values) string {
	ctx := r.Context()
	reply := q.Get("wreply")
	if reply == "" {
		return ""
	}
	if realm := q.Get("wtrealm"); realm != "" {
		if p, err := s.loadSAMLProvider(ctx, realm); err == nil {
			if _, derr := wsFedDestination(p, reply); derr == nil {
				return reply
			}
		}
	} else if sid, _, _ := s.sessionIdentity(ctx, sessionCookie(r)); sid != "" {
		held, err := store.SessionHoldsReplyURL(ctx, s.db, sid, reply)
		if err != nil {
			s.log.Error("reading the reply URLs of a session", "err", err)
		}
		if held {
			return reply
		}
	}
	s.log.Info("ws-federation sign-out wreply dropped", "wreply", reply, "correlation_id", correlationID(ctx))
	return ""
}

// wsFedDemand is what a request asks of the sign-in behind a token.
type wsFedDemand struct {
	// rung is how far up the ladder wauth asks, 0 for not at all.
	rung int
	// fresh says wfresh was given, and within is the age it allows.
	fresh  bool
	within time.Duration
}

// readWSFedDemand reads wauth and wfresh. Neither that cannot be read is taken as not
// having been said: both ask for more than a session may be able to give, and an
// application that asked for a fresh sign-in must not be handed an old one because of
// how it spelled it.
func readWSFedDemand(q url.Values) (wsFedDemand, error) {
	var d wsFedDemand
	if wauth := q.Get("wauth"); wauth != "" {
		rung, reachable := saml.RequestedAuthType(wauth)
		if !reachable {
			return d, errors.New("wauth names a way of signing in this directory does not offer")
		}
		d.rung = rung
	}
	if wfresh := q.Get("wfresh"); wfresh != "" {
		minutes, err := strconv.ParseUint(wfresh, 10, 24)
		if err != nil {
			return d, errors.New("wfresh must be a whole number of minutes")
		}
		d.fresh, d.within = true, time.Duration(minutes)*time.Minute
	}
	return d, nil
}

// wsFedResume is the request to come back to after a sign-in. Without wfresh, which
// the sign-in has just met and which would otherwise ask again for ever; and without
// whr, whose provider has had its say. A person can take either off the URL anyway:
// the request is not signed, so a relying party that cares reads the token's
// authentication instant, which only signing in can move.
func wsFedResume(q url.Values) string {
	again := url.Values{}
	for name, given := range q {
		if name != "wfresh" && name != "whr" {
			again[name] = given
		}
	}
	return "/wsfed?" + again.Encode()
}

// wsFedToSignIn sends somebody to sign in: to the provider whr names when it names
// one, or to the sign-in page.
func (s *Server) wsFedToSignIn(w http.ResponseWriter, r *http.Request, p *saml.Provider, q url.Values, d wsFedDemand) {
	back := wsFedResume(q)
	if whr := q.Get("whr"); whr != "" {
		slug, kind, err := s.wsFedHomeRealm(r.Context(), p.OrgID, whr)
		if err != nil {
			s.log.Error("finding the provider a whr names", "err", err)
		}
		if slug != "" {
			http.Redirect(w, r, providerStart(slug, kind, url.Values{"return": {back}}.Encode()), http.StatusSeeOther)
			return
		}
	}
	if d.rung >= 2 {
		http.Redirect(w, r, parkLoginForMFA(back), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, parkLogin(back), http.StatusSeeOther)
}

// handleWSFedMetadata serves what a relying party imports, at the path tools look for
// it. Like /saml/metadata, an unknown wtrealm is the default document and not an
// error, so this does not say which realms exist.
func (s *Server) handleWSFedMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signatureAlg := saml.SignatureAlgRSASHA256
	if realm := r.URL.Query().Get("wtrealm"); realm != "" {
		if p, err := s.loadSAMLProvider(ctx, realm); err == nil {
			signatureAlg = p.SignatureAlg
		} else if !errors.Is(err, store.ErrSAMLProviderUnknown) {
			s.log.Error("loading a realm for metadata", "err", err)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
	}
	certs, err := s.samlCertificates(ctx, signatureAlg)
	if err != nil {
		s.log.Error("building WS-Federation metadata", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	doc, err := saml.WSFederationMetadata(saml.WSFederationMetadataInput{
		EntityID: s.samlEntityID(), Endpoint: s.cfg.Issuer + "/wsfed", Certificates: certs})
	if err != nil {
		s.log.Error("rendering WS-Federation metadata", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	writeMetadata(w, r, doc)
}

func (s *Server) wsFedSignIn(w http.ResponseWriter, r *http.Request, q url.Values) {
	ctx := r.Context()
	realm := q.Get("wtrealm")
	if realm == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"wtrealm is required: it names the application being signed in to")
		return
	}

	// The realm is the SAML entity id. Reusing the registry means a WS-Federation
	// application is configured, audited and released exactly like a SAML one.
	p, err := s.loadSAMLProvider(ctx, realm)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found",
			"no application is registered with that wtrealm")
		return
	}

	// Before the sign-in, so nobody is asked to authenticate for an application
	// that will be refused anyway.
	if !p.Enabled {
		writeError(w, http.StatusForbidden, "access_denied",
			"this application has been disabled by its administrator")
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

	demand, derr := readWSFedDemand(q)
	if derr != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", derr.Error())
		return
	}

	session, ok := s.browserSession(r)
	if !ok {
		s.wsFedToSignIn(w, r, p, q, demand)
		return
	}
	// The same check the SAML endpoint makes, and the one this endpoint went
	// without: a realm is another organisation's application, and a session here
	// must not be turned into a signed token for it.
	if err := checkSPUsable(p, session.OrgID); err != nil {
		s.log.Info("ws-federation realm refused", "realm", realm, "err", err)
		writeError(w, http.StatusForbidden, "access_denied", err.Error())
		return
	}

	// Held to the session here, per request, as acr_values and max_age are at the
	// authorization endpoint. A sign-in the person has to do again comes back with
	// neither wfresh nor whr, so this cannot go round for ever.
	if demand.fresh && (demand.within == 0 || time.Since(session.AuthTime) > demand.within) {
		s.wsFedToSignIn(w, r, p, q, demand)
		return
	}
	if demand.rung >= 2 {
		met, err := s.samlSessionReaches(ctx, session)
		if err != nil {
			s.log.Error("checking a session against a wauth", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		switch met {
		case samlContextMet:
		case samlContextUnreachable:
			writeError(w, http.StatusForbidden, "access_denied",
				"this account cannot reach the way of signing in this application asks for")
			return
		default:
			s.wsFedToSignIn(w, r, p, q, demand)
			return
		}
	}

	// The assertion is produced by the SAML path and lifted out of the response
	// it comes wrapped in.
	//
	// Reusing issueSAMLAssertion rather than rebuilding the assertion here is
	// the whole reason this endpoint is safe: the audience restriction, subject
	// confirmation, authentication context and attribute mapping are the ones
	// the SAML side already gets right, and encryption keeps working without a
	// second code path knowing about it. The access policy is applied there too,
	// for both protocols.
	v := &saml.Validated{ACSURL: dest, WSFed: true}
	doc, _, err := s.issueSAMLAssertion(ctx, r, v, p, session)
	var denied *policyDenied
	if errors.As(err, &denied) {
		writeError(w, http.StatusForbidden, "access_denied", denied.d.Message)
		return
	}
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
	rstr, err := wsFedRSTR(assertion, realm, saml.WSFedTokenType(p.WSFedSAMLVersion), time.Now(), lifetime)
	if err != nil {
		s.log.Error("building the RSTR", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "wsfed.token_issued", OrgID: session.OrgID, SubjectID: session.UserID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"wtrealm": realm, "wreply": dest},
	})

	s.wsFedPost(w, r, dest, rstr, q.Get("wctx"))
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
func wsFedRSTR(assertion *etree.Element, realm, tokenType string, now time.Time,
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

	rstr.CreateElement("t:TokenType").SetText(tokenType)
	rstr.CreateElement("t:RequestType").
		SetText("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue")
	rstr.CreateElement("t:KeyType").
		SetText("http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey")

	// NOT indented, for the same reason the SAML response is not: whitespace
	// inserted after signing changes the bytes the digest covered.
	return doc.WriteToString()
}

// wsFedPost renders the form that delivers the token.
// r is carried only so the bridge's <noscript> text can be rendered in the
// language the request asked for; see postAuthzResponse.
func (s *Server) wsFedPost(w http.ResponseWriter, r *http.Request,
	dest, wresult, wctx string) {
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
	s.renderBare(w, r, "wsfed", map[string]any{
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
	// A SAML 1.1 token comes as the assertion, with nothing round it.
	if root.Tag == "Assertion" {
		return root, nil
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
