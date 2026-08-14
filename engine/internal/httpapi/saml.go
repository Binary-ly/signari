package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// SAML 2.0 identity provider endpoints.
//
//	GET  /saml/metadata   what a service provider imports
//	GET  /saml/sso        HTTP-Redirect binding
//	POST /saml/sso        HTTP-POST binding
//
// The security work lives in internal/saml, which was written against the
// published advisories for the Go SAML libraries rather than from memory. What
// remains here is the part those libraries do not cover: session handling,
// RelayState, and refusing to emit anything before the request is validated.

const (
	// maxRelayState is the value SAML itself specifies: 80 bytes. It is enforced
	// because RelayState comes back to us from the browser and goes into an HTML
	// form, and an unbounded attacker-controlled string in a page we render is a
	// place to put a payload.
	maxRelayState = 80

	// samlRequestTTL is how long a seen request id is remembered for replay
	// detection. Comfortably longer than the assertion lifetime, so a replay
	// cannot simply wait for the record to expire.
	samlRequestTTL = 30 * time.Minute
)

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	certs, err := s.samlCertificates(ctx)
	if err != nil {
		s.log.Error("building SAML metadata", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	doc, err := saml.Metadata(saml.MetadataInput{
		EntityID: s.samlEntityID(),
		SSOURL:   s.cfg.Issuer + "/saml/sso",
		// Advertised now that it is implemented, and not before -- the same rule
		// OIDC discovery follows here. An endpoint in metadata that answers with
		// an error is worse than one that is absent: the service provider calls
		// it, fails, and blames its own configuration.
		SLOURL:       s.cfg.Issuer + "/saml/slo",
		Certificates: certs,
		NameIDFormat: saml.NameIDFormatPersistent,
	})
	if err != nil {
		s.log.Error("rendering SAML metadata", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	// Cacheable, but briefly. Service providers refetch metadata to pick up a
	// rotating certificate, and a long cache is what turns rotation into an
	// outage.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(doc))
}

// samlEntityID is our own entity id.
//
// Derived from the issuer rather than configured separately, because two names
// for the same thing is how a deployment ends up with metadata that no service
// provider can match against the assertions it receives.
func (s *Server) samlEntityID() string { return s.cfg.Issuer + "/saml" }

// handleSAMLSSO answers an AuthnRequest on either binding.
func (s *Server) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var encoded, relayState string
	switch r.Method {
	case http.MethodGet:
		encoded = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.samlRefuse(w, r, "the request could not be parsed")
			return
		}
		encoded = r.PostForm.Get("SAMLRequest")
		relayState = r.PostForm.Get("RelayState")
	}
	if encoded == "" {
		s.samlRefuse(w, r, "no SAMLRequest")
		return
	}
	if len(relayState) > maxRelayState {
		// Refused rather than truncated: a truncated RelayState is returned to the
		// service provider as something it never sent, and it will fail there in a
		// way nobody can trace back to here.
		s.samlRefuse(w, r, fmt.Sprintf("RelayState is %d bytes, over the %d the "+
			"specification allows", len(relayState), maxRelayState))
		return
	}

	// Which decoding applies depends on how the request ORIGINALLY arrived, not
	// on how it is arriving now. A POST-binding request parked across sign-in
	// comes back as a GET, and feeding its plain base64 to the inflater fails --
	// so the original binding is carried on the resume URL.
	var raw []byte
	var err error
	if r.Method == http.MethodPost || samlBindingFromQuery(r) {
		raw, err = saml.DecodePOST(encoded)
	} else {
		raw, err = saml.DecodeRedirect(encoded)
	}
	if err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}

	var req saml.AuthnRequest
	if err := saml.Unmarshal(raw, &req); err != nil {
		s.samlRefuse(w, r, err.Error())
		return
	}

	provider, err := store.LoadSAMLProvider(ctx, s.db, req.Issuer)
	if err != nil {
		if errors.Is(err, store.ErrSAMLProviderUnknown) {
			// Deliberately NOT a SAML error response. Answering an unknown entity
			// id with a redirect to whatever URL the request named would make this
			// endpoint a redirector for any entity id an attacker cares to invent.
			s.samlRefuse(w, r, fmt.Sprintf("no service provider is registered with "+
				"the entity id %q", req.Issuer))
			return
		}
		s.log.Error("loading SAML provider", "entity_id", req.Issuer, "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	validated, err := saml.ValidateAuthnRequest(&req, provider, s.cfg.Issuer+"/saml/sso", time.Now())
	if err != nil {
		// Refused locally, again. Every failure here is a statement about the
		// request itself, so there is no established, trustworthy place to send a
		// SAML error to -- the ACS URL is exactly what is in dispute.
		s.log.Info("SAML AuthnRequest refused", "entity_id", req.Issuer, "err", err,
			"correlation_id", correlationID(ctx))
		s.samlRefuse(w, r, err.Error())
		return
	}

	// Is there a live session? If not, park this request and sign in first.
	sid, userID, orgID, ok := s.currentSession(r)

	// # ForceAuthn without an infinite loop
	//
	// The obvious reading -- "ForceAuthn is set, so send them to sign in" --
	// loops forever: the resumed request still carries ForceAuthn, so it bounces
	// straight back to the login page, and nothing reports an error because
	// every redirect is individually correct. It is the same shape as the
	// forward-auth cookie loop.
	//
	// A session established AFTER the service provider issued its request IS a
	// fresh authentication for that request, so the comparison terminates. The
	// user cannot forge their way past it either: the only way to move auth_time
	// forward is to actually authenticate again.
	needsAuth := !ok
	if ok && validated.ForceAuthn {
		fresh, ferr := s.sessionAuthedAfter(ctx, sid, validated.IssueInstant)
		if ferr != nil {
			s.log.Error("checking session freshness for ForceAuthn", "err", ferr)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		needsAuth = !fresh
	}
	if needsAuth {
		if validated.IsPassive {
			// The service provider asked us not to interact with the user, and we
			// would have to. That is a defined answer, not an error.
			s.postSAMLStatus(w, r, validated, provider, saml.StatusNoPassive,
				"the user is not signed in and IsPassive was requested", relayState)
			return
		}
		back := "/saml/sso?" + samlResumeQuery(encoded, relayState, r.Method)
		http.Redirect(w, r, parkLogin(back), http.StatusFound)
		return
	}

	if provider.OrgID != orgID {
		// The signed-in user belongs to a different organisation than the service
		// provider does. Issuing here would be a cross-tenant assertion.
		s.samlRefuse(w, r, "this service provider belongs to a different organisation")
		return
	}

	doc, acs, err := s.issueSAMLAssertion(ctx, validated, provider, sid, userID, orgID)
	if err != nil {
		s.log.Error("issuing SAML assertion", "entity_id", provider.EntityID, "err", err,
			"correlation_id", correlationID(ctx))
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.postSAMLResponse(w, acs, doc, relayState)
}

// sessionAuthedAfter reports whether this session was authenticated after t.
func (s *Server) sessionAuthedAfter(ctx context.Context, sid string, t time.Time) (bool, error) {
	var authTime time.Time
	if err := s.db.QueryRow(ctx,
		`SELECT auth_time FROM core.sessions WHERE sid = $1`, sid).Scan(&authTime); err != nil {
		return false, err
	}
	return authTime.After(t), nil
}

// samlResumeQuery rebuilds the query that brings the browser back here after
// sign-in.
//
// The request is carried on the URL even when it arrived by POST, because after
// the login redirect there is no POST body left to resume from. That is safe:
// the AuthnRequest is not a secret, it is signed or it is not, and either way
// it is re-validated from scratch on the way back through.
func samlResumeQuery(encoded, relayState, method string) string {
	q := url.Values{}
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	if method == http.MethodPost {
		// Marks that the original arrived POST-encoded (base64 only, no DEFLATE),
		// so the resumed request is decoded the same way rather than being fed to
		// the inflater and failing.
		q.Set("Binding", "POST")
	}
	return q.Encode()
}

func (s *Server) issueSAMLAssertion(ctx context.Context, v *saml.Validated, p *saml.Provider,
	sid, userID, orgID string) (doc string, acs string, err error) {

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	nameID, err := store.EnsureNameID(ctx, tx, p.ID, userID, orgID, p.NameIDFormat)
	if err != nil {
		return "", "", err
	}

	key, err := s.samlSigningKey()
	if err != nil {
		return "", "", err
	}
	certDER, err := saml.EnsureCertificate(ctx, tx, key.KID(), s.cfg.Issuer, key.Signer())
	if err != nil {
		return "", "", err
	}

	// The SessionIndex is the IdP session id. Reusing it means a logout knows
	// exactly which SAML sessions to end, with no second mapping to maintain and
	// go stale.
	sessionIndex := sid

	acr, amr, authTime, err := store.SessionAuthContext(ctx, tx, sid)
	if err != nil {
		return "", "", err
	}

	// Group attributes, if this provider is released any. Read here, inside the
	// same transaction that mints the assertion, for the same reason the OIDC
	// path reads them at issuance: an assertion is an authorization statement
	// with a lifetime, and a stale group in one is privilege that outlived its
	// revocation.
	attrs := map[string][]string{}
	if attrName, groups, gerr := store.GroupsForSAML(ctx, tx, userID, p.ID); gerr != nil {
		return "", "", gerr
	} else if attrName != "" && len(groups) > 0 {
		attrs[attrName] = groups
	}

	lifetime := time.Duration(p.LifetimeSeconds) * time.Second
	doc, err = saml.BuildResponse(saml.ResponseInput{
		Issuer:      s.samlEntityID(),
		Destination: v.ACSURL,
		InResponse:  v.RequestID,
		Audience:    p.EntityID,
		Lifetime:    lifetime,
		Now:         time.Now(),
		Subject: saml.Subject{
			NameID:       nameID,
			NameIDFormat: saml.FullNameIDFormat(p.NameIDFormat),
			SessionIndex: sessionIndex,
			AuthnInstant: authTime,
			// The context reflects what the user ACTUALLY did, not what was asked
			// for. Claiming multi-factor for a password-only session is a lie the
			// service provider makes access decisions on.
			AuthnContext: samlAuthnContext(acr, amr),
			Attributes:   attrs,
		},
	}, key.KID(), key.Signer(), certDER)
	if err != nil {
		return "", "", err
	}

	if err := store.RecordSAMLParticipant(ctx, tx, sid, p.ID, orgID, sessionIndex, nameID); err != nil {
		return "", "", err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "saml.assertion_issued", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"entity_id": p.EntityID, "acs": v.ACSURL, "request_id": v.RequestID,
		},
	}); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return doc, v.ACSURL, nil
}

// samlAuthnContext reports what the user ACTUALLY did to sign in.
//
// The service provider makes access decisions on this. Overstating it -- saying
// multi-factor when the user typed a password -- is not a cosmetic error; it
// tells an SP that its step-up requirement was satisfied when it was not.
//
// The first version of this asserted MultiFactorAuthentication whenever acr was
// anything other than "0", and a password-only session carries acr "1". So
// every ordinary login claimed MFA. It was caught by comparing a live assertion
// against the session row that produced it, not by reading the code.
func samlAuthnContext(acr string, amr []string) string {
	for _, m := range amr {
		switch m {
		case oauth.AMROTP, oauth.AMRHardwareKey, oauth.AMRMFA:
			return saml.AuthnContextMFA
		}
	}
	if acr == oauth.ACRMultiFactor || acr == oauth.ACRPapeMultiFactor {
		return saml.AuthnContextMFA
	}
	return saml.AuthnContextPassword
}

// samlPostForm is the auto-submitting form the HTTP-POST binding requires.
//
// Every value is inserted through html/template, which escapes by context. The
// SAMLResponse is base64 and RelayState is bounded and opaque, but "the input
// happens to be safe" is not a property to rely on in a page we render --
// crewjam/saml GHSA-267v-3v32-g6q5 was cross-site scripting through exactly
// this surface.
var samlPostForm = template.Must(template.New("saml").Parse(`<!DOCTYPE html>
<html><head><title>Signing in&hellip;</title></head>
<body onload="document.forms[0].submit()">
<noscript><p>JavaScript is disabled. Continue to complete signing in.</p></noscript>
<form method="post" action="{{.ACS}}">
<input type="hidden" name="SAMLResponse" value="{{.Response}}">
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}">{{end}}
<noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>`))

func (s *Server) postSAMLResponse(w http.ResponseWriter, acs, doc, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The page contains an assertion, so it must not be framed: a framed
	// auto-submitting form is how an assertion gets delivered without the user
	// realising anything happened.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")

	if err := samlPostForm.Execute(w, map[string]string{
		"ACS":        acs,
		"Response":   base64Std(doc),
		"RelayState": relayState,
	}); err != nil {
		s.log.Error("rendering the SAML POST form", "err", err)
	}
}

// postSAMLStatus sends a non-success status to the service provider.
//
// Only reachable once the request has been validated and the ACS URL confirmed
// against the allow-list, so this cannot be used to bounce a browser somewhere
// of the caller's choosing.
func (s *Server) postSAMLStatus(w http.ResponseWriter, r *http.Request, v *saml.Validated,
	p *saml.Provider, status, reason, relayState string) {

	doc, err := saml.BuildStatusResponse(saml.StatusInput{
		Issuer:      s.samlEntityID(),
		Destination: v.ACSURL,
		InResponse:  v.RequestID,
		Status:      status,
		Message:     reason,
		Now:         time.Now(),
	})
	if err != nil {
		s.log.Error("building a SAML status response", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	s.postSAMLResponse(w, v.ACSURL, doc, relayState)
}

// samlRefuse answers the BROWSER, not the service provider.
//
// Used for every failure that happens before an ACS URL has been validated. The
// alternative -- rendering a SAML error and POSTing it to the URL in the
// request -- would hand an attacker a redirect to anywhere, which is the thing
// the allow-list exists to prevent.
func (s *Server) samlRefuse(w http.ResponseWriter, r *http.Request, reason string) {
	s.log.Info("SAML request refused", "reason", reason,
		"correlation_id", correlationID(r.Context()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	// The reason is rendered as text through the template package, never
	// concatenated into HTML: much of it is attacker-controlled.
	_ = samlErrorPage.Execute(w, map[string]string{
		"Reason":        reason,
		"CorrelationID": correlationID(r.Context()),
	})
}

var samlErrorPage = template.Must(template.New("samlerr").Parse(`<!DOCTYPE html>
<html><head><title>Sign-in request refused</title></head>
<body>
<h1>This sign-in request was refused</h1>
<p>{{.Reason}}</p>
<p>Reference: <code>{{.CorrelationID}}</code></p>
</body></html>`))

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// samlBindingFromQuery reports whether a resumed request arrived POST-encoded.
func samlBindingFromQuery(r *http.Request) bool {
	return strings.EqualFold(r.URL.Query().Get("Binding"), "POST")
}

// samlSigningKey picks the key SAML can actually use.
//
// Distinct from anySigningKey, which prefers ES256: that is the right default
// for OIDC and unusable here, because a great deal of service-provider software
// cannot verify ECDSA. Choosing it would produce assertions that are correct and
// rejected anyway.
func (s *Server) samlSigningKey() (keys.Key, error) {
	if k, err := s.cfg.Keys.Active(keys.RS256); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("SAML needs an active RS256 key and this instance has none; " +
		"add one with `signari keys rotate -alg RS256`")
}

// samlCertificateFor returns the stored certificate for one key.
func (s *Server) samlCertificateFor(ctx context.Context, k keys.Key) ([]byte, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	der, err := saml.EnsureCertificate(ctx, tx, k.KID(), s.cfg.Issuer, k.Signer())
	if err != nil {
		return nil, err
	}
	return der, tx.Commit(ctx)
}

// samlCertificates returns every certificate a service provider should accept,
// so that rotation does not break every integration at the moment of the switch.
func (s *Server) samlCertificates(ctx context.Context) ([][]byte, error) {
	k, err := s.samlSigningKey()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	der, err := saml.EnsureCertificate(ctx, tx, k.KID(), s.cfg.Issuer, k.Signer())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return [][]byte{der}, nil
}
