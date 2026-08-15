package httpapi

import (
	"encoding/xml"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)


// samlSourceRequestTTL bounds how long a sign-in may take.
//
// Ten minutes: long enough for a password, an MFA prompt and a slow upstream,
// short enough that an abandoned request is not a credential lying around. It
// also bounds how long the replay window is, since a response can only be
// consumed while its request is live.
const samlSourceRequestTTL = 10 * time.Minute

// handleSAMLSourceStart sends the browser to the upstream provider.
func (s *Server) handleSAMLSourceStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := samlSourceSlug(r.URL.Path, "/start")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	src, err := store.LoadSAMLSource(ctx, s.db, slug, s.cfg.Issuer)
	if err != nil {
		s.log.Info("unknown SAML source", "slug", slug, "err", err)
		http.NotFound(w, r)
		return
	}

	relay, err := saml.RelayStateToken()
	if err != nil {
		s.log.Error("generating relay state", "err", err)
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	req, err := saml.BuildAuthnRequest(src.Provider, relay, time.Now())
	if err != nil {
		s.log.Error("building the SAML request", "slug", slug, "err", err)
		s.federationError(w, r, "That sign-in method is not configured correctly.")
		return
	}

	// The destination is stored HERE, keyed by the relay state, rather than
	// carried in RelayState itself. RelayState comes back from the upstream
	// exactly as whoever started the flow chose it, so a URL in it is an open
	// redirect with extra steps.
	returnPath := s.validFederationReturn(r.URL.Query().Get("return"))

	if err := store.RecordSAMLRequest(ctx, s.db, src.ProviderID, req.ID, relay,
		returnPath, samlSourceRequestTTL); err != nil {
		s.log.Error("recording the SAML request", "err", err)
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	http.Redirect(w, r, req.RedirectURL, http.StatusFound)
}

// handleSAMLSourceACS consumes an assertion from the upstream provider.
func (s *Server) handleSAMLSourceACS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := samlSourceSlug(r.URL.Path, "/acs")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}

	src, err := store.LoadSAMLSource(ctx, s.db, slug, s.cfg.Issuer)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	raw, err := saml.DecodePOST(r.PostForm.Get("SAMLResponse"))
	if err != nil {
		s.log.Info("undecodable SAML response", "slug", slug, "err", err)
		s.federationError(w, r, "That sign-in could not be completed.")
		return
	}

	// The outstanding request for THIS browser, claimed exactly once. Its
	// absence is not an error to explain in detail: a response arriving with no
	// matching request is either a stale tab or a replay, and the two look
	// identical from here.
	var expectedID, returnPath string
	relay := r.PostForm.Get("RelayState")
	if relay != "" {
		pending, perr := store.ConsumeSAMLRequest(ctx, s.db, relay)
		if perr != nil {
			s.log.Info("no outstanding SAML request", "slug", slug, "err", perr)
			s.federationError(w, r, "That sign-in has expired. Please try again.")
			return
		}
		if pending.ProviderID != src.ProviderID {
			// The relay state belongs to a different provider. Refused rather than
			// reconciled: it means the response and the request came from two
			// different flows.
			s.log.Info("relay state belongs to another provider", "slug", slug)
			s.federationError(w, r, "That sign-in could not be completed.")
			return
		}
		expectedID = pending.ID
		returnPath = pending.ReturnPath
	}

	assertion, err := saml.ConsumeResponse(raw, src.Provider, saml.ConsumeOptions{
		ExpectedInResponseTo: expectedID,
		Destination:          src.Provider.ACSURL,
		Now:                  time.Now(),
	})
	if err != nil {
		// Logged in full, shown in outline. The detail is what an operator needs
		// and what an attacker would use to find which check to satisfy next.
		s.log.Warn("SAML assertion refused", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "That sign-in could not be completed.")
		return
	}

	// A transient NameID is a different value on every sign-in, so linking an
	// account to it creates a new orphaned account each time. Refused with an
	// explanation, because it is a configuration mistake on the upstream and the
	// operator is the only person who can fix it.
	if err := saml.CheckSubjectFormat(assertion.SubjectFormat); err != nil {
		s.log.Warn("transient NameID from a SAML source", "slug", slug, "err", err)
		s.federationError(w, r, "That sign-in method is not configured correctly.")
		return
	}

	// Spend the assertion. After this, the same document is worthless.
	if err := store.RecordSAMLAssertion(ctx, s.db, src.ProviderID,
		assertion.AssertionID, assertion.NotOnOrAfter); err != nil {
		s.log.Warn("SAML assertion replay", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "That sign-in could not be completed.")
		return
	}

	// From here it is the ordinary external-identity path: the same decision,
	// the same linking rules, the same audit events as Google or GitHub.
	ext := federation.ExternalIdentity{
		Subject: assertion.Subject,
		Email:   assertion.Email,
		Name:    assertion.Name,
		// A SAML upstream does not send a verification flag. Whether its
		// addresses are trustworthy is a property of the deployment, recorded on
		// the provider, not something the assertion can assert about itself.
		EmailVerified: src.Policy.TrustsEmailVerification,
	}

	s.completeFederation(w, r, &federation.Config{
		ID:          src.ProviderID,
		OrgID:       src.OrgID,
		Slug:        src.Slug,
		DisplayName: src.DisplayName,
		Policy:      src.Policy,
		Kind:        federation.KindSAML,
	}, &store.PendingLogin{ReturnTo: returnPath}, ext)
}

// samlSourceSlug pulls the slug out of /saml/source/{slug}/{suffix}.
func samlSourceSlug(path, suffix string) string {
	const prefix = "/saml/source/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	slug := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	// One path segment, and nothing that could climb out of it.
	if slug == "" || strings.ContainsAny(slug, "/.%\\") {
		return ""
	}
	return slug
}

// handleSAMLSourceMetadata publishes our SP metadata for one source.
//
// Every upstream asks for this file, and the alternative is an operator typing
// an entity ID and an ACS URL into someone else's console by hand. A typo there
// produces an assertion addressed to the wrong audience, which this engine
// refuses correctly and unhelpfully.
func (s *Server) handleSAMLSourceMetadata(w http.ResponseWriter, r *http.Request) {
	slug := samlSourceSlug(r.URL.Path, "/metadata")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	src, err := store.LoadSAMLSource(r.Context(), s.db, slug, s.cfg.Issuer)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// No signing certificate is advertised: this SP does not sign its requests
	// and does not accept encrypted assertions yet, and advertising either would
	// be the "documented but absent" failure this project sweeps for.
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` +
		xmlAttr(src.Provider.SPEntityID) + `">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>` + xmlAttr(saml.FullNameIDFormat(src.Provider.NameIDFormat)) +
		`</NameIDFormat>
    <AssertionConsumerService index="0" isDefault="true"
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="` + xmlAttr(src.Provider.ACSURL) + `"/>
  </SPSSODescriptor>
</EntityDescriptor>
`
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write([]byte(xml))
}

// xmlAttr escapes a value for an XML attribute.
//
// Every value here comes from configuration rather than from a request, which
// is an argument for escaping them, not against it: the day somebody puts an
// ampersand in an entity ID, the metadata should stay well-formed rather than
// silently truncate at the point the upstream's parser gives up.
func xmlAttr(v string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(v)); err != nil {
		return ""
	}
	return b.String()
}
