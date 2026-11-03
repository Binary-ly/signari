package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// The HTTP Artifact binding for responses (8.08). A provider whose assertion
// consumer URL is registered for it is sent an artifact through the browser and
// fetches the response itself, over SOAP, from the artifact resolution service:
//
//	POST /saml/artifact               ArtifactResolve, the deployment's entity
//	POST /saml/org/{org}/artifact     the same, for an organisation's entity
//
// The response never crosses the browser, which is the binding's point.

// deliverSAMLResponse sends a response by the binding the ACS URL it was
// validated against is registered for.
func (s *Server) deliverSAMLResponse(w http.ResponseWriter, r *http.Request, v *saml.Validated,
	p *saml.Provider, doc, relayState string) {
	if v.Binding != "HTTP-Artifact" {
		s.postSAMLResponse(w, r, v.ACSURL, doc, relayState)
		return
	}
	ctx := r.Context()
	artifact, handle, err := saml.NewArtifact(s.samlEntityID(p))
	if err == nil {
		err = store.HoldSAMLArtifact(ctx, s.db, p.ID, p.OrgID, handle, []byte(doc))
	}
	acs, perr := url.Parse(v.ACSURL)
	if err == nil {
		err = perr
	}
	if err != nil {
		s.log.ErrorContext(ctx, "holding a SAML response for its artifact", "entity_id", p.EntityID,
			"err", err, "correlation_id", correlationID(ctx))
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	// URL encoding, by redirect (saml-bindings-2.0-os lines 1026-1030, 1113-1117).
	q := acs.Query()
	q.Set("SAMLart", artifact)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	acs.RawQuery = q.Encode()
	// Lines 1145-1147: an artifact is not to be cached on the way.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, acs.String(), http.StatusSeeOther)
}

// handleSAMLArtifactResolve answers a provider resolving an artifact.
//
// A request that is not a readable ArtifactResolve is a SOAP fault and a 500
// (saml-bindings-2.0-os lines 372-377). One that is gets a 200 and an
// ArtifactResponse with Success, carrying the response only when the artifact is
// live and the requester shows, by a signature over its ArtifactResolve made with
// the certificate registered for it, that it is the provider the artifact was
// issued to: "If the artifact issuer receives an <ArtifactResolve> message from
// a requester that cannot authenticate itself as the original intended
// recipient, then the artifact issuer MUST return an empty response"
// (saml-core-2.0-os lines 2397-2400).
func (s *Server) handleSAMLArtifactResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := s.pathOrg(w, r); !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		soapFault(w, "the request could not be read")
		return
	}
	resolve, err := saml.ReadArtifactResolve(body)
	if err != nil {
		soapFault(w, err.Error())
		return
	}
	p, message, why := s.resolveSAMLArtifact(ctx, r, resolve)
	if why != "" {
		s.log.WarnContext(ctx, "a SAML artifact was not given out", "issuer", resolve.Issuer,
			"reason", why, "correlation_id", correlationID(ctx))
		auditOrg := ""
		if p != nil {
			auditOrg = p.OrgID
		}
		s.auditDetached(ctx, audit.Event{Type: "saml.artifact_refused", OrgID: auditOrg,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"issuer": resolve.Issuer, "reason": why}})
		message = nil
	}
	// Answered as the provider's own identity provider where the provider is
	// known, so its algorithm and entity id are the ones it expects; otherwise
	// as the deployment, with RSA.
	issuer, alg := saml.EntityID(s.cfg.Issuer, ""), saml.SignatureAlgRSASHA256
	if p != nil {
		issuer, alg = s.samlEntityID(p), p.SignatureAlg
	}
	key, err := s.samlSigningKey(alg)
	var certDER []byte
	if err == nil {
		certDER, err = s.samlCertificateFor(ctx, key)
	}
	var answer string
	if err == nil {
		answer, err = saml.BuildArtifactResponse(saml.ArtifactResponseInput{Issuer: issuer,
			InResponseTo: resolve.ID, Now: time.Now()}, string(message), key.Signer(), certDER)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "answering an ArtifactResolve", "err", err, "correlation_id", correlationID(ctx))
		soapFault(w, "the identity provider could not answer")
		return
	}
	soapHeaders(w)
	_, _ = io.Copy(w, bytes.NewBufferString(answer))
}

// resolveSAMLArtifact takes what the artifact names and decides whether this
// requester gets it, saying why not when it does not. The artifact is gone
// either way, once asked for.
func (s *Server) resolveSAMLArtifact(ctx context.Context, r *http.Request,
	resolve *saml.ArtifactResolve) (*saml.Provider, []byte, string) {
	_, sourceID, handle, err := saml.ParseArtifact(resolve.Artifact)
	if err != nil {
		return nil, nil, err.Error()
	}
	providerID, message, err := store.TakeSAMLArtifact(ctx, s.db, handle)
	switch {
	case errors.Is(err, store.ErrSAMLArtifactGone):
		return nil, nil, "the artifact was resolved before, expired, or never issued"
	case err != nil:
		return nil, nil, fmt.Sprintf("taking the artifact: %v", err)
	}
	p, err := store.LoadSAMLProviderByID(ctx, s.db, providerID)
	if err != nil {
		return nil, nil, fmt.Sprintf("loading the provider it was issued to: %v", err)
	}
	if resolve.Issuer != p.EntityID {
		return p, nil, fmt.Sprintf("the artifact was issued to %q", p.EntityID)
	}
	if err := resolve.VerifySignature(p.SPSigningCert); err != nil {
		return p, nil, err.Error()
	}
	entityID := s.samlEntityID(p)
	if !bytes.Equal(sourceID, saml.SourceID(entityID)) {
		return p, nil, "the artifact names another issuer"
	}
	if resolve.Destination != "" && resolve.Destination != entityID+"/artifact" {
		return p, nil, fmt.Sprintf("the ArtifactResolve is addressed to %q", resolve.Destination)
	}
	if !p.Enabled {
		return p, nil, "the provider is disabled"
	}
	return p, message, ""
}

// soapHeaders are a SOAP answer's, uncached (saml-bindings-2.0-os lines 364-368).
func soapHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
}

func soapFault(w http.ResponseWriter, reason string) {
	soapHeaders(w)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = io.WriteString(w, saml.SOAPFault(reason))
}
