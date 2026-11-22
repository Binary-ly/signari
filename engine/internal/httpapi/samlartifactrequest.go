package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// A message a service provider sends by artifact (8.08): the browser brings SAMLart,
// and this deployment fetches the message from the provider's artifact resolution
// service over SOAP, "temporarily reversing roles" (saml-bindings-2.0-os lines
// 1121-1126).

// maxArtifactAnswer bounds what a provider's resolution service may send back.
const maxArtifactAnswer = 1 << 20

// artifactResolveTimeout bounds the call the browser is waiting on.
const artifactResolveTimeout = 10 * time.Second

// resolveSAMLRequestArtifact answers an AuthnRequest sent by artifact: fetched, checked
// to be the provider's own request, and handed to the sign-on service as the request
// it is, parked as one arriving by POST is. From there it is the request any binding
// brings: its signature checked where one is required, validated, held across sign-in,
// and refused if seen before.
func (s *Server) resolveSAMLRequestArtifact(w http.ResponseWriter, r *http.Request, artifact, relayState string) {
	ctx := r.Context()
	raw, p, err := s.fetchSAMLArtifact(ctx, r, artifact)
	if err == nil {
		var kind string
		if kind, err = saml.MessageKind(raw); err == nil && kind != "AuthnRequest" {
			err = fmt.Errorf("the artifact names a %s, and the sign-on service takes an AuthnRequest", kind)
		}
	}
	var req saml.AuthnRequest
	if err == nil {
		err = saml.Unmarshal(raw, &req)
	}
	if err == nil && req.Issuer != p.EntityID {
		err = fmt.Errorf("the request fetched names %q as its issuer, and the artifact was %q's", req.Issuer, p.EntityID)
	}
	if err != nil {
		s.log.InfoContext(ctx, "SAML request by artifact refused", "err", err, "correlation_id", correlationID(ctx))
		s.samlRefuse(w, r, err.Error())
		return
	}
	q := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)}, "Binding": {"POST"}}
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	// "HTTP proxies and the user agent intermediary should not cache SAML artifacts"
	// (lines 1143-1147), nor what one was exchanged for.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, r.URL.Path+"?"+q.Encode(), http.StatusSeeOther)
}

// handleSAMLLogoutArtifact answers a logout message a provider sends by artifact. A
// LogoutRequest is the provider's own or refused, and is then acted on as one arriving
// by POST is, its own signature required: fetching it from the provider establishes
// where it came from, and a request to end somebody's session is still believed only
// when signed. A LogoutResponse moves this deployment's logout along, as one arriving
// by redirect does.
func (s *Server) handleSAMLLogoutArtifact(w http.ResponseWriter, r *http.Request, artifact, relayState string) {
	ctx := r.Context()
	raw, p, err := s.fetchSAMLArtifact(ctx, r, artifact)
	var kind string
	if err == nil {
		kind, err = saml.MessageKind(raw)
	}
	if err == nil && kind == "LogoutRequest" {
		var req saml.LogoutRequest
		if err = saml.Unmarshal(raw, &req); err == nil && req.Issuer != p.EntityID {
			err = fmt.Errorf("the logout fetched names %q as its issuer, and the artifact was %q's", req.Issuer, p.EntityID)
		}
	}
	if err == nil && kind != "LogoutRequest" && kind != "LogoutResponse" {
		err = fmt.Errorf("the artifact names a %s, and the logout service takes a LogoutRequest or a LogoutResponse", kind)
	}
	if err != nil {
		s.log.InfoContext(ctx, "SAML logout by artifact refused", "err", err, "correlation_id", correlationID(ctx))
		s.samlRefuse(w, r, err.Error())
		return
	}
	if kind == "LogoutResponse" {
		if s.continueSAMLLogoutChain(w, r, relayState, logoutDocumentFailed(raw)) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	body := form.Encode()
	inner := r.Clone(context.WithValue(ctx, fetchedByArtifactKey{}, true))
	inner.Method = http.MethodPost
	inner.URL.RawQuery = ""
	inner.Body = io.NopCloser(strings.NewReader(body))
	inner.ContentLength = int64(len(body))
	inner.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inner.Form, inner.PostForm = nil, nil
	s.handleSAMLSLO(w, inner)
}

// fetchedByArtifactKey marks a logout request fetched by artifact, whose answer goes
// back the same way where the provider takes it so.
type fetchedByArtifactKey struct{}

func fetchedByArtifact(ctx context.Context) bool {
	v, _ := ctx.Value(fetchedByArtifactKey{}).(bool)
	return v
}

// fetchSAMLArtifact fetches the message an artifact a service provider issued names,
// and answers it with the provider. The artifact names its issuer by the SHA-1 of its
// entity id and the service by index, which the receiver looks up (lines 1079-1086);
// the answer is believed for
// coming from that service's registered https address (saml-profiles-2.0-os lines
// 1482-1483), and must be the provider's, to this request, with a message in it.
func (s *Server) fetchSAMLArtifact(ctx context.Context, r *http.Request, artifact string) ([]byte, *saml.Provider, error) {
	index, sourceID, handle, err := saml.ParseArtifact(artifact)
	if err != nil {
		return nil, nil, err
	}
	orgID := ""
	if slug := r.PathValue("org"); slug != "" {
		if orgID, err = store.OrgBySlug(ctx, s.db, s.instanceID, slug); err != nil {
			return nil, nil, err
		}
	}
	senders, err := store.SAMLArtifactSenders(ctx, s.db, orgID)
	if err != nil {
		return nil, nil, err
	}
	entityID := ""
	for _, e := range senders {
		if bytes.Equal(saml.SourceID(e), sourceID) {
			entityID = e
			break
		}
	}
	if entityID == "" {
		return nil, nil, errors.New("the artifact names no service provider registered here with an artifact " +
			"resolution service, so there is nowhere to fetch what it refers to")
	}
	p, err := s.providerAt(r, entityID)
	if err != nil {
		return nil, nil, err
	}
	if !p.Enabled {
		return nil, nil, fmt.Errorf("the service provider %q is out of service", p.EntityID)
	}
	service, err := store.SAMLArtifactResolutionURL(ctx, s.db, p.ID, int(index))
	if errors.Is(err, store.ErrNoArtifactResolution) {
		return nil, nil, fmt.Errorf("the artifact names resolution service %d, and %q has none by that index",
			index, p.EntityID)
	}
	if err != nil {
		return nil, nil, err
	}

	// Single use on this side too, "RECOMMENDED ... to prevent an attacker from
	// interfering with the resolution of an artifact by a user agent and then
	// resubmitting it", and taken before the attempt, so one that fails is blocked
	// as well (lines 1163-1167).
	sum := sha256.Sum256(handle)
	if err := s.markSAMLArtifactSeen(ctx, "artifact:"+hex.EncodeToString(sum[:]), p); err != nil {
		return nil, nil, err
	}

	key, err := s.samlSigningKey(p.SignatureAlg)
	if err != nil {
		return nil, nil, err
	}
	certDER, err := s.samlCertificateFor(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	envelope, id, err := saml.BuildArtifactResolve(saml.ArtifactResolveInput{Issuer: s.samlEntityID(p),
		Destination: service, Artifact: artifact, Now: time.Now()}, key.Signer(), certDER)
	if err != nil {
		return nil, nil, err
	}
	body, err := postSOAP(ctx, service, envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("the service provider's artifact resolution service at %s: %w", service, err)
	}
	answer, err := saml.ReadArtifactResponse(body)
	switch {
	case err != nil:
		return nil, nil, fmt.Errorf("what %s answered: %w", service, err)
	case answer.InResponseTo != id:
		return nil, nil, fmt.Errorf("%s answered %q, not the request sent", service, answer.InResponseTo)
	case answer.Issuer != p.EntityID:
		return nil, nil, fmt.Errorf("%s answered as %q, not %q", service, answer.Issuer, p.EntityID)
	case answer.StatusCode != saml.StatusSuccess:
		return nil, nil, fmt.Errorf("%s answered with the status %q", service, answer.StatusCode)
	case answer.Message == nil:
		// Success with nothing in it is how a provider says the artifact is not one it
		// will give to this deployment, or no longer (lines 1180-1184).
		return nil, nil, fmt.Errorf("%s gave nothing for the artifact: it was not issued, was already resolved, "+
			"or is not for this identity provider", service)
	}
	return answer.Message, p, nil
}

// markSAMLArtifactSeen records an artifact as resolved, refusing one seen before.
func (s *Server) markSAMLArtifactSeen(ctx context.Context, key string, p *saml.Provider) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fresh, err := store.MarkSAMLRequestSeen(ctx, tx, key, p.OrgID, p.ID, samlRequestTTL)
	if err != nil {
		return err
	}
	if !fresh {
		return errors.New("the artifact has been brought here before; an artifact is resolved once")
	}
	return tx.Commit(ctx)
}

// postSOAP sends a SOAP 1.1 request to an address an operator registered, through the
// dialler every call to such an address goes through, and answers the body. A redirect
// is refused: it would turn the POST into somebody else's GET.
func postSOAP(ctx context.Context, target, envelope string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, artifactResolveTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(envelope))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", saml.SOAPAction)
	client := safedial.Client(artifactResolveTimeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactAnswer))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("it answered %d", resp.StatusCode)
	}
	return body, nil
}
