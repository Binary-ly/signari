package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Automatic Registration, OpenID Federation §12.1: a relying party this server has never
// heard of, whose Entity Identifier is its client_id and whose signed request says the
// rest. What has to hold before it is a client: an anchor on the operator's list vouches
// for it through a chain, it holds any Trust Marks that anchor asks for, and the request
// is signed by the keys that chain published. After that it is an ordinary client, and
// everything downstream treats it as one.
//
// Until then nothing is written. Failing leaves the client unknown, which the
// authorization endpoint shows and does not redirect, as §12.1.3 requires: "it MUST treat
// the redirection URI as invalid".

// federationRegistrationsPerAddress bounds the chains one address can have this server
// walk, each a run of outbound requests to places a stranger named.
const federationRegistrationsPerAddress = 30

const (
	// federationRegisterPath is §12.2's federation_registration_endpoint.
	federationRegisterPath = "/federation/register"
	// registrationResponseType is §12.2.3's media type, and less its prefix the `typ`.
	registrationResponseType = "application/explicit-registration-response+jwt"
	// maxRegistrationBody is more than an Entity Configuration or a chain comes to.
	maxRegistrationBody = 256 << 10
)

// federationFetcher is how chains are fetched, a field so that a test can reach a
// federation on loopback, which the real one refuses.
func (s *Server) federationFetcher() *oidfed.Fetcher {
	if s.fetchFederation != nil {
		return s.fetchFederation()
	}
	return &oidfed.Fetcher{HTTP: s.outboundClient(oidfed.FetchTimeout)}
}

// admitFederatedClient registers the relying party a signed request is from, if it is
// one that has to be and can be. It answers nothing: the caller looks the client up
// next, and either it is there or it is the unknown client it was.
func (s *Server) admitFederatedClient(r *http.Request, clientID, object string) {
	ctx := r.Context()
	if !strings.HasPrefix(clientID, "https://") {
		return
	}
	c, err := clients.Lookup(ctx, s.db, clientID)
	switch {
	case err == nil && (c.FederationExpiry == nil || time.Now().Before(*c.FederationExpiry)):
		return
	case err != nil && !errors.Is(err, clients.ErrNotFound):
		s.log.ErrorContext(ctx, "looking for a federated client", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	anchors, err := store.FederationAnchors(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the trust anchors", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	if len(anchors) == 0 {
		return
	}
	rate, err := store.AllowRate(ctx, s.db, "federation-register:"+clientIP(r), federationRegistrationsPerAddress, time.Minute)
	if err != nil || !rate.Allowed {
		s.log.InfoContext(ctx, "a federated registration was paced", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	if err := s.registerFederatedClient(ctx, clientID, object, anchors); err != nil {
		s.log.InfoContext(ctx, "a relying party was not admitted", "client_id", clientID, "err", err,
			"correlation_id", correlationID(ctx))
	}
}

func (s *Server) registerFederatedClient(ctx context.Context, clientID, object string, anchors []store.FederationAnchor) error {
	now := time.Now()
	resolver := oidfed.Resolver{Fetcher: s.federationFetcher(), Anchors: federationTrustAnchors(anchors)}
	reg, err := oidfed.Register(ctx, &resolver, clientID, now)
	if err != nil {
		return err
	}

	// §12.1.1.1.2: "it MUST verify that the client was actually the one sending the
	// Authentication Request by verifying the signature of the Request Object using the
	// key material the client published". A chain says who an entity is, and anybody can
	// read that and put its name in a client_id.
	if _, err := clientauth.VerifyRequestObject(object, clientID, string(reg.JWKS), []string{s.cfg.Issuer}, now,
		clientauth.RequestObjectRules{Federated: true}); err != nil {
		return err
	}
	return s.admitRegistered(ctx, &resolver, reg, anchors, now, true)
}

func federationTrustAnchors(anchors []store.FederationAnchor) []oidfed.TrustAnchor {
	trusted := make([]oidfed.TrustAnchor, 0, len(anchors))
	for _, anchor := range anchors {
		trusted = append(trusted, oidfed.TrustAnchor{EntityID: anchor.EntityID, JWKS: anchor.JWKS})
	}
	return trusted
}

// admitRegistered is what both kinds of registration come to: a chain that ended at a
// listed anchor, the Trust Marks that anchor asks for, and a client in its organisation.
func (s *Server) admitRegistered(ctx context.Context, resolver *oidfed.Resolver, reg *oidfed.RegisteredClient,
	anchors []store.FederationAnchor, now time.Time, requestsSigned bool) error {
	at := slices.IndexFunc(anchors, func(a store.FederationAnchor) bool { return a.EntityID == reg.TrustAnchor })
	if at < 0 {
		return fmt.Errorf("a chain ended at %s, which is not on the list", reg.TrustAnchor)
	}
	anchor := anchors[at]
	if err := resolver.RequireTrustMarks(ctx, reg, anchor.TrustMarks, now); err != nil {
		return err
	}
	name := reg.Name
	if name == "" {
		name = reg.ClientID
	}
	scopes := reg.Scopes
	if !slices.Contains(scopes, "openid") {
		scopes = append(scopes, "openid")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.RegisterFederatedClient(ctx, tx, store.FederatedClient{ClientID: reg.ClientID, OrgID: anchor.OrgID,
		Name: name, Anchor: anchor.EntityID, RedirectURIs: reg.RedirectURIs, Scopes: scopes, JWKS: reg.JWKS,
		Expiry: reg.Expiry, RequestsSigned: requestsSigned}); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "federation.client_registered", OrgID: anchor.OrgID,
		ClientID: reg.ClientID, Detail: map[string]any{"trust_anchor": anchor.EntityID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// federationKey is what this instance signs a statement with.
func (s *Server) federationKey() (keys.Key, error) {
	key, err := s.fedKeys.Active(keys.ES256)
	if err == nil {
		return key, nil
	}
	for _, alg := range s.fedKeys.Algorithms() {
		if k, e := s.fedKeys.Active(alg); e == nil {
			return k, nil
		}
	}
	return nil, err
}

// handleFederationRegister is Explicit Registration, OpenID Federation §12.2: an RP
// sends its Entity Configuration, or a whole Trust Chain that starts with one, and has a
// client made of it by the rules Automatic Registration has. It keeps its Entity
// Identifier as its client_id, and no secret, so that §12.1's client and this one are the
// same client. Not offered at all with nothing on the anchor list.
func (s *Server) handleFederationRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	anchors, err := store.FederationAnchors(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the trust anchors", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if len(anchors) == 0 {
		writeFederationError(w, http.StatusNotFound, "not_found", "this entity registers nobody")
		return
	}
	rate, err := store.AllowRate(ctx, s.db, "federation-register:"+clientIP(r), federationRegistrationsPerAddress, time.Minute)
	if err != nil || !rate.Allowed {
		w.Header().Set("Retry-After", "60")
		writeFederationError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations from here")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRegistrationBody))
	if err != nil {
		writeFederationError(w, http.StatusBadRequest, "invalid_request", "the request is too large or did not arrive")
		return
	}
	raw, ok := registrationStatement(r.Header.Get("Content-Type"), body)
	if !ok {
		writeFederationError(w, http.StatusBadRequest, "invalid_request",
			"send an Entity Configuration as application/entity-statement+jwt or a Trust Chain as application/trust-chain+json")
		return
	}

	now := time.Now()
	resolver := oidfed.Resolver{Fetcher: s.federationFetcher(), Anchors: federationTrustAnchors(anchors)}
	reg, err := oidfed.RegisterExplicitly(ctx, &resolver, raw, s.cfg.Issuer, now)
	if err != nil {
		s.log.InfoContext(ctx, "an explicit registration was refused", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusBadRequest, "invalid_trust_chain", "no acceptable trust chain for that entity")
		return
	}
	if err := s.admitRegistered(ctx, &resolver, reg, anchors, now, false); err != nil {
		s.log.InfoContext(ctx, "an explicit registration was refused", "client_id", reg.ClientID, "err", err,
			"correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusBadRequest, "invalid_client_metadata", "that entity cannot be registered here")
		return
	}

	key, err := s.federationKey()
	if err != nil {
		s.log.ErrorContext(ctx, "no active federation signing key", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// §12.2.3: the registration, as an Entity Statement about the RP.
	signed, err := tokens.NewSigner(key).SignJSON(map[string]any{
		"iss": s.cfg.Issuer, "sub": reg.ClientID, "aud": reg.ClientID, "iat": now.Unix(), "exp": reg.Expiry.Unix(),
		"jwks": reg.EntityJWKS(), "trust_anchor": reg.TrustAnchor, "authority_hints": []string{reg.ImmediateSuperior()},
		"metadata": map[string]any{"openid_relying_party": map[string]any{
			"client_id": reg.ClientID, "redirect_uris": reg.RedirectURIs, "token_endpoint_auth_method": "private_key_jwt",
			"response_types": []string{"code"}, "client_registration_types": []string{"explicit"},
		}},
	}, strings.TrimPrefix(registrationResponseType, "application/"))
	if err != nil {
		s.log.ErrorContext(ctx, "signing a registration", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	w.Header().Set("Content-Type", registrationResponseType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(signed)); err != nil {
		s.log.InfoContext(ctx, "writing a registration", "err", err, "correlation_id", correlationID(ctx))
	}
}

// registrationStatement is the RP's Entity Configuration out of a request body. §12.2.2:
// "extract the RP's Entity Configuration from the Trust Chain and proceed ... as if only
// an Entity Configuration was received". The rest of a chain is an optimisation.
func registrationStatement(contentType string, body []byte) (string, bool) {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	switch media {
	case "application/entity-statement+jwt":
		return strings.TrimSpace(string(body)), true
	case "application/trust-chain+json":
		var chain []string
		if err := json.Unmarshal(body, &chain); err != nil || len(chain) == 0 {
			return "", false
		}
		return chain[0], true
	}
	return "", false
}

// requestObjectRules says what a client's Request Objects are held to.
func (s *Server) requestObjectRules(ctx context.Context, c *clients.Client) clientauth.RequestObjectRules {
	var rules clientauth.RequestObjectRules
	if c.MessageSigning() {
		rules.Dated, rules.Algorithms = true, clients.FAPI2Algorithms
	}
	if c.FederationExpiry != nil {
		rules.Federated = true
		rules.Claim = func(jti string, expires time.Time) error {
			return store.ClaimRequestObjectJTI(ctx, s.db, c.ClientID, jti, expires)
		}
	}
	return rules
}
