package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
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
	trusted := make([]oidfed.TrustAnchor, 0, len(anchors))
	for _, anchor := range anchors {
		trusted = append(trusted, oidfed.TrustAnchor{EntityID: anchor.EntityID, JWKS: anchor.JWKS})
	}
	resolver := oidfed.Resolver{Fetcher: s.federationFetcher(), Anchors: trusted}
	reg, err := oidfed.Register(ctx, &resolver, clientID, now)
	if err != nil {
		return err
	}
	at := slices.IndexFunc(anchors, func(a store.FederationAnchor) bool { return a.EntityID == reg.TrustAnchor })
	if at < 0 {
		return fmt.Errorf("a chain ended at %s, which is not on the list", reg.TrustAnchor)
	}
	anchor := anchors[at]
	if err := resolver.RequireTrustMarks(ctx, reg, anchor.TrustMarks, now); err != nil {
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

	name := reg.Name
	if name == "" {
		name = clientID
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
	if err := store.RegisterFederatedClient(ctx, tx, store.FederatedClient{ClientID: clientID, OrgID: anchor.OrgID,
		Name: name, Anchor: anchor.EntityID, RedirectURIs: reg.RedirectURIs, Scopes: scopes, JWKS: reg.JWKS,
		Expiry: reg.Expiry}); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "federation.client_registered", OrgID: anchor.OrgID,
		ClientID: clientID, Detail: map[string]any{"trust_anchor": anchor.EntityID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
