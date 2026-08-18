package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// OpenID Federation 1.0 (Final, 17 February 2026), the configuration endpoint.
//
// # What this serves and what it does not claim
//
// One thing: the Entity Configuration, the self-signed Entity Statement this
// entity publishes about itself (§9). It is the leaf of every Trust Chain and
// the prerequisite for everything else in the specification.
//
// The federation endpoints of §8 — fetch, subordinate listing, resolve, trust
// mark status — are not implemented, and the `federation_entity` metadata below
// therefore advertises none of them. That is the same rule this repository
// applies to OIDC discovery: an endpoint enters a metadata document only once it
// works. A `federation_fetch_endpoint` pointing at a 404 is worse than its
// absence, because a federation operator would configure us as an Intermediate
// and find out when a chain fails to resolve for somebody else.
//
// # Not registered unless configured
//
// A deployment that is not in a federation has no Entity Configuration to serve,
// and answering this path with an empty or improvised one would put a signed
// statement into the world claiming things nobody decided. The route exists only
// when `core.federation_config` has a row.

// handleEntityConfiguration serves the self-signed Entity Statement.
func (s *Server) handleEntityConfiguration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cfg, err := store.FederationConfig(ctx, s.db, s.instanceID)
	if err != nil {
		// No row means this instance is not federated. 404 rather than an empty
		// document: "we publish nothing here" is the honest answer, and a
		// well-formed but contentless Entity Configuration would be trusted.
		http.NotFound(w, r)
		return
	}

	// The FEDERATION keys, not the OIDC ones.
	//
	// §3.1.1: "These Federation Entity Keys SHOULD NOT be used in other
	// protocols." Serving s.cfg.Keys here would be the easy mistake -- they are
	// already loaded and already marshalled -- and it would tie two independent
	// trust decisions to one key.
	//
	// A separate key Set rather than a separate query, so federation keys get
	// the rotation states, the wrapping and the retirement sweep that the
	// protocol keys already have, instead of a second half-implementation.
	if s.fedKeys == nil {
		s.log.Error("federated instance with no federation key set loaded")
		http.Error(w, "no federation key", http.StatusInternalServerError)
		return
	}
	fedJWKS, err := s.fedKeys.MarshalJWKS()
	if err != nil {
		s.log.Error("marshalling the federation JWKS", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	conf, err := oidfed.Build(oidfed.Params{
		EntityID:         s.cfg.Issuer,
		FederationJWKS:   fedJWKS,
		AuthorityHints:   cfg.AuthorityHints,
		TrustAnchorHints: cfg.TrustAnchorHints,
		Lifetime:         time.Duration(cfg.LifetimeSeconds) * time.Second,
		Metadata:         s.federationMetadata(cfg),
	}, time.Now())
	if err != nil {
		s.log.Error("building the entity configuration", "err", err)
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}

	key, err := s.fedKeys.Active(keys.ES256)
	if err != nil {
		for _, alg := range s.fedKeys.Algorithms() {
			if k, e := s.fedKeys.Active(alg); e == nil {
				key, err = k, nil
				break
			}
		}
	}
	if err != nil {
		s.log.Error("no active federation signing key", "err", err)
		http.Error(w, "no federation key", http.StatusInternalServerError)
		return
	}

	// §3: "typed, by setting the typ header parameter to entity-statement+jwt to
	// prevent cross-JWT confusion". The signer also emits `kid`, which §3 makes
	// a MUST for Entity Statement JWTs.
	signed, err := tokens.NewSigner(key).SignJSON(conf, oidfed.Typ)
	if err != nil {
		s.log.Error("signing the entity configuration", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", oidfed.MediaType)
	// Cacheable for a fraction of the statement's own lifetime. A fetcher that
	// re-reads this on every trust-chain resolution puts us on the critical path
	// of every authentication in the federation.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(signed))
}

// federationMetadata declares the Entity Types this entity plays (§5.1).
//
// Two: `openid_provider`, because that is what we are, and `federation_entity`,
// which §9 requires to be published at the configuration endpoint when present.
//
// The `openid_provider` metadata deliberately reuses the values from OIDC
// discovery rather than restating them. Two documents describing the same server
// is two documents that eventually disagree, and the one a federation reads is
// the one nobody checks.
func (s *Server) federationMetadata(cfg *store.FederationSettings) map[string]any {
	fedEntity := map[string]any{}
	// Only what has been configured. §5.2.2's informational parameters are all
	// optional, and an empty string in a published statement is worse than an
	// absent claim: it renders as a blank organisation name in a federation's
	// directory.
	if cfg.OrganizationName != "" {
		fedEntity["organization_name"] = cfg.OrganizationName
	}
	if cfg.HomepageURI != "" {
		fedEntity["homepage_uri"] = cfg.HomepageURI
	}
	if len(cfg.Contacts) > 0 {
		fedEntity["contacts"] = cfg.Contacts
	}

	md := map[string]any{"federation_entity": fedEntity}

	// The OIDC half, from the same builder discovery uses -- oidc.Build, not a
	// second description of the same server. Two documents describing one server
	// eventually disagree, and the one a federation reads is the one nobody
	// checks.
	if doc, err := oidc.Build(s.cfg); err == nil {
		var op map[string]any
		if raw, merr := json.Marshal(doc); merr == nil {
			if json.Unmarshal(raw, &op) == nil {
				md["openid_provider"] = op
			}
		}
	}
	return md
}
