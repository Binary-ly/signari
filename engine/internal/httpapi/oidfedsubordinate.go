package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
)

// Speaking for other entities in a federation (12.11, §8.1 to §8.3): what makes this
// deployment a Trust Anchor or an Intermediate. A Subordinate Statement is this entity
// saying which keys an entity uses, and nothing is believed without one above it.

const (
	federationFetchPath   = "/federation/fetch"
	federationListPath    = "/federation/list"
	federationResolvePath = "/federation/resolve"
)

// federationSuperior reports whether this entity is one others look up to: a Trust Anchor
// has no superior, and an Intermediate has somebody below it. Both MUST publish a fetch
// endpoint and a Leaf Entity MUST NOT (§5.1.1, specs/oidfed.html:3451-3462).
func (s *Server) federationSuperior(ctx context.Context, cfg *store.FederationSettings) bool {
	if cfg.IsTrustAnchor() {
		return true
	}
	has, err := store.HasSubordinates(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "deciding whether to advertise the fetch endpoint", "err", err)
	}
	return has
}

// handleFederationFetch answers §8.1: a Subordinate Statement, made fresh each time, so that
// removing a subordinate or changing its keys is true from the next request.
func (s *Server) handleFederationFetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	if !s.federation.Allow() {
		writeFederationError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many federation requests")
		return
	}
	sub := r.URL.Query().Get("sub")
	switch {
	case sub == "":
		writeFederationError(w, http.StatusBadRequest, "invalid_request", "Required request parameter [sub] was missing.")
		return
	case sub == s.cfg.Issuer:
		// §8.1.2: "returning the invalid_request error code is RECOMMENDED".
		writeFederationError(w, http.StatusBadRequest, "invalid_request", "this entity makes no statement about itself here")
		return
	}
	cfg, err := store.FederationConfig(ctx, s.db, s.instanceID)
	if err != nil {
		writeFederationError(w, http.StatusNotFound, "not_found", "this instance is not federated")
		return
	}
	row, err := store.SubordinateOf(ctx, s.db, s.instanceID, sub)
	if err != nil {
		s.log.ErrorContext(ctx, "reading a subordinate", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if row == nil {
		writeFederationError(w, http.StatusNotFound, "not_found", "this entity does not speak for that subject")
		return
	}
	now := time.Now()
	claims := map[string]any{"iss": s.cfg.Issuer, "sub": sub, "iat": now.Unix(),
		"exp":             now.Add(time.Duration(cfg.LifetimeSeconds) * time.Second).Unix(),
		"jwks":            json.RawMessage(row.JWKS),
		"source_endpoint": strings.TrimRight(s.cfg.Issuer, "/") + federationFetchPath}
	if len(row.MetadataPolicy) > 0 {
		claims["metadata_policy"] = json.RawMessage(row.MetadataPolicy)
	}
	if row.MaxPathLength != nil {
		claims["constraints"] = oidfed.Constraints{MaxPathLength: row.MaxPathLength}
	}
	signed, err := store.SignAsFederationEntity(ctx, s.db, s.root, s.instanceID, claims, oidfed.Typ)
	if err != nil {
		s.log.ErrorContext(ctx, "signing a subordinate statement", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	w.Header().Set("Content-Type", oidfed.MediaType)
	_, _ = w.Write([]byte(signed))
}

// handleFederationList answers §8.2. The filters this entity cannot apply are refused as
// §8.2.1 says: a list that ignored one would look filtered and be wrong.
func (s *Server) handleFederationList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	if !s.federation.Allow() {
		writeFederationError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many federation requests")
		return
	}
	q := r.URL.Query()
	for _, name := range []string{"entity_type", "trust_marked", "trust_mark_type"} {
		if q.Has(name) {
			writeFederationError(w, http.StatusBadRequest, "unsupported_parameter",
				"this entity does not filter its subordinates by "+name)
			return
		}
	}
	rows, err := store.Subordinates(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing subordinates", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	onlyIntermediates := q.Get("intermediate") == "true"
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if !onlyIntermediates || row.Intermediate {
			out = append(out, row.EntityID)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFederationResolve answers §8.3 for chains ending at this entity. It holds no other
// anchor's keys, so any other trust_anchor could only be taken on the word of whoever
// answers at that address. A fetch of whatever a stranger names is bounded by the same
// guards as every outbound call and by the budget this endpoint shares.
func (s *Server) handleFederationResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	if !s.federation.Allow() {
		writeFederationError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many federation requests")
		return
	}
	q := r.URL.Query()
	sub := q.Get("sub")
	if sub == "" || len(q["trust_anchor"]) == 0 {
		writeFederationError(w, http.StatusBadRequest, "invalid_request", "sub and trust_anchor are both required")
		return
	}
	if !slices.Contains(q["trust_anchor"], s.cfg.Issuer) {
		writeFederationError(w, http.StatusNotFound, "invalid_trust_anchor", "this entity resolves chains ending at itself")
		return
	}
	cfg, err := store.FederationConfig(ctx, s.db, s.instanceID)
	if err != nil || s.fedKeys == nil {
		writeFederationError(w, http.StatusNotFound, "not_found", "this instance is not federated")
		return
	}
	jwks, err := s.fedKeys.MarshalJWKS()
	if err != nil {
		s.log.ErrorContext(ctx, "marshalling the federation JWKS", "err", err)
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	fetcher := &oidfed.Fetcher{HTTP: s.outboundClient(oidfed.FetchTimeout)}
	resolver := oidfed.Resolver{Fetcher: fetcher, Anchors: []oidfed.TrustAnchor{{EntityID: s.cfg.Issuer, JWKS: jwks}}}
	now := time.Now()
	result, chain, err := resolver.ResolveChain(ctx, sub, now)
	if err != nil {
		s.log.InfoContext(ctx, "a federation chain did not resolve", "sub", sub, "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusBadRequest, "invalid_trust_chain", "no valid chain from that subject to this entity")
		return
	}
	declared, err := oidfed.EntityTypesOf(chain[0])
	if err != nil {
		writeFederationError(w, http.StatusBadRequest, "invalid_metadata", "the subject's metadata did not parse")
		return
	}
	metadata := map[string]any{}
	for _, entityType := range declared {
		if asked := q["entity_type"]; len(asked) > 0 && !slices.Contains(asked, entityType) {
			continue
		}
		resolved, merr := oidfed.MetadataOf(chain, entityType)
		if merr != nil {
			s.log.InfoContext(ctx, "a federation policy did not apply", "sub", sub, "err", merr, "correlation_id", correlationID(ctx))
			writeFederationError(w, http.StatusBadRequest, "invalid_metadata", "the policies in the chain could not be applied")
			return
		}
		if resolved != nil {
			metadata[entityType] = resolved
		}
	}
	links := make([]string, 0, len(chain)+1)
	for _, st := range chain {
		links = append(links, st.Raw)
	}
	// §4: a chain "logically always ends with the Entity Configuration of the Trust Anchor,
	// even though it MAY be omitted", and §8.3.2 wants it from the subject to the anchor.
	if own, err := fetcher.EntityConfigurationOf(ctx, s.cfg.Issuer); err == nil {
		links = append(links, own.Raw)
	}
	// No longer than what it rests on (§10.4), or than this entity would say anything for.
	expiry := now.Add(time.Duration(cfg.LifetimeSeconds) * time.Second)
	if result.Expiry.Before(expiry) {
		expiry = result.Expiry
	}
	signed, err := store.SignAsFederationEntity(ctx, s.db, s.root, s.instanceID, map[string]any{"iss": s.cfg.Issuer,
		"sub": sub, "iat": now.Unix(), "exp": expiry.Unix(), "metadata": metadata, "trust_chain": links},
		oidfed.ResolveResponseTyp)
	if err != nil {
		s.log.ErrorContext(ctx, "signing a resolve response", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	w.Header().Set("Content-Type", oidfed.ResolveResponseMediaType)
	_, _ = w.Write([]byte(signed))
}
