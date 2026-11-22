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
// §8.2.1 says: a list that ignored one would look filtered and be wrong. entity_type is
// one: an operator gives a subordinate's keys and policy, not its types, so this entity
// does not know them, and learning them would take a fetch of every subordinate's
// configuration for every list. trust_marked and trust_mark_type are answered from the
// Trust Marks this entity issued, which it knows (specs/oidfed.txt:3675-3703).
func (s *Server) handleFederationList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	if !s.federation.Allow() {
		writeFederationError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many federation requests")
		return
	}
	q := r.URL.Query()
	if q.Has("entity_type") {
		writeFederationError(w, http.StatusBadRequest, "unsupported_parameter",
			"this entity does not know its subordinates' entity types, so cannot filter by entity_type")
		return
	}
	rows, err := store.Subordinates(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing subordinates", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// Each filter asked for is a set of subordinates to keep; together, all of them.
	var marked []map[string]bool
	markedBy := func(markType string) bool {
		set, err := store.TrustMarkedSubjects(ctx, s.db, s.instanceID, markType)
		if err != nil {
			s.log.ErrorContext(ctx, "reading issued trust marks", "err", err, "correlation_id", correlationID(ctx))
			writeFederationError(w, http.StatusInternalServerError, "server_error", "")
			return false
		}
		marked = append(marked, set)
		return true
	}
	if q.Get("trust_marked") == "true" && !markedBy("") {
		return
	}
	if markType := q.Get("trust_mark_type"); markType != "" && !markedBy(markType) {
		return
	}
	onlyIntermediates := q.Get("intermediate") == "true"
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		keep := !onlyIntermediates || row.Intermediate
		for _, set := range marked {
			keep = keep && set[row.EntityID]
		}
		if keep {
			out = append(out, row.EntityID)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// resolveAnchor is the first trust_anchor asked for that this entity holds keys for:
// itself, or an anchor on the operator's list. Answers for itself when there is none.
func (s *Server) resolveAnchor(ctx context.Context, w http.ResponseWriter, asked []string) (oidfed.TrustAnchor, bool) {
	listed, err := store.FederationAnchors(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the trust anchors", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return oidfed.TrustAnchor{}, false
	}
	for _, id := range asked {
		if id == s.cfg.Issuer {
			jwks, err := s.fedKeys.MarshalJWKS()
			if err != nil {
				s.log.ErrorContext(ctx, "marshalling the federation JWKS", "err", err)
				writeFederationError(w, http.StatusInternalServerError, "server_error", "")
				return oidfed.TrustAnchor{}, false
			}
			return oidfed.TrustAnchor{EntityID: id, JWKS: jwks}, true
		}
		if at := slices.IndexFunc(listed, func(a store.FederationAnchor) bool { return a.EntityID == id }); at >= 0 {
			return oidfed.TrustAnchor{EntityID: id, JWKS: listed[at].JWKS}, true
		}
	}
	writeFederationError(w, http.StatusNotFound, "invalid_trust_anchor",
		"this entity resolves chains ending at itself or at a trust anchor its operator listed")
	return oidfed.TrustAnchor{}, false
}

// handleFederationResolve answers §8.3 for chains ending at this entity or at a Trust
// Anchor an operator listed (`federation add-anchor`), whose keys were given with it. Any
// other trust_anchor could only be taken on the word of whoever answers at that address,
// so it is refused. Of several, §8.3.1 lets any be used, and the first this entity can
// stand behind is. A fetch of whatever a stranger names is bounded by the same guards as
// every outbound call and by the budget this endpoint shares.
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
	cfg, err := store.FederationConfig(ctx, s.db, s.instanceID)
	if err != nil || s.fedKeys == nil {
		writeFederationError(w, http.StatusNotFound, "not_found", "this instance is not federated")
		return
	}
	anchor, ok := s.resolveAnchor(ctx, w, q["trust_anchor"])
	if !ok {
		return
	}
	fetcher := &oidfed.Fetcher{HTTP: s.outboundClient(oidfed.FetchTimeout)}
	resolver := oidfed.Resolver{Fetcher: fetcher, Anchors: []oidfed.TrustAnchor{anchor}}
	now := time.Now()
	result, chain, err := resolver.ResolveChain(ctx, sub, now)
	if err != nil {
		s.log.InfoContext(ctx, "a federation chain did not resolve", "sub", sub, "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusBadRequest, "invalid_trust_chain", "no valid chain from that subject to that trust anchor")
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
	// No longer than what it rests on (§10.4), or than this entity would say anything for.
	expiry := now.Add(time.Duration(cfg.LifetimeSeconds) * time.Second)
	if result.Expiry.Before(expiry) {
		expiry = result.Expiry
	}
	claims := map[string]any{"iss": s.cfg.Issuer, "sub": sub, "iat": now.Unix(), "metadata": metadata}
	// §4: a chain "logically always ends with the Entity Configuration of the Trust Anchor,
	// even though it MAY be omitted", and §8.3.2 wants it from the subject to the anchor.
	// Verified with the anchor's keys, and what the subject's Trust Marks are held to:
	// only those the anchor trusts their issuers for appear (specs/oidfed.txt:3918-3924),
	// and the response lasts no longer than the first to expire (:3900-3902).
	if anchorStatement, aerr := resolver.AnchorConfiguration(ctx, anchor.EntityID); aerr == nil {
		links = append(links, anchorStatement.Raw)
		if marks, earliest := resolver.VerifiedTrustMarks(ctx, chain[0], anchorStatement, now); len(marks) > 0 {
			claims["trust_marks"] = marks
			if !earliest.IsZero() && earliest.Before(expiry) {
				expiry = earliest
			}
		}
	} else {
		s.log.InfoContext(ctx, "the trust anchor's configuration did not verify; resolved without it or any trust mark",
			"trust_anchor", anchor.EntityID, "err", aerr, "correlation_id", correlationID(ctx))
	}
	claims["exp"], claims["trust_chain"] = expiry.Unix(), links
	signed, err := store.SignAsFederationEntity(ctx, s.db, s.root, s.instanceID, claims, oidfed.ResolveResponseTyp)
	if err != nil {
		s.log.ErrorContext(ctx, "signing a resolve response", "err", err, "correlation_id", correlationID(ctx))
		writeFederationError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	w.Header().Set("Content-Type", oidfed.ResolveResponseMediaType)
	_, _ = w.Write([]byte(signed))
}
