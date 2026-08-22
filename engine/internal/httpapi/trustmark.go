package httpapi

import (
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// OpenID Federation 1.0, the three Trust Mark Issuer endpoints.
//
//	POST /federation/trust_mark_status   §8.4  is this exact mark still active
//	GET  /federation/trust_mark_list     §8.5  who holds a mark of this type
//	GET  /federation/trust_mark          §8.6  give me this entity's mark
//
// # What the status endpoint is asked, exactly
//
// §8.4.1's only parameter is `trust_mark` -- the whole signed JWT. Not a
// (subject, type) pair. Earlier drafts of this specification asked with the pair
// and answered `{"active": true}`, and a fair amount of code and lore still says
// so; the Final version asks about a DOCUMENT and answers with a SIGNED JWT.
//
// Both changes matter, and in the same direction. Asking by coordinates cannot
// distinguish a mark from its own superseded predecessor, so the answer "active"
// would be true of a position and false of the thing in the caller's hand.
// Answering in plain JSON leaves the most security-relevant bit in a federation
// -- has this accreditation been withdrawn -- flippable by anything on the
// network path.
//
// # Not registered unless this entity issues Trust Marks
//
// Same rule as the Entity Configuration itself: the routes exist when the
// instance is federated, and the metadata advertises them only when this entity
// has actually issued a Trust Mark. See federationMetadata.

// handleTrustMarkStatus answers §8.4.
func (s *Server) handleTrustMarkStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	if !s.federation.Allow() {
		writeFederationError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"too many federation requests")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeFederationError(w, http.StatusBadRequest, "invalid_request",
			"the request body did not parse as application/x-www-form-urlencoded")
		return
	}
	raw := r.PostForm.Get("trust_mark")
	if raw == "" {
		writeFederationError(w, http.StatusBadRequest, "invalid_request",
			"Required request parameter [trust_mark] was missing.")
		return
	}

	m, err := store.TrustMarkByJWT(ctx, s.db, s.instanceID, raw)
	if errors.Is(err, store.ErrTrustMarkUnknown) {
		// §8.4.2: "If the Trust Mark Issuer receives a request about the status of
		// an unknown Trust Mark, something it did not issue or is not aware of, it
		// MUST respond with an HTTP status code 404 (Not found)."
		//
		// 404 rather than a signed `invalid`, and the difference is not cosmetic.
		// A signed status response is this entity's assertion ABOUT a document;
		// signing `invalid` over a forgery we have never seen would be minting a
		// statement about somebody else's bytes, and a caller could then present
		// that signed object as evidence we had considered it.
		writeFederationError(w, http.StatusNotFound, "not_found",
			"this entity has not issued that Trust Mark")
		return
	}
	if err != nil {
		s.log.Error("looking up a trust mark for a status request", "err", err)
		writeFederationError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	now := time.Now()
	resp := oidfed.StatusResponse{
		Issuer:    s.cfg.Issuer,
		IssuedAt:  now.Unix(),
		TrustMark: raw,
		Status:    m.StatusAt(now),
	}
	signed, err := s.signFederationJWT(resp, oidfed.StatusResponseTyp)
	if err != nil {
		s.log.Error("signing a trust mark status response", "err", err)
		writeFederationError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	w.Header().Set("Content-Type", oidfed.StatusResponseMediaType)
	_, _ = w.Write([]byte(signed))
}

// handleTrustMarkList answers §8.5.
func (s *Server) handleTrustMarkList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if !s.federation.Allow() {
		writeFederationError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"too many federation requests")
		return
	}
	markType := r.URL.Query().Get("trust_mark_type")
	if markType == "" {
		writeFederationError(w, http.StatusBadRequest, "invalid_request",
			"Required request parameter [trust_mark_type] was missing.")
		return
	}
	// `sub` is OPTIONAL and narrows the listing. §19.2 recommends the opposite
	// direction for privacy -- "use the Trust Marked Entities Listing with only
	// the trust_mark_type parameter and not the sub parameter" -- which is a
	// recommendation to the CALLER, so both forms are answered.
	sub := r.URL.Query().Get("sub")

	subjects, err := store.TrustMarkedEntities(ctx, s.db, s.instanceID, markType, sub)
	if err != nil {
		s.log.Error("listing trust marked entities", "err", err)
		writeFederationError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	// §8.5.2: 200 with a JSON array, even when empty.
	//
	// An empty array rather than a 404: the question is "who holds this mark",
	// and "nobody" is an answer. 404 would say the endpoint does not exist,
	// which is a different and false claim.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, subjects)
}

// handleTrustMark answers §8.6.
func (s *Server) handleTrustMark(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if !s.federation.Allow() {
		writeFederationError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"too many federation requests")
		return
	}
	q := r.URL.Query()
	markType, sub := q.Get("trust_mark_type"), q.Get("sub")
	if markType == "" {
		writeFederationError(w, http.StatusBadRequest, "invalid_request",
			"Required request parameter [trust_mark_type] was missing.")
		return
	}
	if sub == "" {
		// REQUIRED here, unlike the listing endpoint. §8.6 hands out a credential
		// about one entity; a request with no subject is not a broader query, it
		// is a request that has not said what it wants.
		writeFederationError(w, http.StatusBadRequest, "invalid_request",
			"Required request parameter [sub] was missing.")
		return
	}

	m, err := store.ActiveTrustMark(ctx, s.db, s.instanceID, markType, sub)
	if errors.Is(err, store.ErrTrustMarkUnknown) {
		// §8.6.2: "If the specified Entity does not have the specified Trust Mark,
		// the response is an error response and MUST use the HTTP status code
		// 404." One answer for "never issued", "revoked" and "expired": those are
		// distinguishable through the status endpoint by anybody actually holding
		// the mark, and distinguishing them HERE would let a stranger enumerate
		// which entities we have ever accredited and withdrawn.
		writeFederationError(w, http.StatusNotFound, "not_found",
			"this entity has no active Trust Mark of that type for that subject")
		return
	}
	if err != nil {
		s.log.Error("fetching a trust mark", "err", err)
		writeFederationError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	w.Header().Set("Content-Type", oidfed.TrustMarkMediaType)
	// Cacheable only as far as the mark's own expiry, and never for a
	// non-expiring one. A cached copy of a revoked mark is a revocation that has
	// not taken effect, and the whole point of §8.4 is to make withdrawal
	// observable.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(m.JWT))
}

// signFederationJWT signs with a Federation Entity Key.
//
// §7: "The key used by the Trust Mark issuer to sign its Trust Marks MUST be one
// of the private keys in its set of Federation Entity Keys." The same holds for
// the status response, which §8.4.2 says "is signed with a Federation Entity
// Key". So this deliberately reaches for s.fedKeys and never for s.cfg.Keys --
// the OIDC signing key is right there and would work, and using it would tie a
// federation's accreditation decisions to the key that asserts who users are.
func (s *Server) signFederationJWT(payload any, typ string) (string, error) {
	if s.fedKeys == nil {
		return "", errors.New("this instance has no federation key set")
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
		return "", err
	}
	return tokens.NewSigner(key).SignJSON(payload, typ)
}

// writeFederationError renders §8.9's error shape.
//
// RFC 6749's `error` and `error_description`, with the status codes §8.9
// assigns. Both members are REQUIRED there, so error_description is never
// omitted -- an error object with only a code tells a federation operator that
// something is wrong and nothing about what.
func writeFederationError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]any{
		"error": code, "error_description": description,
	})
}

// The three endpoint paths, in one place because they are written twice: once
// in the mux and once in the `federation_entity` metadata that tells a
// federation where to find them. A federation that reads the metadata and gets
// a 404 concludes this entity is broken, and the two spellings drifting apart
// is the ordinary way that happens.
const (
	trustMarkStatusPath = "/federation/trust_mark_status"
	trustMarkListPath   = "/federation/trust_mark_list"
	trustMarkPath       = "/federation/trust_mark"
)
