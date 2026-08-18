package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/abca"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// Attestation-Based Client Authentication,
// draft-ietf-oauth-attestation-based-client-auth-10 (6 July 2026).
//
//	POST /oauth2/attestation-challenge  ->  {"attestation_challenge": "..."}
//
// plus the `attest_jwt_client_auth` client authentication method at every
// endpoint that authenticates a client.

// handleAttestationChallenge implements §6.1.
//
// Unauthenticated, and it has to be: a client fetches a challenge in order to
// authenticate, so requiring authentication first is a cycle. What it hands out
// is 32 random bytes with a two-minute life and single use, which is worth
// nothing to anyone who has not also got an attestation and the instance key.
func (s *Server) handleAttestationChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orgID, err := s.defaultOrgID(ctx)
	if err != nil {
		s.log.Error("attestation challenge: resolving the organisation", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	challenge, err := store.NewAttestationChallenge(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("minting an attestation challenge", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	// §6.1: "MUST make the response uncacheable by adding a Cache-Control header
	// field including the value no-store." A cached challenge is a reused
	// challenge, which is the one thing it must never be.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"attestation_challenge": challenge,
	})
}

// authenticateWithAttestation implements §7.1, §7.2 and §7.5.
//
// Returns nil when the client is authenticated. The two artefacts arrive in
// separate headers and are checked in order, because the second cannot be
// checked without the first: the attestation names the key that must have signed
// the PoP.
func (s *Server) authenticateWithAttestation(ctx context.Context, r *http.Request,
	c *clients.Client) error {

	// §7.1 rule 1 and §7.2 rule 1: "There is precisely one" of each header.
	//
	// Precisely one, not at least one. Two attestations would let a caller pair a
	// trusted attestation with a PoP for a different key and leave which one is
	// checked up to header ordering -- the same parameter-pollution shape the PAR
	// endpoint refuses duplicate form fields for.
	att, err := exactlyOneHeader(r, abca.HeaderAttestation)
	if err != nil {
		return err
	}
	pop, err := exactlyOneHeader(r, abca.HeaderPoP)
	if err != nil {
		return err
	}

	raw, err := store.TrustedAttesters(ctx, s.db, c.OrgID)
	if err != nil {
		return fmt.Errorf("reading trusted client attesters: %w", err)
	}
	trusted := &jose.JSONWebKeySet{}
	for _, blob := range raw {
		var set jose.JSONWebKeySet
		if uerr := json.Unmarshal(blob, &set); uerr != nil {
			// One malformed registration must not silently shrink the trust set:
			// that would turn a typo into "this attester is no longer trusted",
			// which fails open for whoever the attester was vouching against.
			return fmt.Errorf("a registered client attester has an unreadable JWKS: %w", uerr)
		}
		trusted.Keys = append(trusted.Keys, set.Keys...)
	}

	now := time.Now()
	attestation, err := abca.VerifyAttestation(att, trusted, now)
	if err != nil {
		return err
	}

	// §7.1 rule 7 and §7.5: "the Authorization Server MUST verify that the value
	// of this parameter is the same as the client_id value in the sub claim".
	//
	// Without it, an attestation for one client authenticates a request made in
	// another client's name -- and attestations are reusable by design, so any
	// party holding one valid attestation could act as every client.
	if attestation.ClientID != c.ClientID {
		return fmt.Errorf("the client attestation is for %q, but this request "+
			"authenticates as %q", attestation.ClientID, c.ClientID)
	}

	// §6.1: "If the Authorization Server offers a challenge endpoint, the Client
	// MUST retrieve a challenge and MUST use this challenge". We offer one, so
	// the challenge is required, and §7.2 rules 5 and 8 make it binding.
	//
	// Read from the PoP first and validated against the store, rather than the
	// server picking a value it expects: there is no session here to remember one
	// in, and any live unused challenge is a value this server genuinely issued.
	claimed, err := abca.VerifyPoP(pop, attestation.Key, s.cfg.Issuer, "", now)
	if err != nil {
		return err
	}
	if claimed.Challenge == "" {
		return &abca.ChallengeError{Reason: "this server offers a challenge endpoint, " +
			"so §6.1 requires the client attestation PoP to carry a challenge"}
	}
	ok, err := store.ClaimAttestationChallenge(ctx, s.db, claimed.Challenge)
	if err != nil {
		// Fail closed. Without the store the challenge cannot be shown to be one
		// we issued, and accepting it would drop the protection precisely when
		// the database is unhappy.
		return fmt.Errorf("attestation challenge verification is unavailable")
	}
	if !ok {
		return &abca.ChallengeError{Reason: "the challenge in the client attestation " +
			"PoP is unknown, expired, or has already been used"}
	}

	// §7.2 rule 9, replay detection. The challenge is already single-use, so this
	// is belt and braces -- but a `jti` check costs one statement and covers the
	// case where a deployment later turns challenges off.
	fresh, err := store.MarkDPoPProofSeen(ctx, s.db, "abca:"+c.ClientID, claimed.JTI,
		abca.MaxPoPAge+abca.MaxSkew)
	if err != nil {
		return fmt.Errorf("replay detection is unavailable")
	}
	if !fresh {
		return fmt.Errorf("this client attestation PoP has already been used")
	}
	return nil
}

// exactlyOneHeader enforces the "precisely one" rules of §7.1 and §7.2.
func exactlyOneHeader(r *http.Request, name string) (string, error) {
	values := r.Header.Values(name)
	switch len(values) {
	case 1:
		if values[0] == "" {
			return "", fmt.Errorf("the %s header is empty", name)
		}
		return values[0], nil
	case 0:
		return "", fmt.Errorf("this client authenticates with %s, and the %s header "+
			"is missing", abca.MethodPoP, name)
	default:
		return "", fmt.Errorf("there are %d %s header fields; exactly one is required",
			len(values), name)
	}
}

// isAttestationFailure reports whether a client authentication error came from
// the attestation path, and so deserves §7.4's error codes rather than the
// generic `invalid_client`.
//
// Keyed on the client's registered method rather than on the error's shape: an
// attestation client cannot fail authentication any other way, and matching on
// error text would break the first time a message is reworded.
func isAttestationFailure(c *clients.Client, err error) bool {
	if err == nil || c == nil {
		return false
	}
	var ce *abca.ChallengeError
	return c.TokenEndpointAuthMethod == abca.MethodPoP || errors.As(err, &ce)
}

// writeAttestationError renders §7.4's error codes.
//
// A ChallengeError MUST carry a fresh challenge: §7.4 says
// `use_attestation_challenge` "MUST be accompanied by the
// OAuth-Client-Attestation-Challenge HTTP header field parameter". Telling a
// client to retry with a challenge without giving it one is a loop the client
// cannot break.
func (s *Server) writeAttestationError(w http.ResponseWriter, r *http.Request,
	c *clients.Client, err error) {

	var ce *abca.ChallengeError
	if errors.As(err, &ce) {
		if c != nil {
			if fresh, ferr := store.NewAttestationChallenge(r.Context(), s.db, c.OrgID); ferr == nil {
				w.Header().Set(abca.HeaderChallenge, fresh)
			} else {
				s.log.Error("minting a replacement attestation challenge", "err", ferr)
			}
		}
		writeTokenError(w, &oauth.TokenError{Code: abca.ErrUseChallenge,
			Description: ce.Reason, Status: http.StatusUnauthorized})
		return
	}
	writeTokenError(w, &oauth.TokenError{Code: abca.ErrInvalidClient,
		Description: err.Error(), Status: http.StatusUnauthorized})
}

// defaultOrgID resolves the organisation a challenge belongs to.
func (s *Server) defaultOrgID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRow(ctx,
		`SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&id)
	return id, err
}
