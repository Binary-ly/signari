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
	"signari.dev/engine/internal/dpop"
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

	// §5.2 combined mode: one DPoP proof does the work of the Client Attestation
	// PoP, so "a request using the mechanism carries only one PoP, the DPoP
	// proof, instead of two separate PoP JWTs".
	//
	// The mode is chosen by what the client sent, not by configuration, because
	// it is a property of the request. §7.3 rules 1 and 2 make the two shapes
	// mutually exclusive -- no attestation-PoP header, precisely one DPoP header
	// -- so there is no request that is ambiguously both, and a client that sends
	// both headers is refused rather than silently having one ignored.
	// A request carrying BOTH a DPoP proof and a dedicated attestation PoP is not
	// combined mode and is not an error: draft -10 notes DPoP may be used
	// independently alongside the attestation. There the DPoP proof is the token's
	// sender-constraint and the dedicated header authenticates the client, so
	// there is nothing extra to check and no branch for it below.
	if len(r.Header.Values(abca.HeaderPoP)) == 0 {
		return s.authenticateWithCombinedDPoP(ctx, r, c, att)
	}

	pop, err := exactlyOneHeader(r, abca.HeaderPoP)
	if err != nil {
		return err
	}

	trusted, err := s.trustedAttesters(ctx, c.OrgID)
	if err != nil {
		return err
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

// authenticateWithCombinedDPoP implements §5.2 and §7.3.
//
// One DPoP proof serves as both the DPoP sender-constraint and the Client
// Attestation PoP. The attestation still names the key; the DPoP proof still has
// to be a valid DPoP proof; and rule 4 is what ties the two together.
func (s *Server) authenticateWithCombinedDPoP(ctx context.Context, r *http.Request,
	c *clients.Client, att string) error {

	// §7.3 rule 2: "There is precisely one `DPoP` HTTP request header field".
	// Rule 1 -- no attestation-PoP header -- is how this function was reached.
	proofs := r.Header.Values("DPoP")
	if len(proofs) == 0 {
		return fmt.Errorf("this client authenticates with an attestation, and the " +
			"request carries neither an " + abca.HeaderPoP + " header nor a DPoP " +
			"proof to serve as one")
	}
	if len(proofs) > 1 {
		return fmt.Errorf("there are %d DPoP header fields; combined mode requires "+
			"precisely one, because a request carrying two proofs has no single "+
			"answer to which key the attestation vouches for", len(proofs))
	}

	trusted, err := s.trustedAttesters(ctx, c.OrgID)
	if err != nil {
		return err
	}
	now := time.Now()
	attestation, err := abca.VerifyAttestation(att, trusted, now)
	if err != nil {
		return err
	}
	if attestation.ClientID != c.ClientID {
		return fmt.Errorf("the client attestation is for %q, but this request "+
			"authenticates as %q", attestation.ClientID, c.ClientID)
	}

	// §7.3 rule 3: validate the DPoP proof per RFC 9449. The SAME verifier the
	// ordinary DPoP path uses -- a second one here would be a second place for
	// the algorithm and replay rules to drift, and this one is the path where a
	// mistake also defeats client authentication.
	uri := s.cfg.Issuer + r.URL.Path
	proof, err := dpop.Verify(proofs[0], r.Method, uri, "", now)
	if err != nil {
		return fmt.Errorf("the DPoP proof serving as the attestation PoP is not "+
			"valid: %w", err)
	}

	// §7.3 rule 4, and the whole point of the mode: the proof must demonstrate
	// possession of the key the attester vouched for. Without this the client
	// proves possession of SOME key and the attestation vouches for ANOTHER, and
	// neither statement constrains the other.
	same, err := abca.SameKey(attestation.Key, proof.PublicKey)
	if err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("the DPoP proof is for a different key than the client " +
			"attestation vouches for, so it proves possession of a key nobody " +
			"attested to")
	}

	// §7.3 rule 5: the challenge, carried in the DPoP proof's `nonce`. We offer a
	// challenge endpoint, so §6.1 makes it required.
	if proof.Nonce == "" {
		return &abca.ChallengeError{Reason: "this server offers a challenge endpoint, " +
			"so the DPoP proof used for combined attestation must carry the " +
			"challenge in its `nonce` claim"}
	}
	ok, err := store.ClaimAttestationChallenge(ctx, s.db, proof.Nonce)
	if err != nil {
		return fmt.Errorf("attestation challenge verification is unavailable")
	}
	if !ok {
		return &abca.ChallengeError{Reason: "the challenge in the DPoP proof is " +
			"unknown, expired, or has already been used"}
	}

	// Replay, keyed the same way as the dedicated-PoP path so one proof cannot be
	// spent once in each mode.
	fresh, err := store.MarkDPoPProofSeen(ctx, s.db, "abca:"+c.ClientID, proof.JTI,
		abca.MaxPoPAge+abca.MaxSkew)
	if err != nil {
		return fmt.Errorf("replay detection is unavailable")
	}
	if !fresh {
		return fmt.Errorf("this DPoP proof has already been used")
	}
	return nil
}

// trustedAttesters loads an organisation's registered attester keys.
//
// Extracted so the dedicated-PoP and combined-DPoP paths share one
// implementation. Two copies would be two chances to differ about what a
// malformed registration means, and the failure direction matters: shrinking the
// trust set silently fails OPEN for whoever the attester was vouching against.
func (s *Server) trustedAttesters(ctx context.Context, orgID string) (*jose.JSONWebKeySet, error) {
	raw, err := store.TrustedAttesters(ctx, s.db, orgID)
	if err != nil {
		return nil, fmt.Errorf("reading trusted client attesters: %w", err)
	}
	trusted := &jose.JSONWebKeySet{}
	for _, blob := range raw {
		var set jose.JSONWebKeySet
		if uerr := json.Unmarshal(blob, &set); uerr != nil {
			return nil, fmt.Errorf("a registered client attester has an unreadable JWKS: %w", uerr)
		}
		trusted.Keys = append(trusted.Keys, set.Keys...)
	}
	return trusted, nil
}
