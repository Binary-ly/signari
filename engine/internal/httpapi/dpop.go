package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/abca"
	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/dpop"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// DPoP wiring: bind at the token endpoint, enforce at every resource.
//
// The two halves are useless apart. Binding without enforcement produces tokens
// that CLAIM to be sender-constrained and are not -- which is worse than plain
// bearer tokens, because a relying party reading `cnf` will believe them.

type dpopCtxKey struct{}

// withDPoPThumbprint carries a verified thumbprint down to token minting.
func withDPoPThumbprint(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, dpopCtxKey{}, jkt)
}

func dpopThumbprintFrom(ctx context.Context) string {
	s, _ := ctx.Value(dpopCtxKey{}).(string)
	return s
}

func confirmationFor(jkt string) *tokens.Confirmation {
	if jkt == "" {
		return nil
	}
	return &tokens.Confirmation{JKT: jkt}
}

// confirmationForCert is the mutual-TLS equivalent, RFC 8705 §3.1.
//
// Same claim, different member: `cnf.x5t#S256` instead of `cnf.jkt`. A token can
// carry only one -- a client authenticating with both DPoP and mTLS would be
// asserting two different possession proofs for one token, and deciding which
// one a resource server must check is not a question to leave open.
func confirmationForCert(thumbprint string) *tokens.Confirmation {
	if thumbprint == "" {
		return nil
	}
	return &tokens.Confirmation{X5TS256: thumbprint}
}

// bearerOrDPoP names the token type.
//
// RFC 9449 §5: a sender-constrained token is issued as token_type "DPoP", not
// "Bearer". The distinction is not cosmetic -- a client told "Bearer" will send
// `Authorization: Bearer ...` and no proof, and the request will be refused.
func bearerOrDPoP(jkt string) string {
	if jkt == "" {
		return "Bearer"
	}
	return "DPoP"
}

// proofForBoundToken is a protected resource's whole check of a DPoP-bound
// access token: a proof is present, valid for this request and this token,
// fresh, and made with the very key the token names in cnf.jkt.
//
// One function for every resource, because the last step is the one a
// resource leaves out. The credential endpoint checked that a valid proof
// came with the token and never that the proof's key was the token's, so a
// stolen bound token minted credentials with the thief's own proof.
func (s *Server) proofForBoundToken(r *http.Request, accessToken, tokenJKT string) error {
	jkt, err := s.verifyDPoPForRequest(r, accessToken)
	if err != nil {
		return err
	}
	if jkt == "" {
		return fmt.Errorf("a DPoP proof is required for this token")
	}
	return dpop.BoundTo(&dpop.Confirmation{JKT: tokenJKT}, &dpop.Proof{JKT: jkt})
}

// certificateForBoundToken is a protected resource's check of a
// certificate-bound access token, RFC 8705 §3 (specs/rfc8705.txt:433-438):
//
//	"The protected resource MUST obtain, from its TLS implementation layer,
//	the client certificate used for mutual TLS and MUST verify that the
//	certificate matches the certificate associated with the access token."
//
// The token endpoint bound tokens to the connection's certificate and no
// resource ever read `cnf.x5t#S256`, so a certificate-bound token worked for
// whoever held it, with or without the certificate.
func certificateForBoundToken(r *http.Request, tokenThumbprint string) error {
	presented := clientauth.ThumbprintFromState(r.TLS)
	if presented == "" {
		return errors.New("the access token is bound to a client certificate; present " +
			"it over mutual TLS")
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(tokenThumbprint)) != 1 {
		return errors.New("the certificate on this connection is not the one the access " +
			"token is bound to")
	}
	return nil
}

// boundTokenRefused is every protected resource's possession check: the DPoP
// proof for a token carrying `cnf.jkt`, the connection's certificate for one
// carrying `cnf.x5t#S256`, and nothing for a bearer token. It writes the
// RFC 6750 / RFC 9449 refusal and reports true when possession is not shown.
//
// The scheme rule (dpop.CheckPresentation) is the caller's, before this:
// it decides how the token was presented, which comes first.
func (s *Server) boundTokenRefused(w http.ResponseWriter, r *http.Request, raw string,
	cnf *tokens.Confirmation, where string) bool {

	switch {
	case cnf == nil:
		return false
	case cnf.JKT != "":
		if derr := s.proofForBoundToken(r, raw, cnf.JKT); derr != nil {
			s.log.Info("DPoP enforcement refused a request", "at", where, "reason", derr,
				"correlation_id", correlationID(r.Context()))
			if errors.Is(derr, errDPoPNonce) {
				// §9: as at the token endpoint, with the status a resource uses.
				s.offerDPoPNonce(w)
				w.Header().Set("WWW-Authenticate", dpopChallenge("use_dpop_nonce",
					"this resource requires a nonce in the DPoP proof"))
				w.WriteHeader(http.StatusUnauthorized)
				return true
			}
			w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token",
				"the access token is sender-constrained and the DPoP proof did not match"))
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
	case cnf.X5TS256 != "":
		if cerr := certificateForBoundToken(r, cnf.X5TS256); cerr != nil {
			s.log.Info("certificate binding refused a request", "at", where, "reason", cerr,
				"correlation_id", correlationID(r.Context()))
			// §3: "rejected with an error, per [RFC6750], using an HTTP 401
			// status code and the "invalid_token" error code."
			w.Header().Set("WWW-Authenticate", `Bearer realm="signari", error="invalid_token", `+
				`error_description="the access token is bound to a client certificate this `+
				`connection did not present"`)
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
	}
	return false
}

// verifyDPoPForRequest checks a proof and its replay record.
//
// Returns the thumbprint on success. An absent header is not an error here: the
// caller decides whether a proof was required, because that depends on whether
// the token being presented is bound.
func (s *Server) verifyDPoPForRequest(r *http.Request, accessToken string) (string, error) {
	proofs := r.Header.Values("DPoP")
	if len(proofs) > 1 {
		return "", fmt.Errorf("there are %d DPoP header fields; RFC 9449 section 4.3 "+
			"permits exactly one, because a request carrying two proofs has no "+
			"single answer to which key it demonstrates possession of", len(proofs))
	}
	if len(proofs) == 0 || proofs[0] == "" {
		return "", nil
	}
	header := proofs[0]

	// The URI as WE saw it, rebuilt from the configured issuer rather than from
	// request headers. Taking the host from the Host header would let a caller
	// choose what their proof authorises by lying about where they sent it.
	uri := s.cfg.Issuer + r.URL.Path

	now := time.Now()
	proof, err := dpop.Verify(header, r.Method, uri, accessToken, now)
	if err != nil {
		return "", err
	}

	// Before the replay record, so the retry a client is asked for can reuse
	// nothing and is refused nothing.
	if s.dpopNonces && !combinedAttestation(r) && !s.dpopNonceRecent(proof.Nonce, now) {
		return "", errDPoPNonce
	}

	// Replay. The proof is fresh, signed and correctly bound -- and still
	// replayable within its lifetime by whoever captured it.
	fresh, err := store.MarkDPoPProofSeen(r.Context(), s.db, proof.JKT, proof.JTI,
		dpop.ReplayWindow)
	if err != nil {
		s.log.Error("recording a DPoP proof", "err", err)
		// Fail CLOSED. If replay detection is unavailable, the proof cannot be
		// shown to be fresh, and accepting it would silently drop the protection
		// exactly when the database is unhappy.
		return "", errDPoPUnavailable
	}
	if !fresh {
		return "", errDPoPReplay
	}
	return proof.JKT, nil
}

var (
	errDPoPReplay      = errors.New("this DPoP proof has already been used")
	errDPoPUnavailable = errors.New("DPoP replay detection is unavailable")
	errDPoPNonce       = errors.New("this DPoP proof carries no recent nonce from this server")
)

// Server-provided nonces (RFC 9449 §8, specs/rfc9449.txt:1089-1099). A proof bounded
// only by its own iat can be prepared ahead of time by whoever briefly has the key; one
// carrying a value this server issued recently cannot.
//
// Derived rather than stored: every node derives the same one, so a client may land on
// any of them, and the token path gains no write. The server keeps "a window of recent
// nonces" (:1142) by accepting the last window's too, so a client that fetched one just
// before the turn is not refused for it. Off unless asked for, since §8 makes it a MAY
// and a client that cannot retry on use_dpop_nonce would stop working.

// dpopNonceWindow is how long one nonce is current.
const dpopNonceWindow = 5 * time.Minute

// SetDPoPNonces makes every DPoP proof carry a nonce from this server. It needs the
// root key, which is what makes one unpredictable.
func (s *Server) SetDPoPNonces(on bool) { s.dpopNonces = on && s.root != nil }

func (s *Server) dpopNonceAt(t time.Time) string {
	window := t.Unix() / int64(dpopNonceWindow/time.Second)
	sum := s.root.AddressHash(fmt.Sprintf("dpop-nonce:%s:%d", s.cfg.Issuer, window))
	return base64.RawURLEncoding.EncodeToString(sum)
}

func (s *Server) dpopNonceRecent(got string, now time.Time) bool {
	for _, want := range []string{s.dpopNonceAt(now), s.dpopNonceAt(now.Add(-dpopNonceWindow))} {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// combinedAttestation is a request whose one proof is also its attestation PoP, with
// no separate PoP header. Its nonce is the attestation challenge, which the attestation
// path issued and checks, and it cannot hold a second value.
func combinedAttestation(r *http.Request) bool {
	return r.Header.Get(abca.HeaderAttestation) != "" && r.Header.Get(abca.HeaderPoP) == ""
}

// offerDPoPNonce gives the client the value to retry with. Uncacheable, as §8.2 asks of
// any response carrying one (:1197).
func (s *Server) offerDPoPNonce(w http.ResponseWriter) {
	w.Header().Set("DPoP-Nonce", s.dpopNonceAt(time.Now()))
	w.Header().Set("Cache-Control", "no-store")
}

// bindingFor chooses the one confirmation a token may carry.
//
// DPoP wins when both are present. A client doing both is asserting two
// possession proofs for one token, and a resource server has to know which to
// check -- so one is chosen here rather than leaving the question open in the
// claim. DPoP is preferred because it is the proof the client had to construct
// deliberately for this request; the certificate is a property of a connection
// it may not even know is mutually authenticated.
func bindingFor(jkt, certThumbprint string) *tokens.Confirmation {
	if jkt != "" {
		return confirmationFor(jkt)
	}
	return confirmationForCert(certThumbprint)
}

type certThumbKey struct{}

// withCertThumbprint carries the presented certificate's thumbprint.
func withCertThumbprint(ctx context.Context, thumb string) context.Context {
	if thumb == "" {
		return ctx
	}
	return context.WithValue(ctx, certThumbKey{}, thumb)
}

func certThumbprintFrom(ctx context.Context) string {
	t, _ := ctx.Value(certThumbKey{}).(string)
	return t
}

// requireSubjectTokenBinding refuses a sender-constrained subject token whose
// key the presenter cannot prove possession of.
//
// # Why this exists when no specification demands it
//
// RFC 8693 §1 puts it explicitly out of scope: "whether ... proof-of-possession-
// style tokens will be required or issued ... will often be policy decisions made
// with respect to the specific needs of individual deployments". So this is a
// choice, not a rule, and it is recorded as one.
//
// The choice: a token carrying `cnf.jkt` means "holding this is not enough".
// Every place we honour that -- userinfo, the credential endpoint -- checks it.
// The token endpoint did not, so a stolen bound token could be handed to the
// exchange and traded for a working token by someone who never held the key.
// That leaves one endpoint where possession alone IS sufficient, which is the
// exact property DPoP was added to remove, and an attacker only needs the
// weakest door.
//
// It breaks nothing legitimate: a client that genuinely holds the token holds the
// key, so it can produce the proof. A client that cannot is, by construction, not
// the party the token was issued to.
//
// Returns nil when the subject token is not bound -- an ordinary bearer token is
// exchanged on the strength of client authentication, as before.
func (s *Server) requireSubjectTokenBinding(r *http.Request, subject *tokens.AccessTokenClaims) error {
	if subject.Cnf != nil && subject.Cnf.X5TS256 != "" {
		// The same rule for the other binding. handleToken put this
		// connection's certificate on the context; a subject token bound to
		// a certificate is exchanged only over a connection presenting it.
		presented := certThumbprintFrom(r.Context())
		if presented == "" {
			return errors.New("the subject token is bound to a client certificate; " +
				"present it over mutual TLS")
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(subject.Cnf.X5TS256)) != 1 {
			return errors.New("the certificate on this connection is not the one the " +
				"subject token is bound to")
		}
		return nil
	}
	if subject.Cnf == nil || subject.Cnf.JKT == "" {
		return nil
	}
	// The proof was already verified by handleToken, which put its thumbprint on
	// the context. Reading it again here rather than re-verifying: a second call
	// would consume the proof's jti a second time and be refused as a replay.
	presented := dpopThumbprintFrom(r.Context())
	if presented == "" {
		return errors.New("the subject token is bound to a DPoP key; present a " +
			"proof of possession for that key alongside it")
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(subject.Cnf.JKT)) != 1 {
		return errors.New("the DPoP proof on this request is for a different key " +
			"than the subject token is bound to")
	}
	return nil
}

// refuseUnboundTokenRequest enforces RFC 9449 §5.2's client registration
// metadata, reporting true when it has written a refusal.
//
//	"dpop_bound_access_tokens: A boolean value specifying whether the client
//	always uses DPoP for token requests ... If the value is true, the
//	authorization server MUST reject token requests from the client that do not
//	contain the DPoP header."
//
// This is the mechanism by which a client pins itself to DPoP. Without it,
// sender-constraining is decided per request by whether a proof happened to be
// attached, so a client that means to be bound on every request cannot say so --
// and one request that simply omits the header yields an ordinary bearer token.
// The downgrade needs no attack on DPoP itself, only the absence of a proof.
//
// A function rather than an inline check because the token endpoint has two
// places where a client becomes known: the ordinary path, and the OID4VCI
// pre-authorized code grant, which is dispatched *before* the client is resolved
// because §6.1 lets a wallet send no `client_id` and so resolves it from the
// offer instead. A rule written out once and enforced in one of those two is a
// rule with a hole, and the hole is invisible from the outside -- the client
// receives a working bearer token, and nothing looks wrong until it is stolen.
//
// The proof itself is verified at the top of `handleToken`, so an empty
// thumbprint here means no DPoP header arrived; a malformed one was already
// refused there.
func (s *Server) refuseUnboundTokenRequest(w http.ResponseWriter, ctx context.Context, c *clients.Client) bool {
	if c == nil || !c.DPoPBoundAccessTokens || dpopThumbprintFrom(ctx) != "" {
		return false
	}
	s.log.Info("token request without DPoP from a client registered as DPoP-bound",
		"client_id", c.ClientID, "correlation_id", correlationID(ctx))
	w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
	writeTokenError(w, &oauth.TokenError{Code: "invalid_dpop_proof",
		Description: "this client is registered with dpop_bound_access_tokens, " +
			"so every token request must carry a DPoP proof",
		Status: http.StatusBadRequest})
	return true
}

type refreshKeptKey struct{}

// withRefreshKept says a grant is keeping the refresh token it came with, so the mint
// issues none. On the context, as the thumbprint above is, for the one grant that sets it.
func withRefreshKept(ctx context.Context) context.Context {
	return context.WithValue(ctx, refreshKeptKey{}, true)
}

func refreshKeptFrom(ctx context.Context) bool {
	kept, _ := ctx.Value(refreshKeptKey{}).(bool)
	return kept
}

// refuseOutOfProfile holds a client marked for a security profile to it at the token
// endpoint, before any grant. A client's settings can leave the profile by a command that
// has never heard of one, and a client out of it is refused rather than served as if
// nothing had happened, because the mark is somebody's promise about it.
func (s *Server) refuseOutOfProfile(w http.ResponseWriter, r *http.Request, c *clients.Client) bool {
	if c == nil || !c.FAPI2() {
		return false
	}
	ctx := r.Context()
	if problems := c.ProfileProblems(); len(problems) > 0 {
		s.log.Error("a client out of its security profile was refused", "client_id", c.ClientID,
			"problems", problems, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "this client does not meet its security profile", Status: http.StatusBadRequest})
		return true
	}
	// FAPI 2.0 §5.3.2.1: "shall only issue sender-constrained access tokens". A client
	// set for mutual TLS binding is otherwise given a bearer token when it arrives
	// without a certificate, which is a cutover for any other client.
	jkt := dpopThumbprintFrom(ctx)
	if jkt == "" && certThumbprintFrom(ctx) == "" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "a client held to FAPI 2.0 is issued only sender-constrained tokens, and this " +
				"request proves no key", Status: http.StatusBadRequest})
		return true
	}
	if jkt != "" && !slices.Contains(clients.FAPI2Algorithms, dpop.Algorithm(r.Header.Get("DPoP"))) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		writeTokenError(w, &oauth.TokenError{Code: "invalid_dpop_proof",
			Description: "a client held to FAPI 2.0 signs its proofs with " +
				strings.Join(clients.FAPI2Algorithms, ", "), Status: http.StatusBadRequest})
		return true
	}
	return false
}

func dpopChallenge(errCode, description string) string {
	return `DPoP realm="signari", error="` + errCode + `", error_description="` +
		description + `", algs="` + dpop.SupportedAlgs() + `"`
}
