package httpapi

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/dpop"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/rar"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// The OID4VCI Credential Issuer role: §7 Nonce Endpoint, §8 Credential Endpoint,
// §12.2 Credential Issuer Metadata.
//
// Migration 0077 made this server the AUTHORIZATION SERVER for OID4VCI — it
// issued the access token a credential endpoint would accept, and the docs said
// plainly that nothing here minted a credential. This is the other half.

// credentialNonceTTL bounds how long a c_nonce stays usable.
//
// Short, because §8.2 uses it for freshness and nothing else: a wallet fetches
// one immediately before building its proof.
const credentialNonceTTL = 5 * time.Minute

// handleCredentialNonce implements §7, the Nonce Endpoint.
//
// "The Nonce Endpoint is not a protected resource, meaning the Wallet does not
// need to supply an access token to access it." That is deliberate and worth
// not second-guessing: the nonce proves freshness, not authorisation, and
// requiring a token would mean a wallet needs one before it can build the proof
// that the token-bearing request depends on.
func (s *Server) handleCredentialNonce(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// §7.2: "the Credential Issuer MUST make the response uncacheable by adding
	// a Cache-Control header field including the value no-store."
	w.Header().Set("Cache-Control", "no-store")

	nonce, err := store.NewCredentialNonce(ctx, s.db, credentialNonceTTL)
	if err != nil {
		s.log.ErrorContext(ctx, "minting a c_nonce", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": nonce})
}

// credentialAudience is the one audience a token redeemed from an offer carries.
// Not the client id, and not the issuer, which are what userinfo accepts: the
// offer vouched for the holder of a code, nobody signed in, and a token that says
// so must not pass for one that says otherwise anywhere else.
func (s *Server) credentialAudience() string {
	return s.cfg.Issuer + oidcPathCredential
}

// issuanceOnly reports whether a token is good for the credential endpoint and so
// for nothing else: not an introspecting resource, and not a subject or actor at
// the exchanges, which would hand back a token with an ordinary audience.
func (s *Server) issuanceOnly(c *tokens.AccessTokenClaims) bool {
	return audienceIncludes(c.Audience, s.credentialAudience())
}

type issuanceAudienceKey struct{}

// withIssuanceAudience tells mintSet to audience the token to the credential
// endpoint, carried as the DPoP thumbprint is: one caller in a dozen sets it, and
// it is not a resource the client asked for, which mintSet would refuse.
func withIssuanceAudience(ctx context.Context) context.Context {
	return context.WithValue(ctx, issuanceAudienceKey{}, true)
}

func issuanceAudienceFrom(ctx context.Context) bool {
	on, _ := ctx.Value(issuanceAudienceKey{}).(bool)
	return on
}

// issuanceToken authenticates a request to an endpoint of issuance. Having answered
// otherwise, it returns nil.
func (s *Server) issuanceToken(w http.ResponseWriter, r *http.Request) *tokens.AccessTokenClaims {
	ctx := r.Context()

	// A protected resource, authenticated exactly as userinfo is — including the
	// DPoP scheme, because a credential endpoint reached with a bound token that
	// proved nothing is the downgrade RFC 9449 §7.2 exists to stop.
	raw, scheme := bearerTokenAndScheme(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", `+s.resourceMetadataChallenge()+
				`, DPoP realm="signari", algs="`+dpop.SupportedAlgs()+`"`)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	claims, err := s.verifyPresented(ctx, s.acceptedIssuers(ctx), raw)
	if err != nil {
		s.log.InfoContext(ctx, "credential endpoint token rejected", "err", err,
			"correlation_id", correlationID(ctx))
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	if !s.issuanceOnly(claims) {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", `+
				`error_description="This token was issued for another resource"`)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	// Revoked and ended are read now, as userinfo reads them (ADR-007). This
	// endpoint checked neither, so a token its client had revoked went on
	// minting credentials until it expired. Before the proof, as there, because
	// the proof is held to the client's profile.
	standing := s.standing(ctx, claims, "the credential endpoint")
	if ended := endedDescription(standing); ended != "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="signari", error="invalid_token", `+
			`error_description="`+ended+`"`)
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}

	// The same two-step enforcement userinfo performs: the SCHEME rule first
	// (RFC 9449 §7.1 and §7.2 both key on it, which is why checking `cnf` alone
	// misses them), then the proof itself when the token is bound.
	bound := claims.Cnf != nil && claims.Cnf.JKT != ""
	if perr := dpop.CheckPresentation(bound, scheme); perr != nil {
		w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token", perr.Error()))
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	if s.boundTokenRefused(w, r, raw, claims.Cnf, "credential", standing.HeldToProfile) {
		return nil
	}
	return claims
}

// handleCredentialOffer serves an offer kept by reference (§4.1.3). Uncacheable, as the
// specification asks of a URI that is not unique, and this one is: it carries a code.
func (s *Server) handleCredentialOffer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	offer, err := store.CredentialOfferByHandle(ctx, s.db, s.root, r.PathValue("handle"), s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading a kept credential offer", "err", err, "correlation_id", correlationID(ctx))
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	if offer == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(offer)
}

// notificationEvents are §11.1's, and case sensitive.
var notificationEvents = map[string]bool{"credential_accepted": true, "credential_failure": true,
	"credential_deleted": true}

// handleCredentialNotification implements §11: a wallet saying what became of what it
// was issued. Nothing depends on it, since a wallet may never say, so it is recorded and
// audited and not acted on.
func (s *Server) handleCredentialNotification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	claims := s.issuanceToken(w, r)
	if claims == nil {
		return
	}
	var req struct {
		NotificationID   string `json:"notification_id"`
		Event            string `json:"event"`
		EventDescription string `json:"event_description"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_notification_request", "the request body is not JSON")
		return
	}
	if req.NotificationID == "" || !notificationEvents[req.Event] || !notificationText(req.EventDescription) {
		writeCredentialError(w, http.StatusBadRequest, "invalid_notification_request",
			"give a notification_id and an event of credential_accepted, credential_failure or credential_deleted")
		return
	}
	configuration, err := store.CredentialNotified(ctx, s.db, req.NotificationID, claims.JTI)
	if errors.Is(err, store.ErrNotificationUnknown) {
		writeCredentialError(w, http.StatusBadRequest, "invalid_notification_id", err.Error())
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "reading a credential notification", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	s.auditDetached(ctx, audit.Event{Type: "oid4vci.credential_notified", SubjectID: claims.Subject,
		ClientID: claims.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"configuration": configuration, "event": req.Event, "description": req.EventDescription}})
	w.WriteHeader(http.StatusNoContent)
}

// notificationText is §11.1's alphabet for event_description: printable ASCII without
// a double quote or a backslash.
func notificationText(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// handleCredential implements §8, the Credential Endpoint.
func (s *Server) handleCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	claims := s.issuanceToken(w, r)
	if claims == nil {
		return
	}

	body, encrypted, ok := s.credentialRequestBody(w, r, 1<<20)
	if !ok {
		return
	}
	var req oid4vci.CredentialRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request",
			"the request body is not JSON")
		return
	}
	seal, serr := sealFor(req.ResponseEncryption, encrypted)
	if serr != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_encryption_parameters", serr.Error())
		return
	}
	proofs, verr := req.Validate()
	if errors.Is(verr, oid4vci.ErrNoProof) {
		writeCredentialError(w, http.StatusBadRequest, "invalid_proof", verr.Error())
		return
	}
	if verr != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request",
			verr.Error())
		return
	}

	// The holder must still be active. A deactivated person's issuance token
	// carries no session to end and no grant to revoke, so without this it went
	// on minting month-long credentials until it expired. Read before the request's
	// shape is judged against the token, which needs to know what this issuer offers.
	var orgID string
	var active bool
	oerr := s.db.QueryRow(ctx,
		`SELECT org_id::text, status = 'active' FROM core.users WHERE id = $1::uuid`,
		claims.Subject).Scan(&orgID, &active)
	if oerr == nil && !active {
		w.Header().Set("WWW-Authenticate", `Bearer realm="signari", error="invalid_token", `+
			`error_description="The account this token was issued for is not active"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if oerr != nil {
		s.log.ErrorContext(ctx, "resolving the organisation for a credential request", "err", oerr)
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	configs, cerr := store.CredentialConfigurations(ctx, s.db, orgID)
	if cerr != nil {
		s.log.ErrorContext(ctx, "loading credential configurations", "err", cerr)
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	// A token that says what it was granted is asked of by identifier, and only
	// that one is (§8.2). It says so itself, signed, and needs no offer behind it:
	// the person signed in and approved what it names.
	granted, derr := decodeDetailClaim(claims.AuthorizationDetails)
	if derr != nil {
		s.log.ErrorContext(ctx, "reading the details of a credential token", "err", derr)
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	asked := rar.CredentialConfigurations(granted)
	wanted := req.ConfigurationID
	var issuable []string
	if len(asked) > 0 {
		// A configuration this issuer has never heard of is that before it is anything
		// else: §8.3.1.2's unknown_credential_configuration (specs/oid4vci.txt:1914), the
		// answer a wallet can act on.
		if _, known := configs[req.ConfigurationID]; req.ConfigurationID != "" && !known {
			writeCredentialError(w, http.StatusBadRequest, "unknown_credential_configuration",
				"this issuer does not offer the credential configuration "+req.ConfigurationID)
			return
		}
		if req.CredentialIdentifier == "" {
			writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request",
				"the token response returned credential_identifiers, so a request sends "+
					"credential_identifier and not credential_configuration_id (section 8.2)")
			return
		}
		if !slices.Contains(asked, req.CredentialIdentifier) {
			// §8.3.1.2 (specs/oid4vci.txt:1917).
			writeCredentialError(w, http.StatusBadRequest, "unknown_credential_identifier",
				"this token was given no such credential identifier")
			return
		}
		wanted, issuable = req.CredentialIdentifier, asked
	} else {
		if req.CredentialIdentifier != "" {
			writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request",
				"credential_identifier is for a token response that returned credential_identifiers, "+
					"and this one did not; send credential_configuration_id (section 8.2)")
			return
		}
		// What this token may be exchanged for: the configurations of the offer that
		// minted it (migration 0133). Any other token audienced here -- a sign-in
		// token from an unrelated client -- used to mint any configuration for its
		// subject. §8.3.1.1 answers a token that "does not contain an Access Token
		// that enables issuance of a requested Credential" with an RFC 6750 error.
		var ierr error
		if issuable, ierr = store.IssuableConfigurations(ctx, s.db, claims.JTI, claims.Subject); ierr != nil {
			s.log.ErrorContext(ctx, "reading what a token may be exchanged for", "err", ierr)
			writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
	}
	if len(issuable) == 0 {
		s.log.InfoContext(ctx, "credential endpoint refused a token no offer minted",
			"client_id", claims.ClientID, "correlation_id", correlationID(ctx))
		w.Header().Set("WWW-Authenticate", `Bearer realm="signari", error="invalid_token", `+
			`error_description="This access token was not issued for credential issuance"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !slices.Contains(issuable, wanted) {
		// The token is good for issuance, of something else: RFC 6750 §3.1's
		// insufficient_scope, which is a 403.
		s.log.InfoContext(ctx, "credential endpoint refused a configuration the offer did not name",
			"requested", wanted, "offered", issuable,
			"correlation_id", correlationID(ctx))
		w.Header().Set("WWW-Authenticate", `Bearer realm="signari", error="insufficient_scope", `+
			`error_description="This access token does not authorize issuing that credential"`)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	cfg, known := configs[wanted]
	if !known {
		// §8.3.1.2's code (specs/oid4vci.txt:1914). Reached when the offer names
		// a configuration that has since been removed.
		writeCredentialError(w, http.StatusBadRequest, "unknown_credential_configuration",
			"this issuer does not offer the credential configuration "+wanted)
		return
	}

	// One instant for the whole batch.
	//
	// RFC 9901 §10.1 requires the time claims to be rounded, and `Issue` rounds
	// them -- but it was previously called with a fresh `time.Now()` per proof,
	// so a batch that straddled a period boundary would still emit two different
	// values. Reading the clock once makes the batch agree by construction
	// instead of by how fast the loop happened to run.
	issuedAt := time.Now()

	// Each proof binds one credential (§8.3: "Each key provided by the Wallet is
	// used to bind to, at most, one Credential"), so each is validated and each
	// c_nonce spent separately.
	//
	// §10.1 requires NEW key binding keys for each credential in a batch, and a
	// wallet that sends the same key twice -- with two different c_nonces, which
	// it can freely obtain -- would get two credentials carrying an identical
	// `cnf`. Those are linkable by inspection, which is the one thing batch
	// issuance exists to prevent, so the batch is refused rather than served.
	seenKeys := make(map[string]bool, len(proofs))

	// The attesters `signari attester add` registered, read once for the batch.
	// A key attestation in a proof is verified against these; with none it is
	// refused, never taken on the wallet's word. Until 2.07 nothing passed them,
	// so every attested proof was refused while the documentation said to
	// register an attester.
	attesterSet, aerr := s.trustedAttesters(ctx, orgID)
	if aerr != nil {
		s.log.ErrorContext(ctx, "reading key attesters", "err", aerr, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error",
			"the trusted key attesters could not be read")
		return
	}
	attesters := make([]*jose.JSONWebKey, len(attesterSet.Keys))
	for i := range attesterSet.Keys {
		attesters[i] = &attesterSet.Keys[i]
	}
	// And the roots an `x5c` chain may verify to (`signari credential
	// trust-root`). Nil when there are none, which refuses every chain.
	roots, rerr := store.CredentialProofRoots(ctx, s.db, orgID)
	if rerr != nil {
		s.log.ErrorContext(ctx, "reading credential proof roots", "err", rerr, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error",
			"the trusted proof roots could not be read")
		return
	}

	holderKeys := make([]*jose.JSONWebKey, 0, len(proofs))
	spent := map[string]bool{}
	for _, p := range proofs {
		key, attested, perr := s.validateCredentialProof(ctx, claims, p, attesters, roots, spent)
		if errors.Is(perr, errCredentialNonce) {
			writeCredentialError(w, http.StatusBadRequest, "invalid_nonce", perr.Error())
			return
		}
		if perr != nil {
			writeCredentialError(w, http.StatusBadRequest, "invalid_proof", perr.Error())
			return
		}
		if cfg.RequireKeyAttestation && !attested {
			writeCredentialError(w, http.StatusBadRequest, "invalid_proof",
				"this credential is issued only to a key a trusted attester vouches for: "+
					"send a key_attestation (Appendix D) covering the proof's key")
			return
		}
		tp, terr := key.Thumbprint(crypto.SHA256)
		if terr != nil {
			s.log.ErrorContext(ctx, "thumbprinting a holder key", "err", terr)
			writeCredentialError(w, http.StatusBadRequest, "invalid_proof",
				"the key in a proof could not be canonicalised")
			return
		}
		if fp := base64.RawURLEncoding.EncodeToString(tp); seenKeys[fp] {
			writeCredentialError(w, http.StatusBadRequest, "invalid_proof",
				"two proofs carry the same public key; RFC 9901 section 10.1 "+
					"requires a new key binding key for each credential in a batch, "+
					"because credentials sharing a cnf can be linked to one holder "+
					"by any two verifiers that compare them")
			return
		} else {
			seenKeys[fp] = true
		}
		holderKeys = append(holderKeys, key)
	}

	if cfg.Deferred {
		s.deferCredential(w, r, seal, orgID, claims, cfg, holderKeys)
		return
	}
	issued, ierr := s.mintCredentials(ctx, orgID, claims, cfg, holderKeys, issuedAt)
	if ierr != nil {
		s.log.ErrorContext(ctx, "issuing a credential", "err", ierr, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "the credential could not be issued")
		return
	}
	s.answerIssued(w, r, seal, orgID, claims, cfg, issued)
}

// mintCredentials mints one credential per key.
func (s *Server) mintCredentials(ctx context.Context, orgID string, claims *tokens.AccessTokenClaims,
	cfg oid4vci.Configuration, holderKeys []*jose.JSONWebKey, at time.Time) ([]oid4vci.IssuedCredential, error) {

	issued := make([]oid4vci.IssuedCredential, 0, len(holderKeys))
	for _, key := range holderKeys {
		cred, err := s.issueCredential(ctx, orgID, claims, cfg, key, at)
		if err != nil {
			return nil, err
		}
		issued = append(issued, oid4vci.IssuedCredential{Credential: cred})
	}
	return issued, nil
}

// answerIssued is the end of an issuance, immediate or deferred.
func (s *Server) answerIssued(w http.ResponseWriter, r *http.Request, seal *credentialSeal, orgID string,
	claims *tokens.AccessTokenClaims, cfg oid4vci.Configuration, issued []oid4vci.IssuedCredential) {
	ctx := r.Context()
	s.auditDetached(ctx, audit.Event{
		Type: "oid4vci.credential_issued", OrgID: orgID, SubjectID: claims.Subject,
		ClientID: claims.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"configuration": cfg.ID, "vct": cfg.VCT,
			"count": len(issued), "format": cfg.Format},
	})

	// Issued whether or not this can be written: the credential is the point, and a
	// wallet with no id reports nothing, which §11 allows of any wallet.
	notification, nerr := store.NewCredentialNotification(ctx, s.db, orgID, claims.Subject, claims.JTI, cfg.ID)
	if nerr != nil {
		s.log.ErrorContext(ctx, "recording an issuance", "err", nerr, "correlation_id", correlationID(ctx))
	}
	s.writeCredentialAnswer(w, r, seal, http.StatusOK, oid4vci.CredentialResponse{Credentials: issued, NotificationID: notification})
}

// deferredInterval is §8.3's wait, as a wallet is told it: long enough not to be
// polling, short enough to come back inside the life of its token, which is all the
// time a decision has.
const deferredInterval = 30

// deferCredential parks a request whose proofs have passed, keeping the keys and not the
// proofs: a nonce is spent once, so a proof could not be checked again and need not be.
func (s *Server) deferCredential(w http.ResponseWriter, r *http.Request, seal *credentialSeal, orgID string,
	claims *tokens.AccessTokenClaims, cfg oid4vci.Configuration, holderKeys []*jose.JSONWebKey) {
	ctx := r.Context()
	keysJSON, err := json.Marshal(holderKeys)
	if err == nil {
		var transaction string
		if transaction, err = store.NewCredentialRequest(ctx, s.db, orgID, claims.Subject, claims.JTI, cfg.ID, keysJSON); err == nil {
			s.auditDetached(ctx, audit.Event{Type: "oid4vci.credential_deferred", OrgID: orgID, SubjectID: claims.Subject,
				ClientID: claims.ClientID, CorrelationID: correlationID(ctx), Detail: map[string]any{"configuration": cfg.ID}})
			s.writeCredentialAnswer(w, r, seal, http.StatusAccepted, map[string]any{"transaction_id": transaction, "interval": deferredInterval})
			return
		}
	}
	s.log.ErrorContext(ctx, "parking a credential request", "err", err, "correlation_id", correlationID(ctx))
	writeCredentialError(w, http.StatusInternalServerError, "server_error", "the request could not be kept")
}

// handleDeferredCredential implements §9: what came of a parked request. Asked with the
// token that made it, since §9 wants one valid for that issuance, and read again now: a
// person deactivated, or a configuration removed, since the request gets nothing.
func (s *Server) handleDeferredCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	claims := s.issuanceToken(w, r)
	if claims == nil {
		return
	}
	body, encrypted, ok := s.credentialRequestBody(w, r, 16<<10)
	if !ok {
		return
	}
	var req struct {
		TransactionID      string          `json:"transaction_id"`
		ResponseEncryption json.RawMessage `json:"credential_response_encryption"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.TransactionID == "" {
		writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request", "give a transaction_id")
		return
	}
	seal, serr := sealFor(req.ResponseEncryption, encrypted)
	if serr != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_encryption_parameters", serr.Error())
		return
	}
	parked, err := store.CredentialRequestFor(ctx, s.db, req.TransactionID, claims.JTI)
	if err != nil {
		s.log.ErrorContext(ctx, "reading a parked credential request", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if parked == nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_transaction_id",
			"that transaction_id was not issued to this token, or has already been used")
		return
	}
	switch parked.State {
	case "pending":
		s.writeCredentialAnswer(w, r, seal, http.StatusAccepted, map[string]any{"transaction_id": req.TransactionID, "interval": deferredInterval})
		return
	case "denied":
		writeCredentialError(w, http.StatusBadRequest, "credential_request_denied", "this request was not accepted")
		return
	}
	configs, err := store.CredentialConfigurations(ctx, s.db, parked.OrgID)
	if err != nil {
		s.log.ErrorContext(ctx, "loading credential configurations", "err", err)
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	cfg, known := configs[parked.Configuration]
	if !known {
		writeCredentialError(w, http.StatusBadRequest, "credential_request_denied",
			"this issuer no longer offers that credential")
		return
	}
	var holderKeys []*jose.JSONWebKey
	if err := json.Unmarshal(parked.HolderKeys, &holderKeys); err != nil {
		s.log.ErrorContext(ctx, "reading a parked request's keys", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	issued, err := s.mintCredentials(ctx, parked.OrgID, claims, cfg, holderKeys, time.Now())
	if err != nil {
		s.log.ErrorContext(ctx, "issuing a deferred credential", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "the credential could not be issued")
		return
	}
	// Spent after minting, so that a failure above leaves the wallet able to come back,
	// and before answering, so that of two racing one is answered.
	spent, err := store.SpendCredentialRequest(ctx, s.db, parked.ID)
	if err != nil {
		s.log.ErrorContext(ctx, "spending a parked request", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if !spent {
		writeCredentialError(w, http.StatusBadRequest, "invalid_transaction_id", "that transaction_id has already been used")
		return
	}
	s.answerIssued(w, r, seal, parked.OrgID, claims, cfg, issued)
}

// errCredentialNonce is a proof whose c_nonce is not one this issuer gave out and has
// not spent: invalid_nonce, so that the wallet "should retrieve a new c_nonce value"
// (specs/oid4vci.txt:1923). A proof with none at all is invalid_proof (:1920).
var errCredentialNonce = errors.New("the key proof does not carry a fresh c_nonce from " +
	"this issuer's nonce endpoint")

// validateCredentialProof checks one key proof and spends its nonce. attested
// reports whether a trusted attester vouched for the key. spent holds the nonces
// this request has spent already: a batch's proofs, each for a key of its own, carry
// the one c_nonce a wallet fetched, and that is not a replay. Spending it per proof
// refused every batch at its second proof (13.01, the OID4VCI plan's batch-issuance).
func (s *Server) validateCredentialProof(ctx context.Context,
	claims *tokens.AccessTokenClaims, proof string, attesters []*jose.JSONWebKey,
	roots *x509.CertPool, spent map[string]bool) (_ *jose.JSONWebKey, attested bool, _ error) {

	// The nonce is read from the proof before validation so the right expected
	// value can be supplied; the proof's signature is what makes it trustworthy,
	// and the claim is compared, not believed.
	presented := oid4vci.NonceFromProof(proof)
	if presented == "" {
		return nil, false, errors.New("the key proof carries no c_nonce, and this issuer has a nonce endpoint")
	}
	if !spent[presented] {
		if err := store.ClaimCredentialNonce(ctx, s.db, presented); err != nil {
			return nil, false, errCredentialNonce
		}
		spent[presented] = true
	}

	key, err := oid4vci.ValidateJWTProof(proof, oid4vci.ProofContext{
		CredentialIssuer: s.credentialIssuerID(),
		ClientID:         claims.ClientID,
		// An access token with no client_id came from an anonymous
		// pre-authorized code redemption, which §F.1 says forbids `iss`.
		Anonymous:        claims.ClientID == "",
		ExpectedNonce:    presented,
		TrustedAttesters: attesters,
		TrustedX5CRoots:  roots,
	}, time.Now())
	if err != nil {
		return nil, false, err
	}
	return key.JWK, key.Attested, nil
}

// issueCredential mints one SD-JWT VC, naming the person as the token's client does:
// a credential is presented to verifiers this deployment never meets.
func (s *Server) issueCredential(ctx context.Context, orgID string, claims *tokens.AccessTokenClaims,
	cfg oid4vci.Configuration, holderKey *jose.JSONWebKey, now time.Time) (string, error) {

	subject, err := store.CredentialSubject(ctx, s.db, claims.Subject)
	if err != nil {
		return "", err
	}
	subject["sub"] = claims.Presented()
	issuer := oid4vci.Issuer{
		CredentialIssuer: s.credentialIssuerID(),
		Sign: func(payload []byte, typ string) (string, error) {
			key, kerr := s.cfg.Keys.Active(keys.ES256)
			if kerr != nil {
				return "", kerr
			}
			return tokens.NewSigner(key).SignRaw(payload, typ)
		},
	}
	if cfg.Revocable {
		// A place of its own, batch or not: §13.2, "every Referenced Token MUST have a
		// dedicated Status List entry". Taken before signing, because a place left over
		// is a decoy and a credential with no place could never be taken back.
		if issuer.Status, err = s.credentialStatusPlace(ctx, orgID, claims.Subject, cfg, now); err != nil {
			return "", err
		}
	}
	return issuer.Issue(cfg, subject, holderKey, now)
}

// credentialIssuerID is the identifier a proof's `aud` must equal (§F.1).
func (s *Server) credentialIssuerID() string { return s.cfg.Issuer }

// writeCredentialError answers in §8.3.1's shape.
func writeCredentialError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code, "error_description": oauth.ErrorText(description),
	})
}

// handleCredentialIssuerMetadata implements §12.2.
//
// Advertised only when the deployment has credential configurations, for the
// rule this project holds everywhere: a metadata document naming a capability is
// one a wallet will try to use. An issuer with nothing configured publishes
// nothing rather than an empty map that looks like a misconfiguration.
func (s *Server) handleCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	configs, err := store.AllCredentialConfigurations(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "loading credential configurations", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if len(configs) == 0 {
		writeError(w, http.StatusNotFound, "not_found",
			"this deployment issues no credentials")
		return
	}

	supported := map[string]any{}
	for id, c := range configs {
		jwtProof := map[string]any{
			"proof_signing_alg_values_supported": oid4vci.ProofAlgNames(),
		}
		// specs/oid4vci.txt:2429: "If the Credential Issuer does not require a
		// key attestation, this parameter MUST NOT be present". Present, and
		// empty (no constraint on key_storage or user_authentication), for
		// exactly the configurations the endpoint enforces it for.
		if c.RequireKeyAttestation {
			jwtProof["key_attestations_required"] = map[string]any{}
		}
		entry := map[string]any{
			"format": c.Format,
			// §8.2: "The proofs parameter MUST be present if the
			// proof_types_supported parameter is present" — so declaring this is
			// what makes a key proof mandatory, which is the point.
			"proof_types_supported": map[string]any{
				oid4vci.ProofTypeJWT: jwtProof,
			},
			"credential_signing_alg_values_supported": []string{string(keys.ES256)},
			// §12.2.4, and absence here is not neutral:
			//
			//	"It MUST be present when Cryptographic Key Binding is required for
			//	a Credential, and omitted otherwise. If absent, Cryptographic Key
			//	Binding is not required for this credential."
			//
			// `Issuer.Issue` refuses a request with no holder key -- "an unbound
			// credential is a bearer token, which is what binding exists to
			// prevent" -- so binding is required unconditionally. Omitting this
			// parameter told every conformant wallet the opposite of what the
			// endpoint does.
			//
			// `jwk` because that is the representation we use: the credential
			// carries `cnf: {"jwk": ...}`. A wallet that holds its key as a COSE
			// Key needs to know which form to present, and the only other place
			// that could be inferred from is a failed request.
			"cryptographic_binding_methods_supported": []string{"jwk"},
		}
		if c.Format == oid4vci.FormatJWTVC {
			// Appendix A.1.1.2, where credential_definition is REQUIRED, and a key
			// bound as the credential's subject rather than in `cnf`.
			entry["credential_definition"] = map[string]any{"type": oid4vci.VCTypes(c)}
			entry["cryptographic_binding_methods_supported"] = []string{"did:jwk"}
		} else {
			entry["vct"] = c.VCT
		}
		if c.DisplayName != "" {
			entry["display"] = []map[string]any{{"name": c.DisplayName, "locale": "en-US"}}
		}
		supported[id] = entry
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	document := map[string]any{
		// §12.2.3 makes this the mix-up defence: a wallet compares it against the
		// identifier it inserted the well-known path into, and refuses the
		// document if they differ.
		"credential_issuer":   s.cfg.Issuer,
		"credential_endpoint": s.cfg.Issuer + oidcPathCredential,
		"nonce_endpoint":      s.cfg.Issuer + oidcPathCredentialNonce,
		// §12.2.4. Named here, so a wallet knows the id in a response has somewhere to go.
		"notification_endpoint":        s.cfg.Issuer + oidcPathCredentialNotification,
		"deferred_credential_endpoint": s.cfg.Issuer + oidcPathDeferredCredential,
		// The wallet needs to know where to get a token, and for us that is the
		// same deployment.
		"authorization_servers": []string{s.cfg.Issuer},
		// §12.2.4: "The presence of this parameter means that the issuer supports
		// more than one key proof in the proofs parameter in the Credential
		// Request." Its ABSENCE therefore says the opposite -- and we accept up to
		// MaxProofsPerRequest, so leaving it out told every conformant wallet that
		// a capability we have does not exist. A wallet batching keys for
		// unlinkability would have sent one proof at a time forever.
		//
		// This is the project's own discovery rule read the other way round.
		// "Advertise only what works" has a second half: something that works and
		// is not advertised may as well not exist, because the client is doing
		// exactly what the specification tells it to and never asking.
		//
		// batch_size "MUST be 2 or greater"; ours is MaxProofsPerRequest, and the
		// test asserts the advertised number is the one actually enforced.
		"batch_credential_issuance": map[string]any{
			"batch_size": oid4vci.MaxProofsPerRequest,
		},
		"credential_configurations_supported": supported,
	}
	for name, value := range s.credentialEncryptionMetadata(r) {
		document[name] = value
	}
	writeJSON(w, http.StatusOK, document)
}

const (
	oidcPathCredential             = "/oid4vci/credential"
	oidcPathCredentialNonce        = "/oid4vci/nonce"
	oidcPathCredentialNotification = "/oid4vci/notification"
	oidcPathDeferredCredential     = "/oid4vci/deferred_credential"
)
