package httpapi

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/dpop"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oid4vci"
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
		s.log.Error("minting a c_nonce", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"c_nonce": nonce})
}

// handleCredential implements §8, the Credential Endpoint.
func (s *Server) handleCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	// A protected resource, authenticated exactly as userinfo is — including the
	// DPoP scheme, because a credential endpoint reached with a bound token that
	// proved nothing is the downgrade RFC 9449 §7.2 exists to stop.
	raw, scheme := bearerTokenAndScheme(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", `+s.resourceMetadataChallenge()+
				`, DPoP realm="signari", algs="`+dpop.SupportedAlgs()+`"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(), raw)
	if err != nil {
		s.log.Info("credential endpoint token rejected", "err", err,
			"correlation_id", correlationID(ctx))
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !tokens.AudienceAccepted(claims, s.cfg.Issuer) {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", `+
				`error_description="This token was issued for another resource"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// The same two-step enforcement userinfo performs: the SCHEME rule first
	// (RFC 9449 §7.1 and §7.2 both key on it, which is why checking `cnf` alone
	// misses them), then the proof itself when the token is bound.
	bound := claims.Cnf != nil && claims.Cnf.JKT != ""
	if perr := dpop.CheckPresentation(bound, scheme); perr != nil {
		w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token", perr.Error()))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if bound {
		if jkt, derr := s.verifyDPoPForRequest(r, raw); derr != nil || jkt == "" {
			s.log.Info("DPoP enforcement refused a credential request",
				"correlation_id", correlationID(ctx))
			w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token",
				"the access token is sender-constrained and the DPoP proof did not match"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	var req oid4vci.CredentialRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request",
			"the request body is not JSON")
		return
	}
	proofs, verr := req.Validate()
	if verr != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request",
			verr.Error())
		return
	}

	var orgID string
	oerr := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`,
		claims.Subject).Scan(&orgID)
	if oerr != nil {
		s.log.Error("resolving the organisation for a credential request", "err", oerr)
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	configs, cerr := store.CredentialConfigurations(ctx, s.db, orgID)
	if cerr != nil {
		s.log.Error("loading credential configurations", "err", cerr)
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	cfg, known := configs[req.ConfigurationID]
	if !known {
		writeCredentialError(w, http.StatusBadRequest, "unsupported_credential_type",
			"this issuer does not offer the credential configuration "+req.ConfigurationID)
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

	issued := make([]oid4vci.IssuedCredential, 0, len(proofs))
	for _, p := range proofs {
		key, perr := s.validateCredentialProof(ctx, claims, p)
		if perr != nil {
			writeCredentialError(w, http.StatusBadRequest, "invalid_proof", perr.Error())
			return
		}
		tp, terr := key.Thumbprint(crypto.SHA256)
		if terr != nil {
			s.log.Error("thumbprinting a holder key", "err", terr)
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
		cred, ierr := s.issueCredential(ctx, orgID, claims.Subject, cfg, key, issuedAt)
		if ierr != nil {
			s.log.Error("issuing a credential", "err", ierr,
				"correlation_id", correlationID(ctx))
			writeCredentialError(w, http.StatusInternalServerError, "server_error",
				"the credential could not be issued")
			return
		}
		issued = append(issued, oid4vci.IssuedCredential{Credential: cred})
	}

	s.auditDetached(ctx, audit.Event{
		Type: "oid4vci.credential_issued", OrgID: orgID, SubjectID: claims.Subject,
		ClientID: claims.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"configuration": cfg.ID, "vct": cfg.VCT,
			"count": len(issued), "format": cfg.Format},
	})

	writeJSON(w, http.StatusOK, oid4vci.CredentialResponse{Credentials: issued})
}

// validateCredentialProof checks one key proof and spends its nonce.
func (s *Server) validateCredentialProof(ctx context.Context,
	claims *tokens.AccessTokenClaims, proof string) (*jose.JSONWebKey, error) {

	// The nonce is read from the proof before validation so the right expected
	// value can be supplied; the proof's signature is what makes it trustworthy,
	// and the claim is compared, not believed.
	presented := oid4vci.NonceFromProof(proof)
	if err := store.ClaimCredentialNonce(ctx, s.db, presented); err != nil {
		return nil, errors.New("the key proof does not carry a fresh c_nonce from " +
			"this issuer's nonce endpoint")
	}

	key, err := oid4vci.ValidateJWTProof(proof, oid4vci.ProofContext{
		CredentialIssuer: s.credentialIssuerID(),
		ClientID:         claims.ClientID,
		// An access token with no client_id came from an anonymous
		// pre-authorized code redemption, which §F.1 says forbids `iss`.
		Anonymous:     claims.ClientID == "",
		ExpectedNonce: presented,
	}, time.Now())
	if err != nil {
		return nil, err
	}
	return key.JWK, nil
}

// issueCredential mints one SD-JWT VC.
func (s *Server) issueCredential(ctx context.Context, orgID, userID string,
	cfg oid4vci.Configuration, holderKey *jose.JSONWebKey, now time.Time) (string, error) {

	subject, err := store.CredentialSubject(ctx, s.db, userID)
	if err != nil {
		return "", err
	}
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
		"error": code, "error_description": description,
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

	configs, err := store.AllCredentialConfigurations(ctx, s.db)
	if err != nil {
		s.log.Error("loading credential configurations", "err", err)
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
		entry := map[string]any{
			"format": c.Format,
			"vct":    c.VCT,
			// §8.2: "The proofs parameter MUST be present if the
			// proof_types_supported parameter is present" — so declaring this is
			// what makes a key proof mandatory, which is the point.
			"proof_types_supported": map[string]any{
				oid4vci.ProofTypeJWT: map[string]any{
					"proof_signing_alg_values_supported": oid4vci.ProofAlgNames(),
				},
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
		if c.DisplayName != "" {
			entry["display"] = []map[string]any{{"name": c.DisplayName, "locale": "en-US"}}
		}
		supported[id] = entry
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		// §12.2.3 makes this the mix-up defence: a wallet compares it against the
		// identifier it inserted the well-known path into, and refuses the
		// document if they differ.
		"credential_issuer":   s.cfg.Issuer,
		"credential_endpoint": s.cfg.Issuer + oidcPathCredential,
		"nonce_endpoint":      s.cfg.Issuer + oidcPathCredentialNonce,
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
	})
}

const (
	oidcPathCredential      = "/oid4vci/credential"
	oidcPathCredentialNonce = "/oid4vci/nonce"
)
