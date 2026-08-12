package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/passkeys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// WebAuthn ceremonies.
//
// A ceremony has two halves: the server issues a challenge, the authenticator
// signs it, the server checks the signature against the challenge it issued. The
// only hard part is the state in between -- and where that state lives is a
// security decision, not a storage one:
//
//   - It must be bound to THIS browser. A challenge any caller can present is a
//     challenge an attacker can have signed elsewhere and replay here.
//   - It must be single-use and short-lived, or a captured challenge is
//     replayable for as long as it survives.
//   - It must not be forgeable. A caller who can choose their own challenge can
//     choose one they already have a signature for.
//
// A signed, typed cookie satisfies all three: the browser scopes it, the
// signature makes it unforgeable, and a 5-minute expiry with a distinct `typ`
// keeps it out of every other verification path.

const (
	// ceremonyTTL is how long a user has to touch their authenticator. Long
	// enough to find a security key in a drawer, short enough that a challenge
	// captured from a shared machine is worthless.
	ceremonyTTL = 5 * time.Minute

	CeremonyCookieName = "__Host-signari_ceremony"
	typCeremony        = "ceremony+jwt"
)

// ceremonyClaims wraps the library's SessionData with our own binding.
type ceremonyClaims struct {
	Issuer  string `json:"iss"`
	Purpose string `json:"pur"` // "register" or "login" -- see below
	// Subject is empty for a discoverable login, where the whole point is that
	// we do not yet know who is signing in.
	Subject string          `json:"sub,omitempty"`
	OrgID   string          `json:"org,omitempty"`
	Session json.RawMessage `json:"sd"`
	Expiry  int64           `json:"exp"`
}

// issueCeremony stores the in-flight challenge in a signed cookie.
//
// Purpose is carried and checked because a REGISTRATION challenge must never be
// finishable as a LOGIN. Without it, an attacker who can start a registration on
// their own account could take the resulting signature and complete a login
// ceremony with it -- the two look similar enough that only an explicit label
// keeps them apart.
func (s *Server) issueCeremony(w http.ResponseWriter, purpose, userID, orgID string, sd *webauthn.SessionData) error {
	raw, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("encoding ceremony state: %w", err)
	}
	key, err := s.anySigningKey()
	if err != nil {
		return err
	}
	tok, err := tokens.NewSigner(key).SignJSON(ceremonyClaims{
		Issuer: s.cfg.Issuer, Purpose: purpose, Subject: userID, OrgID: orgID,
		Session: raw, Expiry: time.Now().Add(ceremonyTTL).Unix(),
	}, typCeremony)
	if err != nil {
		return fmt.Errorf("signing ceremony state: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name: CeremonyCookieName, Value: tok, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(ceremonyTTL.Seconds()),
	})
	return nil
}

// readCeremony verifies and consumes the in-flight challenge.
//
// The cookie is cleared by the caller on BOTH success and failure. A challenge
// that survives a failed attempt is a challenge an attacker can keep grinding
// against.
func (s *Server) readCeremony(r *http.Request, wantPurpose string) (*ceremonyClaims, *webauthn.SessionData, error) {
	c, err := r.Cookie(CeremonyCookieName)
	if err != nil || c.Value == "" {
		return nil, nil, errors.New("no ceremony in progress")
	}
	payload, err := tokens.VerifyTyped(s.cfg.Keys, s.cfg.Issuer, c.Value, typCeremony)
	if err != nil {
		return nil, nil, err
	}
	var cl ceremonyClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, nil, fmt.Errorf("malformed ceremony state: %w", err)
	}
	if cl.Purpose != wantPurpose {
		return nil, nil, fmt.Errorf("ceremony is for %q, not %q", cl.Purpose, wantPurpose)
	}
	if time.Now().After(time.Unix(cl.Expiry, 0)) {
		return nil, nil, errors.New("ceremony expired")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(cl.Session, &sd); err != nil {
		return nil, nil, fmt.Errorf("malformed ceremony session: %w", err)
	}
	return &cl, &sd, nil
}

func (s *Server) clearCeremony(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CeremonyCookieName, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (s *Server) anySigningKey() (keys.Key, error) {
	if k, err := s.cfg.Keys.Active(keys.ES256); err == nil {
		return k, nil
	}
	for _, alg := range s.cfg.Keys.Algorithms() {
		if k, err := s.cfg.Keys.Active(alg); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("no active signing key")
}

// relyingParty builds the WebAuthn configuration for the signed-in user's
// instance.
//
// Per request rather than cached at boot: rp_id is instance configuration an
// operator can legitimately set while the server runs, and a cached value would
// keep issuing ceremonies against the old one until a restart.
func (s *Server) relyingParty(ctx context.Context, orgID string) (*passkeys.Relying, error) {
	var rpID, displayName string
	if err := s.db.QueryRow(ctx, `
		SELECT COALESCE(i.rp_id,''), COALESCE(i.rp_display_name, i.display_name, '')
		FROM core.instances i
		JOIN core.organizations o ON o.instance_id = i.id
		WHERE o.id = $1::uuid`, orgID).Scan(&rpID, &displayName); err != nil {
		return nil, fmt.Errorf("loading instance rp_id: %w", err)
	}
	return passkeys.New(rpID, displayName, s.cfg.Issuer)
}

// handlePasskeyRegisterBegin starts adding an authenticator to a live account.
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "login_required", "sign in first")
		return
	}

	rp, err := s.relyingParty(ctx, orgID)
	if err != nil {
		// The most likely cause by far is an unset rp_id, and saying so beats a
		// generic failure an operator has to go digging for.
		s.log.Error("building the relying party", "err", err)
		writeError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}

	u, err := s.passkeyUser(ctx, userID)
	if err != nil {
		s.log.Error("loading passkey user", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	creation, sd, err := rp.BeginRegistration(u)
	if err != nil {
		s.log.Error("beginning registration", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := s.issueCeremony(w, "register", userID, orgID, sd); err != nil {
		s.log.Error("issuing ceremony", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// handlePasskeyRegisterFinish verifies the attestation and stores the credential.
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Cleared unconditionally: a challenge that survives a failed attempt can be
	// ground against.
	defer s.clearCeremony(w)

	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "login_required", "sign in first")
		return
	}

	cl, sd, err := s.readCeremony(r, "register")
	if err != nil {
		s.log.Info("registration ceremony rejected", "err", err)
		writeError(w, http.StatusBadRequest, "invalid_request", "no valid registration in progress")
		return
	}
	// The ceremony must belong to the SAME account that is finishing it.
	// Otherwise a user could begin a ceremony, sign in as someone else, and
	// attach their authenticator to that account.
	if cl.Subject != userID {
		s.log.Warn("ceremony subject does not match the session",
			"ceremony_sub", cl.Subject, "session_sub", userID)
		writeError(w, http.StatusBadRequest, "invalid_request", "no valid registration in progress")
		return
	}

	rp, err := s.relyingParty(ctx, orgID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}
	u, err := s.passkeyUser(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	cred, err := rp.FinishRegistration(u, *sd, r)
	if err != nil {
		// Logged with the reason, returned without it: attestation failures are
		// detailed and would tell an attacker exactly which check they tripped.
		s.log.Info("registration failed verification", "err", err)
		writeError(w, http.StatusBadRequest, "invalid_request", "the authenticator response was rejected")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}

	if err := store.SaveCredential(ctx, tx, userID, orgID, rp.RPID(),
		cred.ID, cred.PublicKey, cred.Authenticator.AAGUID, cred.Authenticator.SignCount,
		cred.Flags.BackupEligible, transports, cred.AttestationType, name); err != nil {
		s.log.Error("saving credential", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.passkey_registered", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"rp_id": rp.RPID(), "attestation": cred.AttestationType},
	}); err != nil {
		s.log.Error("auditing passkey registration", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	// Counted inside the transaction that just wrote the credential, so the
	// number reported back cannot disagree with what was stored.
	total, err := store.CountCredentials(ctx, tx, userID)
	if err != nil {
		s.log.Error("counting credentials", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "registered",
		"credentials": total,
		// Told plainly, because the number is the difference between a recoverable
		// lost device and a dead account.
		"passwordless_available": total >= store.MinCredentialsForPasswordless,
		"hint": map[bool]string{
			true:  "You can now sign in without a password.",
			false: "Register a second passkey on another device before removing your password.",
		}[total >= store.MinCredentialsForPasswordless],
	})
}

// passkeyUser assembles the library's view of a user from the database.
func (s *Server) passkeyUser(ctx context.Context, userID string) (*passkeys.User, error) {
	var handle []byte
	var email, username string
	if err := s.db.QueryRow(ctx, `
		SELECT user_handle, COALESCE(email,''), COALESCE(username,'')
		FROM core.users WHERE id = $1::uuid AND status = 'active'`, userID).
		Scan(&handle, &email, &username); err != nil {
		return nil, fmt.Errorf("loading user for a passkey ceremony: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	stored, err := store.CredentialsForUser(ctx, tx, userID)
	if err != nil {
		return nil, err
	}

	name := email
	if name == "" {
		name = username
	}
	return &passkeys.User{
		ID: handle, Name: name, DisplayName: name,
		Creds: passkeys.ToLibrary(stored),
	}, nil
}
