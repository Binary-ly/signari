package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mail"
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

	// Every credential this server creates is discoverable: BeginRegistration
	// passes ResidentKey: ResidentKeyRequirementRequired. That is a fact about
	// our configuration, so it is written as one rather than inferred from a
	// flag that means something else -- which is exactly what happened here
	// before, when cred.Flags.BackupEligible was passed into the `discoverable`
	// parameter and stored in is_discoverable.
	if err := store.SaveCredential(ctx, tx, userID, orgID, rp.RPID(),
		cred.ID, cred.PublicKey, cred.Authenticator.AAGUID, cred.Authenticator.SignCount,
		true, cred.Flags.BackupEligible, cred.Flags.BackupState,
		transports, cred.AttestationType, name); err != nil {
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

	// NIST SP 800-63B-4, Binding an Additional Authenticator:
	//
	//	"When an authenticator is added, the CSP SHALL notify the subscriber via
	//	a mechanism independent of the transaction binding the new authenticator"
	//
	// An unmet SHALL until now. The point is not tidiness: an attacker who has
	// momentary control of a session -- a borrowed laptop, a hijacked cookie --
	// registers their own passkey and thereby obtains durable access that
	// outlives the session they stole. Nothing else in the system would have told
	// the account's owner, and the credential list is a page nobody visits.
	//
	// Independent of the transaction, which is why it is email rather than a
	// banner on the page that just did it: whoever is holding the browser is
	// exactly who must not be the only one who finds out.
	//
	// AFTER the commit. A notification about a registration that then rolled back
	// is worse than none -- it teaches the recipient that these messages are
	// noise, which is the one thing a security notification cannot afford.
	//
	// Failure to send does NOT undo the registration. The credential is real and
	// refusing it now would leave the user with an authenticator the server has
	// forgotten. It is logged and audited instead, so an operator can see that a
	// required notification did not go out.
	s.notifyAuthenticatorBound(ctx, userID, orgID, name)

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

// handlePasskeyLoginBegin starts a sign-in with no identifier at all.
//
// This is the flow passkeys exist for: the user clicks "sign in", the browser
// offers whatever credential it holds for this RP ID, and nobody types a
// username. It only works because registration requires resident keys.
//
// No user is named, so nothing is leaked: the response is identical whether or
// not any account exists, which removes the enumeration oracle that a
// username-first passkey flow always has.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	orgID, err := s.defaultOrg(ctx)
	if err != nil {
		s.log.Error("resolving the org for a passkey login", "err", err)
		writeError(w, http.StatusServiceUnavailable, "passkeys_unavailable", "unavailable")
		return
	}
	rp, err := s.relyingParty(ctx, orgID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}

	assertion, sd, err := rp.BeginDiscoverableLogin()
	if err != nil {
		s.log.Error("beginning discoverable login", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	// No subject: we genuinely do not know who this is yet, and inventing one
	// would defeat the point of the flow.
	if err := s.issueCeremony(w, "login", "", orgID, sd); err != nil {
		s.log.Error("issuing ceremony", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// handlePasskeyLoginFinish verifies the assertion and signs the user in.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer s.clearCeremony(w)

	cl, sd, err := s.readCeremony(r, "login")
	if err != nil {
		s.log.Info("passkey login ceremony rejected", "err", err)
		writeError(w, http.StatusBadRequest, "invalid_request", "no valid sign-in in progress")
		return
	}
	rp, err := s.relyingParty(ctx, cl.OrgID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}

	// The handler is how the library asks "who does this credential belong to".
	// Resolution is by USER HANDLE, not by anything the caller supplies: the
	// handle came back inside the signed assertion, so it cannot be chosen.
	var resolvedUser, resolvedOrg string
	// The presented credential id, captured before validation.
	//
	// On failure the library returns a nil credential, so this closure is the
	// only place the id is available -- and it is exactly what a browser needs
	// in order to call signalUnknownCredential and stop the authenticator
	// offering a passkey we no longer hold.
	//
	// `held` is the other half, and it is what makes the signal safe to send.
	//
	// signalUnknownCredential tells the authenticator to DELETE a credential.
	// Sending it whenever an assertion fails would delete a perfectly good
	// passkey on any transient failure -- a user-verification timeout, a
	// sign-count regression, a corrupted signature. For somebody whose only
	// passkey it was, that is a self-inflicted lockout caused by the feature
	// meant to prevent one.
	//
	// So the id alone is not enough to justify the signal: we also have to know
	// the credential is genuinely not ours. That is decided here, where the
	// user's credential list is in hand, rather than inferred later from an
	// error the library does not distinguish.
	var presentedID []byte
	var held bool
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		presentedID = append([]byte(nil), rawID...)
		u, userID, orgID, err := s.userByHandle(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		for _, c := range u.WebAuthnCredentials() {
			if bytes.Equal(c.ID, rawID) {
				held = true
				break
			}
		}
		resolvedUser, resolvedOrg = userID, orgID
		return u, nil
	}

	cred, err := rp.FinishDiscoverableLogin(handler, *sd, r)
	if err != nil {
		s.log.Info("passkey assertion rejected", "err", err)
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"reason": "passkey_assertion_rejected"},
		})
		// Tell the browser WHICH credential we did not accept, so it can call
		// signalUnknownCredential and the authenticator can stop offering it.
		//
		// Without this, the only cure for a deleted passkey is
		// signalAllAcceptedCredentials, which needs a session -- so a user whose
		// only passkey was deleted is stuck being offered it forever, because
		// the one credential they have is the one that cannot sign them in.
		// This is the exact case WebAuthn L3 §5.1.10.2 exists for.
		//
		// It leaks nothing: the caller just presented this credential id, so
		// returning it tells them something they already had. §14.6.3's concern
		// is about disclosing ids to somebody who did NOT have them.
		//
		// Only when we do NOT hold it. A failure against a credential we still
		// have is a bad assertion, not a stale one, and answering it with a
		// deletion instruction would remove a working passkey.
		if held {
			writeError(w, http.StatusUnauthorized, "invalid_grant",
				"the passkey was not accepted")
			return
		}
		s.refuseWithUnknownCredential(w, rp.RPID(), presentedID)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	stored, _, err := store.CredentialByID(ctx, tx, cred.ID)
	if err != nil {
		s.log.Error("loading the asserted credential", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	// Cloning check. A backwards counter does NOT abort the sign-in on its own --
	// it is evidence, not proof, and a false positive here locks a legitimate
	// user out of their own account. It is recorded at WARN and audited so an
	// operator can act on a pattern rather than a single event.
	// §6.1.3: a BS transition from 1 to 0 means the credential is no longer
	// backed up, so the user is one lost device away from losing this factor.
	// The specification says the relying party "SHOULD guide the user through a
	// process to validate their other authentication factors". We record it;
	// the user-facing prompt is a product decision and is item 9k.
	if stored.BackupState && !cred.Flags.BackupState {
		s.log.Warn("passkey is no longer backed up; the user may be one device loss "+
			"from losing this credential", "user_id", resolvedUser,
			"correlation_id", correlationID(ctx))
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "mfa.passkey_backup_lost", OrgID: resolvedOrg, SubjectID: resolvedUser,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"rp_id": stored.RPID},
		}); aerr != nil {
			s.log.Error("auditing a passkey backup-state change", "err", aerr)
		}
	}

	if err := store.UpdateSignCount(ctx, tx, cred.ID, stored.SignCount,
		cred.Authenticator.SignCount, cred.Flags.BackupState); err != nil {
		if errors.Is(err, store.ErrCredentialCloned) {
			s.log.Warn("passkey signature counter went backwards; possible cloned authenticator",
				"user_id", resolvedUser, "stored", stored.SignCount,
				"presented", cred.Authenticator.SignCount, "correlation_id", correlationID(ctx))
			if aerr := audit.Write(ctx, tx, audit.Event{
				Type: "mfa.passkey_counter_regression", OrgID: resolvedOrg, SubjectID: resolvedUser,
				CorrelationID: correlationID(ctx),
				Detail: map[string]any{
					"stored": stored.SignCount, "presented": cred.Authenticator.SignCount,
				},
			}); aerr != nil {
				s.log.Error("auditing counter regression", "err", aerr)
			}
		} else {
			s.log.Error("updating the signature counter", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
	}

	s.completeSignIn(w, r, tx, resolvedUser, resolvedOrg, amrForPasskey(cred), r.URL.Query().Get("authz"))
}

// amrForPasskey reports what the assertion actually proved (RFC 8176).
//
// Honest rather than flattering, because acr is derived from this and a wrong
// value here silently upgrades every session that used a passkey:
//
//   - `user` always: the authenticator confirmed someone was present.
//   - `hwk` or `swk` by whether the credential is backup-eligible. A synced
//     passkey lives in a keychain across devices and is software-backed; a
//     device-bound one is hardware. Claiming `hwk` for a synced credential
//     overstates what the user physically holds.
//   - `mfa` ONLY when the authenticator reports user verification. That flag is
//     what distinguishes "someone touched this device" from "the device checked
//     a biometric or PIN first" -- one factor versus two. Without the check, a
//     tapped security key would satisfy an MFA requirement.
func amrForPasskey(cred *webauthn.Credential) []string {
	amr := []string{"user"}
	if cred.Flags.BackupEligible {
		amr = append(amr, "swk")
	} else {
		amr = append(amr, "hwk")
	}
	if cred.Flags.UserVerified {
		amr = append(amr, "mfa")
	}
	return amr
}

// userByHandle resolves the 64-byte user handle from a signed assertion.
func (s *Server) userByHandle(ctx context.Context, handle []byte) (*passkeys.User, string, string, error) {
	var userID, orgID, email, username string
	if err := s.db.QueryRow(ctx, `
		SELECT id::text, org_id::text, COALESCE(email,''), COALESCE(username,'')
		FROM core.users WHERE user_handle = $1 AND status = 'active'`, handle).
		Scan(&userID, &orgID, &email, &username); err != nil {
		return nil, "", "", fmt.Errorf("no active user for that credential: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	stored, err := store.CredentialsForUser(ctx, tx, userID)
	if err != nil {
		return nil, "", "", err
	}

	name := email
	if name == "" {
		name = username
	}
	return &passkeys.User{ID: handle, Name: name, DisplayName: name,
		Creds: passkeys.ToLibrary(stored)}, userID, orgID, nil
}

// defaultOrg picks the organisation a usernameless sign-in belongs to.
//
// Single-org deployments are the common case and this is correct for them. A
// multi-tenant deployment must instead scope by hostname, because the RP ID (and
// therefore which credentials the browser will even offer) is per instance --
// left explicit here rather than silently guessing wrong later.
func (s *Server) defaultOrg(ctx context.Context) (string, error) {
	var orgID string
	err := s.db.QueryRow(ctx, `
		SELECT o.id::text FROM core.organizations o
		JOIN core.instances i ON i.id = o.instance_id
		WHERE i.issuer = $1
		ORDER BY o.created_at LIMIT 1`, s.cfg.Issuer).Scan(&orgID)
	return orgID, err
}

// notifyAuthenticatorBound sends the NIST-required notice that a new
// authenticator was added.
//
// The message says what happened, when, and what to do if it was not them --
// "The notification SHALL provide clear instructions, including contact
// information, in case the recipient repudiates the event associated with the
// notification."
//
// Text only, like every other message this server sends. HTML mail from an
// identity provider trains users that a message about their account can contain
// a styled button they should click, which is the shape of the attack it is
// warning them about.
func (s *Server) notifyAuthenticatorBound(ctx context.Context, userID, orgID, name string) {
	var email string
	if err := s.db.QueryRow(ctx,
		`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`, userID).
		Scan(&email); err != nil {
		s.log.Error("looking up an address for an authenticator-bound notice",
			"err", err, "correlation_id", correlationID(ctx))
		return
	}
	if email == "" {
		// NIST also requires at least two notification addresses per account,
		// which this server does not yet model -- see item 9l. With none at all
		// there is nothing to send to, and that is worth an operator seeing
		// rather than passing in silence.
		s.log.Warn("a passkey was registered for an account with no notification "+
			"address; NIST SP 800-63B-4 requires the subscriber to be told",
			"user_id", userID, "correlation_id", correlationID(ctx))
		return
	}

	support := s.cfg.Issuer
	if err := s.mailer.Send(ctx, mail.Message{
		To:      email,
		Subject: "A new passkey was added to your account",
		Body: fmt.Sprintf("A passkey named %q was added to your account on %s.\n\n"+
			"If you added it, there is nothing to do.\n\n"+
			"If you did NOT add it, someone else may have had access to your "+
			"account. Sign in, remove the passkey you do not recognise, and "+
			"change your password. If you cannot sign in, contact support at %s.\n",
			name, time.Now().UTC().Format("2 January 2006 at 15:04 UTC"), support),
	}); err != nil {
		// Logged AND audited. A required notification that did not go out is an
		// operational fact somebody has to be able to find later, and a log line
		// alone is not durable enough for that.
		s.log.Error("sending an authenticator-bound notice", "err", err,
			"user_id", userID, "correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: "mfa.passkey_notice_failed", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"reason": err.Error()},
		})
	}
}
