package httpapi

import (
	"encoding/base64"
	"net/http"

	"signari.dev/engine/internal/store"
)

// WebAuthn Level 3 signal methods — the half that lives on the server.
//
// # The bug this fixes
//
// An administrator deletes somebody's passkey. The record is gone here; the
// credential is still on the authenticator, and the platform goes on offering
// it at every sign-in. The user picks it, it fails, and there is nothing in the
// interface to explain why. On a password manager syncing across four devices,
// that stale entry follows them everywhere. Every identity provider has this
// bug, because until Level 3 there was no way to tell an authenticator that a
// credential is no longer known.
//
// # What Level 3 added
//
//	signalUnknownCredential()        one credential is not recognised
//	signalAllAcceptedCredentials()   here is the complete list; forget the rest
//	signalCurrentUserDetails()       the name shown for this account has changed
//
// Candidate Recommendation, 26 May 2026.
//
// # Why the server needs an endpoint at all
//
// These are browser APIs, but the browser cannot know which credentials the
// server still accepts -- that is the entire point. So the page has to ask, and
// this is what it asks.
//
// # Why it needs a session and returns nothing without one
//
// The list of credential ids for an account is a fingerprint of that account:
// how many authenticators, and which. Handing it to an unauthenticated caller
// would turn a bug fix into a user-enumeration endpoint. It answers only for
// the account whose session is presenting.

// signalPayload is what the page needs to call the signal methods.
//
// Field names are the specification's, so the page can pass this object
// straight through rather than transcribing it -- transcription is where a
// field name gets mistyped and the call silently does nothing.
type signalPayload struct {
	RPID string `json:"rpId"`
	// UserID is the WebAuthn user handle, base64url, as the API expects.
	UserID string `json:"userId"`
	// AllAcceptedCredentialIds is the COMPLETE list. An authenticator holding
	// anything not in it should forget it. Empty means "none of them are valid
	// any more", which is a meaningful answer and not the same as no answer.
	AllAcceptedCredentialIds []string `json:"allAcceptedCredentialIds"`
	// Name and DisplayName for signalCurrentUserDetails.
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// handlePasskeySignal returns what the browser needs to bring an authenticator
// back in step with what this server actually accepts.
func (s *Server) handlePasskeySignal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		// No session, no answer. Not an error page: the caller is a script, and
		// the honest response to "who are you" is 401 rather than a login form.
		writeJSONResponse(w, http.StatusUnauthorized,
			map[string]any{"error": "sign in first"})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError,
			map[string]any{"error": "internal error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	creds, err := store.CredentialsForUser(ctx, tx, userID)
	if err != nil {
		s.log.Error("listing passkeys for a signal", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError,
			map[string]any{"error": "internal error"})
		return
	}

	// The relying party is read per request for the same reason the ceremony
	// path reads it: rp_id is instance configuration an operator can change
	// while the server runs, and a signal naming the wrong one does nothing.
	rp, err := s.relyingParty(ctx, orgID)
	if err != nil {
		// No rp_id means passkeys are not configured here, which is a
		// deployment choice rather than a fault. Answered as "not available"
		// so the page skips quietly -- a 500 would put an error in the console
		// of every sign-in on a deployment that simply does not use passkeys.
		writeJSONResponse(w, http.StatusNotImplemented,
			map[string]any{"error": "passkeys are not configured for this instance"})
		return
	}

	out := signalPayload{
		RPID: rp.RPID(),
		// Always an empty slice rather than nil: `null` and `[]` mean different
		// things to the API, and "the server sent null" is not a state the page
		// should have to reason about.
		AllAcceptedCredentialIds: []string{},
	}
	for _, c := range creds {
		out.AllAcceptedCredentialIds = append(out.AllAcceptedCredentialIds,
			base64.RawURLEncoding.EncodeToString(c.CredentialID))
	}

	// The same identity the ceremony uses. Reading it from a second place would
	// eventually disagree, and a userId that does not match the one the
	// credential was created with makes every signal a no-op -- silently.
	var handle []byte
	var email, username string
	if err := tx.QueryRow(ctx, `
		SELECT user_handle, COALESCE(email,''), COALESCE(username,'')
		FROM core.users WHERE id = $1::uuid AND org_id = $2::uuid`,
		userID, orgID).Scan(&handle, &email, &username); err != nil {
		s.log.Error("reading the passkey identity for a signal", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError,
			map[string]any{"error": "internal error"})
		return
	}
	out.UserID = base64.RawURLEncoding.EncodeToString(handle)
	out.Name = email
	if out.Name == "" {
		out.Name = username
	}
	out.DisplayName = username
	if out.DisplayName == "" {
		out.DisplayName = out.Name
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSONResponse(w, http.StatusOK, out)
}

// passkeySignalJS is the page-side half.
//
// Served rather than inlined so it carries a stable URL and can be cached, and
// so the CSP does not need to permit inline script for it.
//
// Every call is wrapped: the signal methods are new enough that a browser
// without them is ordinary, not an error, and a page that throws on an older
// browser has made a working sign-in worse in order to fix a stale entry.
const passkeySignalJS = `//	WebAuthn Level 3 signal methods.
//
//	Brings the authenticator back in step with what the server accepts, so a
//	passkey deleted here stops being offered there.
(async function () {
  if (!window.PublicKeyCredential) return;
  let r;
  try {
    r = await fetch("/account/passkeys/signal", { credentials: "same-origin" });
  } catch (e) { return; }
  if (!r.ok) return;   //	401 = not signed in, 501 = passkeys not configured
  const s = await r.json();

  //	Each is attempted separately. They landed in browsers at different times,
  //	and one being absent must not stop the others running.
  if (PublicKeyCredential.signalAllAcceptedCredentials) {
    try {
      await PublicKeyCredential.signalAllAcceptedCredentials({
        rpId: s.rpId,
        userId: s.userId,
        allAcceptedCredentialIds: s.allAcceptedCredentialIds,
      });
    } catch (e) { /* an authenticator that declines is not our problem */ }
  }
  if (PublicKeyCredential.signalCurrentUserDetails && s.name) {
    try {
      await PublicKeyCredential.signalCurrentUserDetails({
        rpId: s.rpId, userId: s.userId,
        name: s.name, displayName: s.displayName,
      });
    } catch (e) { /* as above */ }
  }
})();
`

// handlePasskeySignalJS serves the script.
func (s *Server) handlePasskeySignalJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(passkeySignalJS))
}
