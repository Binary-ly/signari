package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The signal payload's shape is load-bearing.
//
// These are browser APIs with fixed parameter names. A field spelled slightly
// wrong does not error -- the call simply does nothing, on every browser, for
// every user, silently. There is no failure to notice, which is why the shape
// is asserted rather than trusted.

func TestTheSignalPayloadUsesTheSpecificationsFieldNames(t *testing.T) {
	raw, err := json.Marshal(signalPayload{
		RPID:                     "example.com",
		UserID:                   "dXNlcg",
		AllAcceptedCredentialIds: []string{"Y3JlZA"},
		Name:                     "alice@example.com",
		DisplayName:              "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// Exactly these, spelled exactly this way. WebAuthn L3 §5.1.
	for _, want := range []string{
		"rpId", "userId", "allAcceptedCredentialIds", "name", "displayName",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("the payload has no %q. The signal methods take fixed "+
				"parameter names; a wrong one does not error, the call just "+
				"does nothing -- silently, everywhere", want)
		}
	}
	// And nothing extra, because an unexpected key is a sign the struct and the
	// specification have drifted.
	if len(got) != 5 {
		t.Errorf("the payload has %d fields, want exactly 5: %v", len(got), got)
	}
}

// An empty list is a real instruction -- "forget every credential you hold for
// me" -- and must serialise as [] rather than null.
func TestAnEmptyCredentialListIsNotNull(t *testing.T) {
	raw, err := json.Marshal(signalPayload{
		RPID: "example.com", UserID: "dXNlcg",
		AllAcceptedCredentialIds: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"allAcceptedCredentialIds":null`) {
		t.Fatal("an empty credential list serialised as null. `null` and `[]` " +
			"mean different things to the API, and a user whose last passkey " +
			"was deleted is exactly the case that must work")
	}
	if !strings.Contains(string(raw), `"allAcceptedCredentialIds":[]`) {
		t.Fatalf("expected an empty array, got %s", raw)
	}
}

// The script must not throw on a browser without the methods. A page that
// breaks sign-in in order to tidy a stale entry has made things worse.
func TestTheScriptGuardsEveryCallAndEveryFailure(t *testing.T) {
	for _, guard := range []string{
		"if (!window.PublicKeyCredential) return;",
		"if (PublicKeyCredential.signalAllAcceptedCredentials)",
		"if (PublicKeyCredential.signalCurrentUserDetails",
		"if (!r.ok) return;",
	} {
		if !strings.Contains(passkeySignalJS, guard) {
			t.Errorf("the script is missing the guard %q", guard)
		}
	}
	// Both calls are individually wrapped: they landed in browsers at different
	// times, and one being absent must not stop the other.
	if n := strings.Count(passkeySignalJS, "try {"); n < 3 {
		t.Errorf("only %d try blocks; each network call and each signal method "+
			"needs its own", n)
	}
	// It must not be an inline handler -- the CSP forbids inline script, and a
	// version that only works with 'unsafe-inline' would push us to weaken it.
	if strings.Contains(passkeySignalJS, "<script") {
		t.Error("the script contains markup; it is served as a file, not inlined")
	}
}

// §5.1.10.2: a refused assertion must name the credential, so the browser can
// signal it and the authenticator stops offering it.
//
// This is the half `signalAllAcceptedCredentials` cannot cover: that method
// needs a session, and a user whose ONLY passkey was deleted can never get one
// -- the single credential they hold is the one that cannot sign them in.
func TestARefusedAssertionNamesTheCredential(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).refuseWithUnknownCredential(w, "example.com", []byte{1, 2, 3, 4})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	sig, ok := body["signal_unknown_credential"].(map[string]any)
	if !ok {
		t.Fatalf("no signal_unknown_credential in %v", body)
	}
	// The dictionary's field names, exactly. §5.1.10.2's UnknownCredentialOptions.
	if sig["rpId"] != "example.com" {
		t.Errorf("rpId = %v", sig["rpId"])
	}
	// Base64URLString, unpadded.
	if sig["credentialId"] != "AQIDBA" {
		t.Errorf("credentialId = %v, want base64url of the presented bytes", sig["credentialId"])
	}

	// With nothing to name, the signal must be ABSENT -- telling a browser to
	// forget a credential we could not identify would forget the wrong one.
	w = httptest.NewRecorder()
	(&Server{}).refuseWithUnknownCredential(w, "example.com", nil)
	body = nil
	_ = json.NewDecoder(w.Body).Decode(&body)
	if _, present := body["signal_unknown_credential"]; present {
		t.Fatal("a refusal with no identified credential still told the browser " +
			"to forget one")
	}
}

// signalUnknownCredential tells an authenticator to DELETE a credential, so it
// must only be sent for a credential we genuinely do not hold.
//
// WebAuthn L3 §5.1.10.2 exists for one case: a passkey the server has deleted,
// which the authenticator keeps offering. The cure is destructive, and the
// failure it cures is indistinguishable at the top of an assertion handler from
// every other failure -- a user-verification timeout, a sign-count regression, a
// corrupted signature.
//
// The credential id used to be captured unconditionally, before the user was
// resolved and before any signature was checked, so ANY failed assertion came
// back with a deletion instruction. For somebody whose only passkey it was, that
// is a self-inflicted lockout produced by the feature meant to prevent one.
//
// The fix is a `held` flag set while the user's credential list is in hand. This
// test pins the shape, because the alternative -- driving a full WebAuthn
// assertion failure against a real authenticator -- is a fixture this package
// does not have, and the bug was a missing condition rather than a wrong
// computation.
func TestAKnownCredentialIsNeverSignalledAsUnknown(t *testing.T) {
	src := readSource(t, "passkey.go")

	// The list must actually be consulted.
	if !strings.Contains(src, "u.WebAuthnCredentials()") {
		t.Error("the assertion handler never inspects the user's credential " +
			"list, so it cannot tell a credential we no longer hold from one " +
			"that simply failed to verify")
	}
	if !strings.Contains(src, "held = true") {
		t.Error("nothing records that the presented credential is one we hold")
	}
	// And the refusal must branch on it.
	if !strings.Contains(src, "if held {") {
		t.Fatal("the refusal path does not check whether the credential is held, " +
			"so a bad signature against a VALID passkey answers with " +
			"signal_unknown_credential and the authenticator deletes it")
	}

	// The guard has to sit before the signal, not after.
	heldAt := strings.Index(src, "if held {")
	signalAt := strings.Index(src, "s.refuseWithUnknownCredential(w, rp.RPID(), presentedID)")
	if heldAt < 0 || signalAt < 0 || heldAt > signalAt {
		t.Error("the `held` check does not precede the unknown-credential signal")
	}
}
