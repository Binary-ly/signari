package httpapi

import (
	"encoding/json"
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
