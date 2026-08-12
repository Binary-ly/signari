package outbox

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)


func testWorker(t *testing.T) *Worker {
	t.Helper()
	k, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	return &Worker{keys: set, issuer: "https://id.example.test"}
}

func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", raw)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func headerOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	h, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(h, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Every claim OIDC Back-Channel Logout 1.0 §2.4 requires, present and correct.
func TestLogoutTokenHasEveryRequiredClaim(t *testing.T) {
	w := testWorker(t)
	raw, err := w.mintLogoutToken(store.LogoutNotice{ClientID: "webapp", SessionID: "sid-1"})
	if err != nil {
		t.Fatal(err)
	}
	c := claimsOf(t, raw)

	for _, k := range []string{"iss", "aud", "iat", "jti", "events"} {
		if _, ok := c[k]; !ok {
			t.Errorf("missing required claim %q", k)
		}
	}
	if c["iss"] != "https://id.example.test" {
		t.Errorf("iss = %v", c["iss"])
	}
	if c["aud"] != "webapp" {
		t.Errorf("aud = %v -- a token audienced to the wrong client is one an RP must reject", c["aud"])
	}

	// The events member is what distinguishes a logout token from any other JWT
	// with the same claims. An RP that skips it can be handed an ID token.
	ev, ok := c["events"].(map[string]any)
	if !ok {
		t.Fatalf("events is not an object: %T", c["events"])
	}
	if _, ok := ev[BackchannelLogoutEvent]; !ok {
		t.Errorf("events lacks %q; a conformant RP will reject this token", BackchannelLogoutEvent)
	}

	// typ separates it structurally from an ID token.
	if got := headerOf(t, raw)["typ"]; got != "logout+jwt" {
		t.Errorf("typ = %v, want logout+jwt", got)
	}
}

// PROHIBITED by the spec, and for a concrete reason: a logout token carrying a
// nonce can be replayed into an RP's ID-token path, where the nonce is exactly
// what makes it look legitimate.
func TestLogoutTokenNeverCarriesANonce(t *testing.T) {
	w := testWorker(t)
	for _, n := range []store.LogoutNotice{
		{ClientID: "webapp", SessionID: "sid-1"},
		{ClientID: "webapp", Subject: "user-1"},
	} {
		raw, err := w.mintLogoutToken(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, present := claimsOf(t, raw)["nonce"]; present {
			t.Fatal("a logout token carried a nonce -- it can now be replayed as an ID token")
		}
	}
}

func TestLogoutTokenAlwaysIdentifiesWhatToEnd(t *testing.T) {
	w := testWorker(t)

	sidOnly := claimsOf(t, mustMint(t, w, store.LogoutNotice{ClientID: "webapp", SessionID: "sid-1"}))
	if sidOnly["sid"] != "sid-1" {
		t.Errorf("sid-only token lost its sid: %v", sidOnly["sid"])
	}
	if _, present := sidOnly["sub"]; present {
		t.Error("a sid-only notice emitted a sub, which would end MORE sessions than intended")
	}

	subOnly := claimsOf(t, mustMint(t, w, store.LogoutNotice{ClientID: "webapp", Subject: "user-1"}))
	if subOnly["sub"] != "user-1" {
		t.Errorf("sub-only token lost its sub: %v", subOnly["sub"])
	}
	if _, present := subOnly["sid"]; present {
		t.Error("a sub-only notice emitted a sid it does not have")
	}

	// A notice naming neither must be REFUSED, not signed. A relying party
	// receiving one has a valid instruction to end nothing, cannot tell it apart
	// from a logout it handled, and the delivery is recorded as a success while a
	// session survives.
	if _, err := w.mintLogoutToken(store.LogoutNotice{ClientID: "webapp"}); err == nil {
		t.Fatal("minted a logout token naming neither a sid nor a sub")
	}
}

// Replay protection depends on jti being unique per token. A repeated jti means
// an RP that dedupes correctly will DROP a legitimate second logout.
func TestEveryLogoutTokenHasAUniqueJTI(t *testing.T) {
	w := testWorker(t)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c := claimsOf(t, mustMint(t, w, store.LogoutNotice{ClientID: "webapp", SessionID: "sid-1"}))
		jti, _ := c["jti"].(string)
		if jti == "" {
			t.Fatal("a logout token had no jti; an RP cannot dedupe replays")
		}
		if seen[jti] {
			t.Fatalf("jti %q was reused -- a conformant RP would silently drop this logout", jti)
		}
		seen[jti] = true
	}
}

// exp is optional in the spec, but its absence leaves a signed instruction that
// is valid forever. A captured token would end sessions indefinitely.
func TestLogoutTokenExpiresQuickly(t *testing.T) {
	w := testWorker(t)
	c := claimsOf(t, mustMint(t, w, store.LogoutNotice{ClientID: "webapp", SessionID: "sid-1"}))

	exp, ok := c["exp"].(float64)
	if !ok {
		t.Fatal("no exp: this token would be replayable forever")
	}
	iat, _ := c["iat"].(float64)
	life := time.Duration(exp-iat) * time.Second
	if life <= 0 || life > 5*time.Minute {
		t.Errorf("lifetime %v: a logout token is consumed immediately or not at all, "+
			"and a long expiry only widens the replay window", life)
	}
}

func mustMint(t *testing.T, w *Worker, n store.LogoutNotice) string {
	t.Helper()
	raw, err := w.mintLogoutToken(n)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
