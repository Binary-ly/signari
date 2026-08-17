package outbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The delivery guarantees, tested where each can actually be observed.

// The MAC must cover the timestamp, not only the body -- otherwise a captured
// delivery replays forever and a subscriber cannot tell live from stale.
func TestTheSignatureCoversTheTimestamp(t *testing.T) {
	const secret = "whsec_test"
	body := []byte(`{"type":"login.failed"}`)
	at := time.Unix(1786972759, 0)

	got := Sign(secret, at, body)
	ts, v1 := parseSig(t, got)
	if ts != "1786972759" {
		t.Fatalf("t = %q, want the supplied time", ts)
	}

	// Recomputed independently, exactly as docs/events.md tells a subscriber to.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	if want := hex.EncodeToString(mac.Sum(nil)); v1 != want {
		t.Fatalf("v1 = %s, want %s -- the documented scheme and the code disagree",
			v1, want)
	}

	// Change the timestamp alone: the signature must no longer verify. If it
	// still does, the timestamp is decoration and the replay window is a lie.
	_, other := parseSig(t, Sign(secret, at.Add(time.Hour), body))
	if other == v1 {
		t.Fatal("changing the timestamp did not change the signature")
	}
}

// Without a separator, (t=1, body="23") and (t=12, body="3") hash identically.
// A signature ambiguous about what it signed is not a signature.
func TestTheSeparatorMakesTheSignatureUnambiguous(t *testing.T) {
	const secret = "whsec_test"
	a := Sign(secret, time.Unix(1, 0), []byte("23"))
	b := Sign(secret, time.Unix(12, 0), []byte("3"))
	_, av := parseSig(t, a)
	_, bv := parseSig(t, b)
	if av == bv {
		t.Fatal("two different (timestamp, body) pairs produced one signature")
	}
}

// The escape hatch that lets the delivery tests use httptest is also a way to
// turn the SSRF guard off. This is what checks the door is shut in production.
func TestTheDefaultClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a delivery reached a loopback address using the default client")
	}))
	defer srv.Close()

	resp, err := webhookClient().Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the default delivery client connected to loopback; this is an SSRF")
	}
	if !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("err = %v, want the SSRF guard's refusal", err)
	}
}

func parseSig(t *testing.T, header string) (ts, v1 string) {
	t.Helper()
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			v1 = v
		}
	}
	if ts == "" || v1 == "" {
		t.Fatalf("signature %q has no t= or no v1=", header)
	}
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		t.Fatalf("t=%q is not a unix time", ts)
	}
	return ts, v1
}
