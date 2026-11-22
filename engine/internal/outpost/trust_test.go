package outpost

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/safedial"
)

// A core whose certificate an internal authority issued is reached through
// SIGNARI_CA_BUNDLE, as every other call out of the binary is. The outpost's client
// once trusted the system's roots alone, so the compose template in docs/outposts.md
// could not reach a core on a private certificate however the bundle was set.
func TestAnOutpostTrustsTheOperatorsCABundle(t *testing.T) {
	core := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"branch","kind":"radius"}`))
	}))
	defer core.Close()
	t.Cleanup(func() { _ = safedial.TrustBundle("") })

	// Without the bundle the core's certificate is nobody's, and the outpost says so.
	c, err := New(core.URL, "token", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an unknown authority was trusted: %v", err)
	}

	bundle := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: core.Certificate().Raw})
	if err := os.WriteFile(bundle, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safedial.TrustBundle(bundle); err != nil {
		t.Fatal(err)
	}
	c, err = New(core.URL, "token", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err != nil {
		t.Fatalf("the core's authority is in SIGNARI_CA_BUNDLE and the outpost refused it: %v", err)
	}
	if c.kind != "radius" {
		t.Fatalf("the core answered and the outpost did not read it: kind %q", c.kind)
	}
}
