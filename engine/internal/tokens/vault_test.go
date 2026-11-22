package tokens

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Against a real transit engine, on a mount of the test's own; see
// keys/vault_test.go.
func TestATokenSignedInATransitEngineVerifies(t *testing.T) {
	addr, token := os.Getenv("SIGNARI_TEST_VAULT_ADDR"), os.Getenv("SIGNARI_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("SIGNARI_TEST_VAULT_ADDR and SIGNARI_TEST_VAULT_TOKEN not set")
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	mount := "signari-test-" + hex.EncodeToString(suffix)
	sys := func(method, body string) {
		t.Helper()
		req, err := http.NewRequest(method, strings.TrimRight(addr, "/")+"/v1/sys/mounts/"+mount,
			bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			t.Fatalf("%s sys/mounts/%s: %d", method, mount, resp.StatusCode)
		}
	}
	sys(http.MethodPost, `{"type":"transit"}`)
	t.Cleanup(func() { sys(http.MethodDelete, "") })
	heldKeysSignTokens(t, heldRing(t, map[string]string{
		"SIGNARI_VAULT_ADDR":          addr,
		"SIGNARI_VAULT_TOKEN":         token,
		"SIGNARI_VAULT_TRANSIT_MOUNT": mount,
	}))
}
