package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
)

// vaultRing is a keyring given a transit engine the way a node is, by its
// settings, on a mount of the test's own that is removed after it. Run against
// a real server, with SIGNARI_TEST_VAULT_ADDR and SIGNARI_TEST_VAULT_TOKEN, a
// token that may mount and unmount; the transit API has no specification here
// to test a fake against.
func vaultRing(t *testing.T, ref string) *RootKey {
	ring, _ := vaultRingAndMount(t, ref)
	return ring
}

// vaultRingAndMount is vaultRing with a way to call the mount directly, as an
// operator would: path is relative to the mount.
func vaultRingAndMount(t *testing.T, ref string) (*RootKey, func(method, path, body string)) {
	t.Helper()
	addr, token := os.Getenv("SIGNARI_TEST_VAULT_ADDR"), os.Getenv("SIGNARI_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("SIGNARI_TEST_VAULT_ADDR and SIGNARI_TEST_VAULT_TOKEN not set")
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	mount := "signari-test-" + hex.EncodeToString(suffix)
	call := func(method, path, body string) {
		t.Helper()
		req, err := http.NewRequest(method, strings.TrimRight(addr, "/")+"/v1/"+path,
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
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
	}
	call(http.MethodPost, "sys/mounts/"+mount, `{"type":"transit"}`)
	t.Cleanup(func() { call(http.MethodDelete, "sys/mounts/"+mount, "") })

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SIGNARI_ROOT_KEY":            base64.StdEncoding.EncodeToString(secret),
		"SIGNARI_ROOT_KEY_REF":        ref,
		"SIGNARI_VAULT_ADDR":          addr,
		"SIGNARI_VAULT_TOKEN_FILE":    tokenFile,
		"SIGNARI_VAULT_TRANSIT_MOUNT": mount,
	}
	ring, err := LoadRootKeyring(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if ring.backend == nil || ring.backend.Scheme() != "vault-transit" {
		t.Fatal("the keyring was given a transit engine and holds none")
	}
	return ring, func(method, path, body string) { call(method, mount+"/"+path, body) }
}

func TestSigningKeysAreMadeAndKeptInATransitEngine(t *testing.T) {
	heldKeysAreMadeKeptAndRotated(t, vaultRing(t, "vault-test"), "SIGNARI_VAULT_ADDR")
}

func TestAKeyMadeBeforeTheTransitEngineIsSucceededByOneInIt(t *testing.T) {
	heldKeySucceedsASealedOne(t, vaultRing(t, "vault-move"))
}

func TestAKeyTheTransitEngineHoldsIsTheKeyThatWasPublished(t *testing.T) {
	heldKeyMustBeThePublishedOne(t, vaultRing(t, "vault-swap"))
}

func TestARootKeyRotationLeavesTransitKeysAlone(t *testing.T) {
	rootRotationLeavesHeldKeys(t, vaultRing(t, "old"))
}

func TestTheTransitEngineMakesEveryAlgorithm(t *testing.T) {
	everyAlgorithmIsMadeHeld(t, vaultRing(t, "vault-algs"))
}

// A key the engine already holds under a new key's name is refused, not
// adopted: a second create of a held name answers 200 and keeps the old key.
// The kid begins and ends with a hyphen, as one in sixteen do, which a transit
// key's name may not.
func TestATransitKeyIsNeverAdopted(t *testing.T) {
	ring := vaultRing(t, "vault-adopt")
	kid := "-" + NewKID() + "-"
	if _, err := ring.Generate(kid, ES256); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Generate(kid, ES256); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("a name already held was made again: %v", err)
	}
}

// A version added to a key inside Vault is not the key published, so it never
// signs: the published key goes on signing, and verifies.
func TestAVersionAddedInsideTheTransitEngineDoesNotSign(t *testing.T) {
	ring, mount := vaultRingAndMount(t, "vault-version")
	k, err := ring.Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	mount(http.MethodPost, "keys/"+transitName(k.KID())+"/rotate", "")
	reopened, err := ring.backend.Open(k.KID())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("signed after a rotation inside Vault"))
	sig, err := reopened.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing after the key gained a version: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Signer().Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Error("the signature is not by the published key")
	}
}

// Its settings are complete or refused, and it is one place or the other.
func TestATransitEngineIsConfiguredCompletelyOrRefused(t *testing.T) {
	base := map[string]string{
		"SIGNARI_ROOT_KEY":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"SIGNARI_VAULT_ADDR":  "https://vault.internal:8200",
		"SIGNARI_VAULT_TOKEN": "a token",
	}
	for _, c := range []struct {
		name string
		set  map[string]string
		want string
	}{
		{"no token", map[string]string{"SIGNARI_VAULT_TOKEN": ""}, "neither SIGNARI_VAULT_TOKEN"},
		{"two tokens", map[string]string{"SIGNARI_VAULT_TOKEN_FILE": "/nowhere"}, "both set"},
		{"a missing token file", map[string]string{"SIGNARI_VAULT_TOKEN": "", "SIGNARI_VAULT_TOKEN_FILE": "/nowhere"}, "/nowhere"},
		{"plain http across a network", map[string]string{"SIGNARI_VAULT_ADDR": "http://vault.internal:8200"}, "in clear"},
		{"a module as well", map[string]string{"SIGNARI_PKCS11_MODULE": "/lib/module.so"}, "one place"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range c.set {
			env[k] = v
		}
		_, err := LoadRootKeyring(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", c.name, err, c.want)
		}
	}
	base["SIGNARI_VAULT_ADDR"] = "http://127.0.0.1:8200"
	if ring, err := LoadRootKeyring(func(k string) string { return base[k] }); err != nil || ring.backend == nil {
		t.Errorf("plain http on loopback: %v", err)
	}
}
