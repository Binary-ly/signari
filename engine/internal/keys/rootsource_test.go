package keys

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The root key is read from the variable or from a file that only its owner
// may read, never from both (3.12). It could only come from the environment.
func TestTheRootKeyComesFromTheVariableOrAPrivateFile(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	private := write("root.key", b64+"\n", 0o600)
	shared := write("shared.key", b64, 0o644)
	group := write("group.key", b64, 0o640)
	empty := write("empty.key", "\n", 0o400)

	load := func(env map[string]string) (*RootKey, error) {
		return LoadRootKey(func(k string) string { return env[k] },
			"SIGNARI_ROOT_KEY", "SIGNARI_ROOT_KEY_FILE", "SIGNARI_ROOT_KEY_REF")
	}

	fromEnv, err := load(map[string]string{"SIGNARI_ROOT_KEY": b64, "SIGNARI_ROOT_KEY_REF": "r1"})
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := load(map[string]string{"SIGNARI_ROOT_KEY_FILE": private, "SIGNARI_ROOT_KEY_REF": "r1"})
	if err != nil {
		t.Fatalf("a 0600 key file was refused: %v", err)
	}
	sealed, err := fromEnv.seal([]byte("a signing key"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := fromFile.open(sealed); err != nil || !bytes.Equal(opened, []byte("a signing key")) {
		t.Fatalf("the key read from the file does not open what the variable's sealed: %v", err)
	}

	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"both set", map[string]string{"SIGNARI_ROOT_KEY": b64, "SIGNARI_ROOT_KEY_FILE": private}, "both set"},
		{"world-readable", map[string]string{"SIGNARI_ROOT_KEY_FILE": shared}, "others may read"},
		{"group-readable", map[string]string{"SIGNARI_ROOT_KEY_FILE": group}, "others may read"},
		{"empty", map[string]string{"SIGNARI_ROOT_KEY_FILE": empty}, "empty"},
		{"missing", map[string]string{"SIGNARI_ROOT_KEY_FILE": filepath.Join(dir, "nope")}, "no such file"},
		{"neither", map[string]string{}, "is unset"},
	} {
		if _, err := load(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", c.name, err, c.want)
		}
	}
}
