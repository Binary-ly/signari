package passwords

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAlgorithmOfNamesWhatTheHasherMade(t *testing.T) {
	for hash, want := range map[string]string{
		"$pbkdf2-sha256$i=600000$c2FsdA$a2V5":          "pbkdf2-sha256",
		"$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA": "argon2id",
	} {
		if got := AlgorithmOf(hash); got != want {
			t.Errorf("%s: %q, want %q", hash, got, want)
		}
	}
}

// No write of a password names its algorithm by hand. Every writer once recorded
// "argon2id" beside whatever it stored, so under FIPS each PBKDF2 hash was labelled
// Argon2id. Read from the code, so a new writer cannot repeat it.
func TestNoPasswordWriteNamesItsAlgorithmByHand(t *testing.T) {
	scanned := 0
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(b)
			if !strings.Contains(src, "password_credentials") {
				return nil
			}
			scanned++
			if strings.Contains(src, "'argon2id'") {
				t.Errorf("%s writes the algorithm 'argon2id' by hand; pass passwords.AlgorithmOf(hash)", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 8 {
		t.Fatalf("only %d files touching password_credentials were read; this check is reading too little", scanned)
	}
}
