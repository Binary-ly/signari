package passwords

import (
	"crypto/fips140"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/openwall/yescrypt-go"
)

// yescrypt ($y$), the /etc/shadow default on current distributions. A memory-hard hash
// with a good many parts, so this is not a hand-written copy: it is the Go module of the
// scheme's own author, held here to libxcrypt's output (yescrypt_test.go).

// yescryptItoa is crypt(3)'s alphabet, in which a setting spells its cost.
const yescryptItoa = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// yescryptMaxMemoryKiB is as far as one imported hash goes, the same reasoning as scrypt's:
// a hash in an import file is a stranger's cost setting. libxcrypt's default, j9T, takes
// 16 MiB, and the module would otherwise go on to a gigabyte.
const yescryptMaxMemoryKiB = 256 << 10

// yescryptCost reads N and r out of `$y$j<N><r>$...`, the only form libxcrypt generates
// and the only one the module reads. ok is false for anything else, a hash this cannot
// check being refused at the import rather than at a person's sign-in.
func yescryptCost(stored string) (kib int64, ok bool) {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || len(parts[2]) != 3 || parts[2][0] != 'j' {
		return 0, false
	}
	log2 := strings.IndexByte(yescryptItoa, parts[2][1]) + 1
	r := strings.IndexByte(yescryptItoa, parts[2][2]) + 1
	if log2 < 10 || log2 > 18 || r < 1 || r > 32 {
		return 0, false
	}
	// Like scrypt's V, 128·N·r bytes.
	return (int64(1) << log2) * int64(r) * 128 / 1024, true
}

func yescryptRefusal(stored string) error {
	kib, ok := yescryptCost(stored)
	if !ok {
		return fmt.Errorf("that yescrypt setting is not one libxcrypt generates")
	}
	if kib > yescryptMaxMemoryKiB {
		return fmt.Errorf("yescrypt needing %d MiB is above the %d MiB an imported hash may take", kib/1024, yescryptMaxMemoryKiB/1024)
	}
	return nil
}

func verifyYescrypt(stored, password string) error {
	// It starts its HMAC from a key the module will not take, and panics rather than say.
	if fips140.Enforced() {
		return fmt.Errorf("%w: this password was imported as a yescrypt hash, which FIPS 140-only "+
			"mode refuses; reset the password", ErrMismatch)
	}
	if err := yescryptRefusal(stored); err != nil {
		return fmt.Errorf("%w: %v", ErrMismatch, err)
	}
	computed, err := yescrypt.Hash([]byte(password), []byte(stored))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMismatch, err)
	}
	if subtle.ConstantTimeCompare(computed, []byte(stored)) != 1 {
		return ErrMismatch
	}
	return nil
}
