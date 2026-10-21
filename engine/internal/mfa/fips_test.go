package mfa

import (
	"crypto/fips140"
	"errors"
	"flag"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Under GODEBUG=fips140=only the default TOTP code is HMAC-SHA1, which the
// module refuses, so the package's other tests cannot run there; only the one
// that says what happens instead does.
func TestMain(m *testing.M) {
	flag.Parse()
	if fips140.Enforced() {
		_ = flag.Set("test.run", "UnderFIPSOnly")
	}
	os.Exit(m.Run())
}

// Under fips140=only, checking a SHA-1 code is refused with ErrFIPS rather
// than panicking the request (3.11): HMAC-SHA1 is refused by the module, and a
// person who had enrolled TOTP had their sign-in crash. A SHA-256 code is
// checked, which is what lets a FIPS deployment have authenticator apps; a
// token seed under 112 bits is refused, as the module would panic on it.
func TestTOTPIsRefusedUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTOTPIsRefusedUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	if Available(SHA1) || !Available(SHA256) || !Available(SHA512) {
		t.Errorf("under fips140=only: SHA1 %v, SHA256 %v, SHA512 %v; want only the SHA-2 ones",
			Available(SHA1), Available(SHA256), Available(SHA512))
	}
	if _, err := (Params{}).Verify([]byte("12345678901234567890"), "287082", time.Unix(59, 0),
		DefaultSkew, 0); !errors.Is(err, ErrFIPS) {
		t.Errorf("a SHA-1 code checked under fips140=only: %v, want ErrFIPS", err)
	}
	if _, err := (Params{}).VerifyHOTP([]byte("12345678901234567890"), "287082", 0, HOTPLookAhead); !errors.Is(err, ErrFIPS) {
		t.Errorf("a SHA-1 counter code checked under fips140=only: %v, want ErrFIPS", err)
	}
	p := Params{Algorithm: SHA256, Digits: 8}
	seed := []byte("12345678901234567890123456789012")
	if _, err := p.Verify(seed, "46119246", time.Unix(59, 0), DefaultSkew, 0); err != nil {
		t.Errorf("a SHA-256 code under fips140=only: %v", err)
	}
	if _, err := p.Verify([]byte("0123456789"), "00000000", time.Unix(59, 0), DefaultSkew, 0); !errors.Is(err, ErrFIPS) {
		t.Errorf("an 80-bit seed under fips140=only: %v, want ErrFIPS", err)
	}
}
