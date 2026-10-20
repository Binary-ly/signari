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

// Under GODEBUG=fips140=only every TOTP code is HMAC-SHA1, which the module
// refuses, so the package's other tests cannot run there; only the one that
// says what happens instead does.
func TestMain(m *testing.M) {
	flag.Parse()
	if fips140.Enforced() {
		_ = flag.Set("test.run", "UnderFIPSOnly")
	}
	os.Exit(m.Run())
}

// Under fips140=only, checking a code is refused with ErrFIPS rather than
// panicking the request (3.11): HMAC-SHA1 is refused by the module, and a
// person who had enrolled TOTP had their sign-in crash.
func TestTOTPIsRefusedUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTOTPIsRefusedUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	if Available() {
		t.Error("TOTP reports itself available under fips140=only")
	}
	if _, err := Verify([]byte("12345678901234567890"), "287082", time.Unix(59, 0),
		DefaultDigits, DefaultPeriod, DefaultSkew, 0); !errors.Is(err, ErrFIPS) {
		t.Errorf("a code checked under fips140=only: %v, want ErrFIPS", err)
	}
}
