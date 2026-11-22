package passwords

import (
	"context"
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
)

// From libxcrypt 4.5.2's crypt_gensalt and crypt, at costs 1, 3, 5 (every distribution's
// default) and 7, so that what is checked here is agreement with the C library that wrote
// these lines of /etc/shadow, and not with the module checking itself.
var yescryptVectors = []struct{ password, stored string }{
	{`correct horse battery staple`, `$y$j75$aSCccA8ziT52XOmLczA/v0$MGDssiFGMo8n7emoQPq4j.WBDTyBWCPAcuCuqQ7Dw..`},
	{`p`, `$y$j75$/hwbfHAxBAvVq5qp61/8u1$OBRC/75Ya3k6vUOaCUkP7IoeJoTo8ECXqHqyHq6Kk02`},
	{`pa$$w0rd:with$symbols`, `$y$j75$Rsa9oRiOs/LPHXtU.Fq551$A3p0TzzAODM/BMsuRkib8x9ANHA.IiPf.058eLxJPF8`},
	{`pässwörd`, `$y$j75$sfZk9r/Pyyh36sC.nbStU.$2/T9rpi8bfClGj1rJtwMj6VLI43hGmT.j.IZfov8Mu2`},
	{`correct horse battery staple`, `$y$j7T$XU5HbH4EJxNlid6vUKX4Y.$1UV8xwhoAkB31kiHbwHBmb7eRv5Y4L80KoagHz6UEy1`},
	{`p`, `$y$j7T$K5M3NkHjNz4rTEUgjV0d0/$Z8AnzfF84tD.Ds6ap.w/a1VlqeQklfzmvdoj3aPcOb8`},
	{`pa$$w0rd:with$symbols`, `$y$j7T$e0STrGozx966VQ4rkUzNW1$3oYZc4Qca05JjFoedVgNvp9UIFkUD4WqQtnKEEehfeA`},
	{`pässwörd`, `$y$j7T$6H87yqxo0t87Duxa/wVE4/$aOjUnUIJCkm0B1bviqywSY/dBp4A51liP7Hwx7o84r5`},
	{`correct horse battery staple`, `$y$j9T$4cToiz86Uw5Cgzr0.LQNE.$pwAcjE/PI1ujEhmZa1eu29haXGtj0Kkc9YBE7gj4X50`},
	{`p`, `$y$j9T$XViuZS9NrehGkmegAbH2e1$EuCG0wztP5rbvSmm7f.aBtyMRPIcjDGLoO99xWygDD1`},
	{`pa$$w0rd:with$symbols`, `$y$j9T$yynJgJK8kAjlTfWxu72vj.$b132dpX1QdOpqjdYAfDkmFlCG4ullYi77mQ7im/Nwv6`},
	{`pässwörd`, `$y$j9T$35w1CPsti4M1TDntfU28r0$u7hv1TjAZ2o7KXaiwd9PEtTk4zsl9u.ePUHm8RTARv4`},
	{`correct horse battery staple`, `$y$jBT$Vq.zVh6tvWp9Zv1eHIBhi1$xQUgJk/iAT1jwcbIDRDmFQTPI4gobV2zPLGbrtrKvJA`},
	{`p`, `$y$jBT$dHwIjVKdCpBorNRKLTqq3.$5haljF2lpPJZtA/u1vU3huWfxNo0JDiEq/VH55zEmS2`},
	{`pa$$w0rd:with$symbols`, `$y$jBT$Vt/6VE8fuvbtUlkPqjcj81$jkvfdX8tIsRco3czEVyG8MkoVHyH3.EIWZPFS6.ROFC`},
	{`pässwörd`, `$y$jBT$BFzNz4kd2rCMJfmcwkuvw/$QKhpezg4EJBZVuHKT7vEpKQGdMPv0uMiP/GZdydx2RB`},
}

// The module panics on the short keys yescrypt's HMAC starts from, and that would be a
// sign-in panicking, so it is refused first, as the MD5 formats are.
func TestYescryptIsRefusedUnderTheModule(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("only under fips140=only")
	}
	v := yescryptVectors[0]
	if err := verifyYescrypt(v.stored, v.password); !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "reset the password") {
		t.Errorf("it answered %v", err)
	}
}

func TestYescryptAgreesWithLibxcrypt(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("refused under fips140=only")
	}
	for _, v := range yescryptVectors {
		if err := verifyYescrypt(v.stored, v.password); err != nil {
			t.Errorf("%.30s did not verify %q: %v", v.stored, v.password, err)
		}
		if err := verifyYescrypt(v.stored, v.password+"x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("%.30s verified the wrong password: %v", v.stored, err)
		}
	}
}

// The way an imported hash is used: a sign-in verifies it and asks for a rehash.
func TestYescryptVerifiesAndIsRehashed(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("refused under fips140=only")
	}
	h := NewHasher(MemoryBudgetMiB)
	v := yescryptVectors[8]
	if !CanVerify(v.stored) {
		t.Fatal("the default cost is not verifiable")
	}
	if rehash, err := h.Verify(context.Background(), v.stored, v.password); err != nil || !rehash {
		t.Fatalf("rehash %v, %v; want it to verify and move to Argon2id", rehash, err)
	}
	if _, err := h.Verify(context.Background(), v.stored, "not it"); err == nil {
		t.Fatal("the wrong password verified")
	}
}

// What it would cost is read from the hash, for the budget and the refusal alike.
func TestAYescryptHashSaysWhatItCosts(t *testing.T) {
	for stored, want := range map[string]int64{
		"$y$j75$s$h": 1 << 10,  // N=1024, r=8: 1 MiB
		"$y$j7T$s$h": 4 << 10,  // N=1024, r=32
		"$y$j9T$s$h": 16 << 10, // N=4096, r=32: the default
		"$y$jBT$s$h": 64 << 10,
	} {
		if got := memoryKiB(stored); got != want {
			t.Errorf("%s needs %d KiB, want %d", stored, got, want)
		}
	}
}

func TestAYescryptHashThisCannotCheckIsNotImported(t *testing.T) {
	for name, stored := range map[string]string{
		// N=2^17, r=20: 335 MiB, which fits the 512 MiB the process allows for all
		// verifications and still is not one to spend on a stranger's hash.
		"a cost above the ceiling": "$y$jEH$saltsaltsaltsaltsaltsa$hash",
		"a cost above the budget":  "$y$jFT$saltsaltsaltsaltsaltsa$hash", // N=2^18, r=32: 1 GiB
		"a long setting":           "$y$j9T4$saltsaltsaltsaltsaltsa$hash",
		"other flags":              "$y$k9T$saltsaltsaltsaltsaltsa$hash",
		"no hash":                  "$y$j9T$saltsaltsaltsaltsaltsa",
		"an N outside":             "$y$j.T$saltsaltsaltsaltsaltsa$hash",
		"nothing":                  "$y$",
	} {
		if CanVerify(stored) {
			t.Errorf("%s was reported verifiable", name)
		}
		if err := verifyYescrypt(stored, "x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s answered %v", name, err)
		}
	}
}

func TestMalformedYescryptNeverPasses(t *testing.T) {
	h := NewHasher(MemoryBudgetMiB)
	for _, bad := range []string{"$y$j9T$$", "$y$j9T$!!!$x", "$y$j75$aSCccA8ziT52XOmLczA/v0$", "$y$j75$aSCccA8ziT52XOmLczA/v0$wrong"} {
		if _, err := h.Verify(context.Background(), bad, "anything"); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
