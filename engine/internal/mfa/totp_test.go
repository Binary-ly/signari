package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// def is the default authenticator's parameters.
var def = Params{}

// The RFC 6238 Appendix B test vectors, verbatim.
//
// This is the only assertion that proves the implementation is TOTP rather than
// something that merely round-trips against itself. A home-grown OTP that agrees
// with its own verifier but not with Google Authenticator fails in the worst
// possible way: enrolment appears to work and every subsequent login is refused,
// with the user's phone showing a different number and nobody able to say why.
//
// The SHA-256 and SHA-512 columns were computed with Python's hmac module, an
// implementation independent of this one, from ASCII digit seeds as long as
// each hash's output; the same computation reproduces the SHA-1 column.
func TestRFC6238Vectors(t *testing.T) {
	seeds := map[Algorithm][]byte{
		SHA1:   []byte("12345678901234567890"),
		SHA256: []byte("12345678901234567890123456789012"),
		SHA512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	for _, tc := range []struct {
		unix               int64
		sha1, sha256, s512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	} {
		for alg, want := range map[Algorithm]string{SHA1: tc.sha1, SHA256: tc.sha256, SHA512: tc.s512} {
			p := Params{Algorithm: alg, Digits: 8}
			c := Counter(time.Unix(tc.unix, 0), DefaultPeriod)
			if got := p.Code(seeds[alg], c); got != want {
				t.Errorf("%s T=%d: got %s, want %s", alg, tc.unix, got, want)
			}
		}
	}
	// The package-level Code is the SHA-1 one.
	if got := Code(seeds[SHA1], Counter(time.Unix(59, 0), DefaultPeriod), 8); got != "94287082" {
		t.Errorf("Code at T=59: got %s", got)
	}
}

// Counter-based codes (RFC 4226), computed with Python's hmac as above:
// counters 0 to 9 of the ASCII seed "12345678901234567890".
func TestHOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	for c, w := range want {
		if got := def.Code(secret, int64(c)); got != w {
			t.Errorf("counter %d: got %s, want %s", c, got, w)
		}
	}
	// A token last accepted at counter 2, pressed twice in a pocket: the code
	// for 5 is within the look-ahead and moves the counter there.
	got, err := def.VerifyHOTP(secret, want[5], 2, HOTPLookAhead)
	if err != nil || got != 5 {
		t.Fatalf("counter 5 after 2: %d, %v", got, err)
	}
	// Spent: the last accepted is a replay, which is not charged as a guess;
	// further behind is wrong.
	if _, err := def.VerifyHOTP(secret, want[5], 5, HOTPLookAhead); !errors.Is(err, ErrReplay) {
		t.Errorf("counter 5 again after 5: %v, want ErrReplay", err)
	}
	if _, err := def.VerifyHOTP(secret, want[2], 5, HOTPLookAhead); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("counter 2 after 5: %v, want ErrInvalidCode", err)
	}
	// Beyond the look-ahead: refused, so a token pressed a hundred times needs
	// resynchronising rather than accepting codes far ahead.
	if _, err := def.VerifyHOTP(secret, want[9], 2, 3); err == nil {
		t.Error("a code seven ahead was accepted with a look-ahead of three")
	}
}

// A leading zero is part of the code. Trimming it is a classic bug that fails
// for roughly one user in ten, intermittently, and looks like a clock problem.
func TestCodesAreZeroPadded(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := Code(secret, Counter(time.Unix(1111111109, 0), DefaultPeriod), 8); got != "07081804" {
		t.Fatalf("got %q, want the zero-padded 07081804", got)
	}
	for i := int64(0); i < 500; i++ {
		if got := Code(secret, i, 6); len(got) != 6 {
			t.Fatalf("counter %d produced %q, which is not 6 digits", i, got)
		}
	}
}

func TestVerifyAcceptsTheCurrentCode(t *testing.T) {
	for _, p := range []Params{def, {Algorithm: SHA256, Digits: 8, Period: 60 * time.Second}, {Algorithm: SHA512}} {
		raw, _, err := GenerateSecret(p.Algorithm)
		if err != nil {
			t.Fatal(err)
		}
		if want := p.Algorithm.withDefault().SecretBytes(); len(raw) != want {
			t.Errorf("%s: a %d-byte secret, want %d", p.Algorithm, len(raw), want)
		}
		now := time.Now()
		period := p.withDefaults().Period
		code := p.Code(raw, Counter(now, period))

		c, err := p.Verify(raw, code, now, DefaultSkew, 0)
		if err != nil {
			t.Fatalf("%+v: a freshly generated code was rejected: %v", p, err)
		}
		if c != Counter(now, period) {
			t.Errorf("matched counter %d, want %d", c, Counter(now, period))
		}
		// The same secret under another algorithm is another code.
		if p.Algorithm == SHA256 || p.Algorithm == SHA512 {
			other := Params{Algorithm: SHA1, Digits: p.Digits, Period: p.Period}
			if _, err := other.Verify(raw, code, now, DefaultSkew, 0); err == nil {
				t.Errorf("%s's code was accepted as SHA1's", p.Algorithm)
			}
		}
	}
}

// THE test that separates a real second factor from a decorative one.
//
// A TOTP code is valid for its whole window. Without a strictly advancing
// counter, anyone who sees a code -- over a shoulder, through a phishing proxy,
// in a screenshot -- can reuse it for the remainder of that window. Most
// implementations do not do this.
func TestReplayIsRefused(t *testing.T) {
	raw, _, _ := GenerateSecret(SHA1)
	now := time.Now()
	code := Code(raw, Counter(now, DefaultPeriod), DefaultDigits)

	used, err := def.Verify(raw, code, now, DefaultSkew, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The same code, the same window, with the counter now recorded.
	_, err = def.Verify(raw, code, now, DefaultSkew, used)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("a used code was accepted again (err = %v)", err)
	}

	// And an OLDER window must not be accepted either -- an attacker holding a
	// code from the previous step must not be able to spend it after a newer one
	// has been used.
	older := Code(raw, Counter(now, DefaultPeriod)-1, DefaultDigits)
	if _, err := def.Verify(raw, older, now, DefaultSkew, used); err == nil {
		t.Error("a code from an earlier window was accepted after a later one")
	}
}

// Clock skew between a phone and a server is normal; the adjacent windows must
// work or a meaningful share of users simply cannot sign in.
func TestAdjacentWindowsAreAccepted(t *testing.T) {
	raw, _, _ := GenerateSecret(SHA1)
	now := time.Now()

	for _, offset := range []time.Duration{-DefaultPeriod, DefaultPeriod} {
		code := Code(raw, Counter(now.Add(offset), DefaultPeriod), DefaultDigits)
		if _, err := def.Verify(raw, code, now, DefaultSkew, 0); err != nil {
			t.Errorf("a code %v out of step was rejected: %v", offset, err)
		}
	}

	// Two windows out is beyond the tolerance and must fail, or the code stays
	// valid for two and a half minutes.
	far := Code(raw, Counter(now.Add(3*DefaultPeriod), DefaultPeriod), DefaultDigits)
	if _, err := def.Verify(raw, far, now, DefaultSkew, 0); err == nil {
		t.Error("a code three windows away was accepted")
	}
}

func TestMalformedCodesAreRejected(t *testing.T) {
	raw, _, _ := GenerateSecret(SHA1)
	now := time.Now()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "12 34 56", "------"} {
		if _, err := def.Verify(raw, code, now, DefaultSkew, 0); err == nil {
			t.Errorf("%q was accepted as a code", code)
		}
		if _, err := def.VerifyHOTP(raw, code, 0, HOTPLookAhead); err == nil {
			t.Errorf("%q was accepted as a counter code", code)
		}
	}
}

// What an organisation may choose is what apps and tokens display.
func TestParamsAreChecked(t *testing.T) {
	for _, p := range []Params{
		{Algorithm: SHA1, Digits: 6, Period: 30 * time.Second},
		{Algorithm: SHA256, Digits: 8, Period: 60 * time.Second},
		{Algorithm: SHA512, Digits: 6, Period: 30 * time.Second},
	} {
		if err := p.Check(); err != nil {
			t.Errorf("%+v refused: %v", p, err)
		}
	}
	for _, p := range []Params{
		{Algorithm: "MD5", Digits: 6, Period: 30 * time.Second},
		{Algorithm: SHA1, Digits: 7, Period: 30 * time.Second},
		{Algorithm: SHA1, Digits: 6, Period: 45 * time.Second},
		{Algorithm: "sha1", Digits: 6, Period: 30 * time.Second},
	} {
		if err := p.Check(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

// A secret typed in by hand arrives spaced, lower-cased, or padded.
func TestSecretDecodingIsForgiving(t *testing.T) {
	raw, enc, _ := GenerateSecret(SHA1)
	for _, variant := range []string{enc, strings.ToLower(enc), spaced(enc), enc + "==="} {
		got, err := DecodeSecret(variant)
		if err != nil {
			t.Fatalf("%q was refused: %v", variant, err)
		}
		if string(got) != string(raw) {
			t.Errorf("%q decoded to the wrong bytes", variant)
		}
	}
	// But a secret too short to be safe is refused rather than quietly used.
	if _, err := DecodeSecret("AAAA"); err == nil {
		t.Error("a 2-byte secret was accepted")
	}
}

func spaced(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// The URI is what the authenticator app scans; a malformed one produces an
// unlabelled entry the user cannot identify among twenty others.
func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("Signari", "alice@example.test", "JBSWY3DPEHPK3PXP", Params{Digits: 6})

	for _, want := range []string{
		"otpauth://totp/Signari:alice@example.test",
		"secret=JBSWY3DPEHPK3PXP",
		"issuer=Signari",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI is missing %q:\n  %s", want, uri)
		}
	}
	// What the organisation chose is what the app is told.
	uri = ProvisioningURI("Signari", "alice", "JBSWY3DPEHPK3PXP",
		Params{Algorithm: SHA256, Digits: 8, Period: 60 * time.Second})
	for _, want := range []string{"algorithm=SHA256", "digits=8", "period=60"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI is missing %q:\n  %s", want, uri)
		}
	}

	// A colon in the issuer or account breaks the label grammar, and Google
	// Authenticator misparses it into the wrong fields rather than refusing it.
	dirty := ProvisioningURI("Sign:ari", "al:ice", "AAAA", Params{Digits: 6})
	if strings.Count(dirty, ":") != 2 { // scheme + label separator only
		t.Errorf("colons were not sanitised out of the label: %s", dirty)
	}
}
