package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The RFC 6238 Appendix B test vectors, verbatim.
//
// This is the only assertion that proves the implementation is TOTP rather than
// something that merely round-trips against itself. A home-grown OTP that agrees
// with its own verifier but not with Google Authenticator fails in the worst
// possible way: enrolment appears to work and every subsequent login is refused,
// with the user's phone showing a different number and nobody able to say why.
func TestRFC6238Vectors(t *testing.T) {
	// The RFC's SHA-1 seed: the ASCII string "12345678901234567890".
	secret := []byte("12345678901234567890")

	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		c := Counter(time.Unix(tc.unix, 0), DefaultPeriod)
		if got := Code(secret, c, 8); got != tc.want {
			t.Errorf("T=%d: got %s, want %s (RFC 6238 Appendix B)", tc.unix, got, tc.want)
		}
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
	raw, _, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := Code(raw, Counter(now, DefaultPeriod), DefaultDigits)

	c, err := Verify(raw, code, now, DefaultDigits, DefaultPeriod, DefaultSkew, 0)
	if err != nil {
		t.Fatalf("a freshly generated code was rejected: %v", err)
	}
	if c != Counter(now, DefaultPeriod) {
		t.Errorf("matched counter %d, want %d", c, Counter(now, DefaultPeriod))
	}
}

// THE test that separates a real second factor from a decorative one.
//
// A TOTP code is valid for its whole window. Without a strictly advancing
// counter, anyone who sees a code -- over a shoulder, through a phishing proxy,
// in a screenshot -- can reuse it for the remainder of that window. Most
// implementations do not do this.
func TestReplayIsRefused(t *testing.T) {
	raw, _, _ := GenerateSecret()
	now := time.Now()
	code := Code(raw, Counter(now, DefaultPeriod), DefaultDigits)

	used, err := Verify(raw, code, now, DefaultDigits, DefaultPeriod, DefaultSkew, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The same code, the same window, with the counter now recorded.
	_, err = Verify(raw, code, now, DefaultDigits, DefaultPeriod, DefaultSkew, used)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("a used code was accepted again (err = %v)", err)
	}

	// And an OLDER window must not be accepted either -- an attacker holding a
	// code from the previous step must not be able to spend it after a newer one
	// has been used.
	older := Code(raw, Counter(now, DefaultPeriod)-1, DefaultDigits)
	if _, err := Verify(raw, older, now, DefaultDigits, DefaultPeriod, DefaultSkew, used); err == nil {
		t.Error("a code from an earlier window was accepted after a later one")
	}
}

// Clock skew between a phone and a server is normal; the adjacent windows must
// work or a meaningful share of users simply cannot sign in.
func TestAdjacentWindowsAreAccepted(t *testing.T) {
	raw, _, _ := GenerateSecret()
	now := time.Now()

	for _, offset := range []time.Duration{-DefaultPeriod, DefaultPeriod} {
		code := Code(raw, Counter(now.Add(offset), DefaultPeriod), DefaultDigits)
		if _, err := Verify(raw, code, now, DefaultDigits, DefaultPeriod, DefaultSkew, 0); err != nil {
			t.Errorf("a code %v out of step was rejected: %v", offset, err)
		}
	}

	// Two windows out is beyond the tolerance and must fail, or the code stays
	// valid for two and a half minutes.
	far := Code(raw, Counter(now.Add(3*DefaultPeriod), DefaultPeriod), DefaultDigits)
	if _, err := Verify(raw, far, now, DefaultDigits, DefaultPeriod, DefaultSkew, 0); err == nil {
		t.Error("a code three windows away was accepted")
	}
}

func TestMalformedCodesAreRejected(t *testing.T) {
	raw, _, _ := GenerateSecret()
	now := time.Now()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "12 34 56", "------"} {
		if _, err := Verify(raw, code, now, DefaultDigits, DefaultPeriod, DefaultSkew, 0); err == nil {
			t.Errorf("%q was accepted as a code", code)
		}
	}
}

// A secret typed in by hand arrives spaced, lower-cased, or padded.
func TestSecretDecodingIsForgiving(t *testing.T) {
	raw, enc, _ := GenerateSecret()
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
	uri := ProvisioningURI("Signari", "alice@example.test", "JBSWY3DPEHPK3PXP", 6, DefaultPeriod)

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

	// A colon in the issuer or account breaks the label grammar, and Google
	// Authenticator misparses it into the wrong fields rather than refusing it.
	dirty := ProvisioningURI("Sign:ari", "al:ice", "AAAA", 6, DefaultPeriod)
	if strings.Count(dirty, ":") != 2 { // scheme + label separator only
		t.Errorf("colons were not sanitised out of the label: %s", dirty)
	}
}
