// Package mfa implements second factors.
//
// TOTP (RFC 6238) is written out rather than pulled from a dependency: it is
// HMAC plus a truncation, the spec ships official test vectors, and a second
// factor is a poor place to accept a supply-chain edge for fifty lines of code.
//
// Three decisions here are security-relevant and easy to get wrong:
//
//  1. SHA-1, deliberately. TOTP's HMAC-SHA1 is not a collision problem -- HMAC
//     does not rely on collision resistance -- and every authenticator app in
//     the world supports it. SHA-256 is permitted by the RFC and silently
//     unsupported by enough apps that choosing it produces "the code is always
//     wrong" reports with no way to diagnose them.
//
//  2. Codes are compared in constant time. A byte-by-byte compare on a 6-digit
//     code is a timing oracle that reduces a million guesses to sixty.
//
//  3. Verification returns the COUNTER it matched. The caller must persist it
//     and refuse anything less than or equal to it. Without that, a code stays
//     replayable for its whole window -- so an attacker who observes one over a
//     shoulder, a proxy, or a phishing page has ~30 seconds to reuse it. Most
//     implementations skip this; it is the difference between a second factor
//     and a second factor that survives being seen.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	// #nosec G505 -- RFC 6238 specifies HMAC-SHA1 for TOTP and every
	// authenticator app implements it. HMAC-SHA1 is not affected by the collision
	// attacks that retired SHA-1 for signatures, and choosing SHA-256 here would
	// produce codes that Google Authenticator and 1Password cannot generate.
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultDigits is 6. Eight is more secure and is what nobody's authenticator
	// app displays by default; the rate limit is the real control here.
	DefaultDigits = 6
	// DefaultPeriod is the universal 30 seconds. Changing it breaks apps that
	// assume it, and several ignore the parameter in the provisioning URI.
	DefaultPeriod = 30 * time.Second
	// DefaultSkew accepts the adjacent windows, so a phone up to ~30s out of
	// step still works. Wider means a code stays valid longer, which is exactly
	// what replay protection is trying to bound.
	DefaultSkew = 1
	// secretBytes is 160 bits, the RFC 4226 recommendation and what fits the
	// base32 alphabet without padding awkwardness.
	secretBytes = 20
)

// b32 is the unpadded, upper-case encoding authenticator apps expect.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new shared secret and its base32 form.
func GenerateSecret() (raw []byte, encoded string, err error) {
	raw = make([]byte, secretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, "", fmt.Errorf("mfa: no entropy for a TOTP secret: %w", err)
	}
	return raw, b32.EncodeToString(raw), nil
}

// DecodeSecret parses a base32 secret, tolerating the spacing and lower case
// that people produce when typing one in by hand.
func DecodeSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	raw, err := b32.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("mfa: secret is not valid base32: %w", err)
	}
	if len(raw) < 10 {
		return nil, fmt.Errorf("mfa: secret is %d bytes, too short to be safe", len(raw))
	}
	return raw, nil
}

// Counter is the time step a code belongs to.
func Counter(t time.Time, period time.Duration) int64 {
	if period <= 0 {
		period = DefaultPeriod
	}
	return t.UTC().Unix() / int64(period.Seconds())
}

// Code computes the TOTP value for one counter. RFC 4226 §5.3 dynamic truncation.
func Code(secret []byte, counter int64, digits int) string {
	if digits <= 0 {
		digits = DefaultDigits
	}
	var buf [8]byte
	// #nosec G115 -- counter is unix time divided by the period, so it is
	// positive until the year 292277026596.
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// The low four bits of the last byte select where to read from.
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	// Zero-padded: "012345" and "12345" are different codes, and trimming the
	// leading zero is a classic source of one-in-ten intermittent failures.
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// ErrReplay means the code was correct but has already been used.
//
// Distinguished from a wrong code so the caller can say something accurate --
// "that code was already used, wait for the next one" is actionable, while
// "invalid code" sends a user who did nothing wrong round a loop. It is safe to
// distinguish: the attacker replaying it already knows the code was valid.
var ErrReplay = fmt.Errorf("mfa: code has already been used")

// ErrInvalidCode is every other failure, deliberately undifferentiated.
var ErrInvalidCode = fmt.Errorf("mfa: code is invalid")

// Verify checks a code and returns the counter it matched.
//
// lastUsed is the highest counter this credential has already accepted; pass 0
// for a credential that has never been used. The caller MUST persist the
// returned counter, or replay protection does not exist.
func Verify(secret []byte, code string, now time.Time, digits int, period time.Duration, skew int, lastUsed int64) (int64, error) {
	code = strings.TrimSpace(code)
	if digits <= 0 {
		digits = DefaultDigits
	}
	if len(code) != digits {
		return 0, ErrInvalidCode
	}
	if _, err := strconv.Atoi(code); err != nil {
		return 0, ErrInvalidCode
	}
	if skew < 0 {
		skew = 0
	}

	current := Counter(now, period)

	// Every candidate window is evaluated even after a match, so the time taken
	// does not reveal WHICH window matched. That leaks a few hundred
	// milliseconds of clock offset, which is not secret, but the uniform shape
	// is free and removes the question.
	matched := int64(-1)
	for i := -skew; i <= skew; i++ {
		c := current + int64(i)
		if subtle.ConstantTimeCompare([]byte(Code(secret, c, digits)), []byte(code)) == 1 {
			matched = c
		}
	}
	if matched < 0 {
		return 0, ErrInvalidCode
	}

	// Replay. The counter must strictly advance: accepting the same one twice is
	// what makes an observed code reusable for the rest of its window.
	if matched <= lastUsed {
		return 0, ErrReplay
	}
	return matched, nil
}

// ProvisioningURI builds the otpauth:// URI an authenticator app scans.
//
// The label is "Issuer:account" AND the issuer is repeated as a parameter --
// belt and braces, because apps disagree about which one they read, and an app
// that reads neither shows the user an unlabelled six-digit code among twenty
// others.
func ProvisioningURI(issuer, account, secretB32 string, digits int, period time.Duration) string {
	if digits <= 0 {
		digits = DefaultDigits
	}
	if period <= 0 {
		period = DefaultPeriod
	}
	// A colon in either field breaks the label grammar, and Google Authenticator
	// parses the result into the wrong fields rather than refusing it.
	issuer = strings.ReplaceAll(issuer, ":", " ")
	account = strings.ReplaceAll(account, ":", " ")

	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(digits))
	q.Set("period", strconv.Itoa(int(period.Seconds())))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}
