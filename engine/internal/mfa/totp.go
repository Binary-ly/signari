// Package mfa implements second factors.
//
// TOTP (RFC 6238) is written out rather than pulled from a dependency: it is
// HMAC plus a truncation, the spec ships official test vectors, and a second
// factor is a poor place to accept a supply-chain edge for fifty lines of code.
//
// Three decisions here are security-relevant and easy to get wrong:
//
//  1. SHA-1 by default, deliberately. TOTP's HMAC-SHA1 is not a collision
//     problem -- HMAC does not rely on collision resistance -- and every
//     authenticator app in the world supports it. SHA-256 and SHA-512 are
//     permitted and silently unsupported by enough apps that choosing them
//     produces "the code is always wrong" reports with no way to diagnose them,
//     so they are an organisation's choice (Params), made for its own apps or
//     tokens -- or for FIPS 140-only mode, whose module refuses HMAC-SHA1.
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
	"crypto/fips140"
	"crypto/hmac"
	"crypto/rand"
	// #nosec G505 -- RFC 6238 specifies HMAC-SHA1 for TOTP and every
	// authenticator app implements it. HMAC-SHA1 is not affected by the collision
	// attacks that retired SHA-1 for signatures, and choosing SHA-256 here would
	// produce codes that Google Authenticator and 1Password cannot generate.
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm is the HMAC hash: SHA1, SHA256 or SHA512, spelled as the
// otpauth URI spells it.
type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// Valid reports whether a is one of the three.
func (a Algorithm) Valid() bool { return a == SHA1 || a == SHA256 || a == SHA512 }

func (a Algorithm) hash() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	}
	return sha1.New
}

// SecretBytes is the secret length for a: the hash's own output, as the
// test seeds of every OATH vector set are. 160 bits for SHA-1, the RFC 4226
// recommendation and what fits the base32 alphabet without padding.
func (a Algorithm) SecretBytes() int {
	switch a {
	case SHA256:
		return 32
	case SHA512:
		return 64
	}
	return 20
}

// Params are an authenticator's: algorithm, digits and period. An empty one
// is the default, SHA-1, six digits, thirty seconds.
type Params struct {
	Algorithm Algorithm
	Digits    int
	Period    time.Duration
}

func (p Params) withDefaults() Params {
	if !p.Algorithm.Valid() {
		p.Algorithm = SHA1
	}
	if p.Digits <= 0 {
		p.Digits = DefaultDigits
	}
	if p.Period <= 0 {
		p.Period = DefaultPeriod
	}
	return p
}

// Check refuses parameters outside what the store holds and authenticator
// apps and tokens display: SHA1, SHA256 or SHA512; six or eight digits; a
// period of 30 or 60 seconds.
func (p Params) Check() error {
	switch {
	case !p.Algorithm.Valid():
		return fmt.Errorf("mfa: the algorithm must be SHA1, SHA256 or SHA512, not %q", p.Algorithm)
	case p.Digits != 6 && p.Digits != 8:
		return fmt.Errorf("mfa: codes are 6 or 8 digits, not %d", p.Digits)
	case p.Period != 30*time.Second && p.Period != 60*time.Second:
		return fmt.Errorf("mfa: the period is 30s or 60s, not %s", p.Period)
	}
	return nil
}

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
	// HOTPLookAhead is how many presses of a counter-based token may have gone
	// unused since its last accepted code: a button pressed in a pocket moves
	// the token on and not the server. Each counter it spans is a code that
	// would be accepted, so it is a factor in the guessing odds, kept small.
	HOTPLookAhead = 10
	// fipsKeyBytes is the shortest HMAC key FIPS 140-only mode accepts, 112
	// bits; a hardware token's seed can be shorter.
	fipsKeyBytes = 14
)

// b32 is the unpadded, upper-case encoding authenticator apps expect.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrFIPS is a SHA-1 code, or a key under 112 bits, under GODEBUG=fips140=only,
// whose module refuses HMAC with anything but SHA-2 or SHA-3 (3.11). A code
// check used to panic its request.
var ErrFIPS = errors.New("mfa: FIPS 140-only mode refuses HMAC-SHA1 and keys under 112 bits; " +
	"an organisation can enrol SHA256 authenticators, or use a passkey")

// Available reports whether codes under a can be checked in this process.
func Available(a Algorithm) bool { return a.withDefault() != SHA1 || !fips140.Enforced() }

func (a Algorithm) withDefault() Algorithm {
	if !a.Valid() {
		return SHA1
	}
	return a
}

// GenerateSecret returns a new shared secret for a, and its base32 form.
func GenerateSecret(a Algorithm) (raw []byte, encoded string, err error) {
	raw = make([]byte, a.withDefault().SecretBytes())
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

// Code computes the SHA-1 value for one counter, the default authenticator's.
func Code(secret []byte, counter int64, digits int) string {
	return Params{Digits: digits}.Code(secret, counter)
}

// Code computes the value for one counter under p. RFC 4226 §5.3 dynamic
// truncation, whatever the hash: every output is at least 20 bytes, so the
// offset the last byte picks always leaves four to read.
func (p Params) Code(secret []byte, counter int64) string {
	p = p.withDefaults()
	digits := p.Digits
	var buf [8]byte
	// #nosec G115 -- counter is unix time divided by the period, or a
	// token's press count, so it is never negative.
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(p.Algorithm.hash(), secret)
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

// Plausible reports whether a submission could match any code of this length:
// exactly that many decimal digits once surrounding space is trimmed. Verify
// refuses everything else before computing anything, so a caller can use this
// to charge a failure only to a credential the submission was a guess at.
func Plausible(code string, digits int) bool {
	code = strings.TrimSpace(code)
	if digits <= 0 {
		digits = DefaultDigits
	}
	if len(code) != digits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// usable refuses what FIPS 140-only mode would: SHA-1, or a key under 112
// bits, which the module panics on rather than returning an error.
func (p Params) usable(secret []byte) error {
	if !Available(p.Algorithm) || (fips140.Enforced() && len(secret) < fipsKeyBytes) {
		return ErrFIPS
	}
	return nil
}

// Verify checks a time-based code under p and returns the counter it matched.
//
// lastUsed is the highest counter this credential has already accepted; pass 0
// for a credential that has never been used. The caller MUST persist the
// returned counter, or replay protection does not exist.
func (p Params) Verify(secret []byte, code string, now time.Time, skew int, lastUsed int64) (int64, error) {
	p = p.withDefaults()
	if err := p.usable(secret); err != nil {
		return 0, err
	}
	if !Plausible(code, p.Digits) {
		return 0, ErrInvalidCode
	}
	code = strings.TrimSpace(code)
	if skew < 0 {
		skew = 0
	}

	current := Counter(now, p.Period)

	// Every candidate window is evaluated even after a match, so the time taken
	// does not reveal WHICH window matched. That leaks a few hundred
	// milliseconds of clock offset, which is not secret, but the uniform shape
	// is free and removes the question.
	matched := int64(-1)
	for i := -skew; i <= skew; i++ {
		c := current + int64(i)
		if subtle.ConstantTimeCompare([]byte(p.Code(secret, c)), []byte(code)) == 1 {
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

// VerifyHOTP checks a counter-based code (RFC 4226), from a token whose last
// accepted counter is lastUsed, among the next window counters, and returns
// the one it matched. The caller MUST persist it.
//
// The last accepted code itself is ErrReplay, as in Verify, so submitting it
// twice is not charged as a guess; anything further behind is simply wrong.
// Every candidate is computed, as in Verify.
func (p Params) VerifyHOTP(secret []byte, code string, lastUsed int64, window int) (int64, error) {
	p = p.withDefaults()
	if err := p.usable(secret); err != nil {
		return 0, err
	}
	if !Plausible(code, p.Digits) {
		return 0, ErrInvalidCode
	}
	code = strings.TrimSpace(code)
	matched := int64(-1)
	for i := 1; i <= window; i++ {
		c := lastUsed + int64(i)
		if subtle.ConstantTimeCompare([]byte(p.Code(secret, c)), []byte(code)) == 1 && matched < 0 {
			matched = c
		}
	}
	replayed := subtle.ConstantTimeCompare([]byte(p.Code(secret, lastUsed)), []byte(code)) == 1
	switch {
	case matched >= 0:
		return matched, nil
	case replayed:
		return 0, ErrReplay
	}
	return 0, ErrInvalidCode
}

// ProvisioningURI builds the otpauth:// URI an authenticator app scans.
//
// The label is "Issuer:account" AND the issuer is repeated as a parameter --
// belt and braces, because apps disagree about which one they read, and an app
// that reads neither shows the user an unlabelled six-digit code among twenty
// others.
func ProvisioningURI(issuer, account, secretB32 string, p Params) string {
	p = p.withDefaults()
	// A colon in either field breaks the label grammar, and Google Authenticator
	// parses the result into the wrong fields rather than refusing it.
	issuer = strings.ReplaceAll(issuer, ":", " ")
	account = strings.ReplaceAll(account, ":", " ")

	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", string(p.Algorithm))
	q.Set("digits", strconv.Itoa(p.Digits))
	q.Set("period", strconv.Itoa(int(p.Period.Seconds())))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}
