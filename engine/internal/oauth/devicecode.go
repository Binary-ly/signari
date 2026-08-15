package oauth

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

// GrantTypeDeviceCode is RFC 8628's grant type.
const GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceCodeAlphabet is what a user code is drawn from.
//
// Twenty-one letters: A-Z without B, I, O, S, Z. Digits are excluded entirely.
//
// Every exclusion is a misreading somebody actually makes when copying a code
// off a television across a room: I/1/l, O/0, S/5, Z/2, B/8. A code that is
// technically valid and routinely mistyped costs more in support than the four
// bits of entropy it buys, and the entropy is not what protects this code -- the
// attempt limit and the ten-minute expiry are.
const DeviceCodeAlphabet = "ACDEFGHJKLMNPQRTUVWXY"

// UserCodeLength is the number of characters, before formatting.
//
// Eight from a 21-character alphabet is about 35 bits. RFC 8628 §5.1 asks for
// at least 20 bits of entropy against a rate-limited endpoint; this is well
// past that while still being typable.
const UserCodeLength = 8

// NewUserCode returns a code a person can read off a screen and type.
func NewUserCode() (string, error) {
	b := make([]byte, UserCodeLength)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating a user code: %w", err)
	}
	// Modulo introduces a slight bias because 256 is not a multiple of 21: the
	// first four characters of the alphabet are drawn marginally more often.
	// Accepted deliberately -- this code's security rests on the attempt limit
	// and the ten-minute expiry, not on uniformity, and rejection sampling here
	// would buy nothing measurable. Stated so the choice is visible.
	out := make([]byte, UserCodeLength)
	for i, v := range b {
		out[i] = DeviceCodeAlphabet[int(v)%len(DeviceCodeAlphabet)]
	}
	return string(out), nil
}

// FormatUserCode groups a code for display: ABCD-EFGH.
//
// The hyphen is presentation only. NormalizeUserCode removes it again, because
// a person who types what they see must not be told they are wrong.
func FormatUserCode(code string) string {
	if len(code) != UserCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// NormalizeUserCode turns what somebody typed into what was stored.
//
// Case, hyphens and whitespace only. It is tempting to go further and map the
// confusable characters -- 0 to O, 1 to I, 5 to S -- to "what they meant", but
// that is not knowable: a round character could be D, O or Q, and the mapping
// has to guess. Worse, any such table risks rewriting a character that IS in the
// alphabet, which silently corrupts a correct code and produces a failure nobody
// can reproduce.
//
// The alphabet already solves this by construction: B, I, O, S and Z are never
// generated, so a code containing one is a misreading that cannot match anything
// and is rejected by ValidUserCodeShape before it costs an attempt.
func NormalizeUserCode(in string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(in)) {
		switch r {
		case '-', ' ', '\t', '\n', '\r', '_':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ValidUserCodeShape reports whether a normalised code could possibly be one of
// ours, without touching the database.
//
// A cheap filter in front of the lookup: nothing else should reach a query, and
// an obviously malformed code should not consume an attempt.
func ValidUserCodeShape(code string) bool {
	if len(code) != UserCodeLength {
		return false
	}
	for _, r := range code {
		if !strings.ContainsRune(DeviceCodeAlphabet, r) {
			return false
		}
	}
	return true
}
