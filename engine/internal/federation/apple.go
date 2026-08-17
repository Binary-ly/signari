package federation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Sign in with Apple's client secret.
//
// # Why this needs code at all
//
// Every other provider issues a client secret: a string you paste into
// configuration and forget. Apple does not. Apple's "client secret" is a JWT
// that YOU sign, with an ECDSA P-256 key downloaded once as a .p8 file, and it
// is valid for at most six months.
//
// So every Sign in with Apple integration in the world breaks twice a year. It
// fails as `invalid_client` at the token endpoint, which reads like the
// credentials are wrong rather than expired, at a moment nobody has changed
// anything. The usual fix is a calendar reminder, and the usual outcome is that
// the reminder outlives the person who set it.
//
// Minting it here means the expiry is something the software handles rather
// than something an operator has to remember.

// AppleSecretMaxAge is the longest Apple accepts.
//
// Their documentation caps it at six months. Signari mints for slightly less so
// a secret generated on the last day of a month cannot land on a date that does
// not exist in the target month -- a genuine off-by-one that arithmetic on
// calendar months produces twice a year.
const AppleSecretMaxAge = 180 * 24 * time.Hour

// AppleSecretInput is what Apple's developer portal gives you.
type AppleSecretInput struct {
	// TeamID is the ten-character team identifier, top right of the portal.
	TeamID string
	// ClientID is the Services ID, NOT the App ID. This is the one people get
	// wrong: the App ID looks right, is in the same list, and produces
	// invalid_client with no indication which identifier was wrong.
	ClientID string
	// KeyID identifies the .p8 key.
	KeyID string
	// PrivateKeyPEM is the contents of the .p8 file, which is PKCS#8 PEM.
	PrivateKeyPEM string
	// Lifetime defaults to the maximum Apple allows.
	Lifetime time.Duration
}

// MintAppleSecret produces the client secret JWT.
func MintAppleSecret(in AppleSecretInput, now time.Time) (string, time.Time, error) {
	switch {
	case in.TeamID == "":
		return "", time.Time{}, fmt.Errorf("give the Apple team id (ten characters, " +
			"top right of the developer portal)")
	case in.ClientID == "":
		return "", time.Time{}, fmt.Errorf("give the Services ID. NOT the App ID -- " +
			"they sit in the same list and the wrong one produces invalid_client " +
			"without saying which identifier was wrong")
	case in.KeyID == "":
		return "", time.Time{}, fmt.Errorf("give the key id shown beside the .p8 key")
	case in.PrivateKeyPEM == "":
		return "", time.Time{}, fmt.Errorf("give the .p8 private key")
	}

	lifetime := in.Lifetime
	if lifetime <= 0 || lifetime > AppleSecretMaxAge {
		lifetime = AppleSecretMaxAge
	}

	block, _ := pem.Decode([]byte(strings.TrimSpace(in.PrivateKeyPEM)))
	if block == nil {
		return "", time.Time{}, fmt.Errorf("the key is not PEM. Use the .p8 file " +
			"exactly as downloaded, including the BEGIN and END lines")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("the key did not parse as PKCS#8: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", time.Time{}, fmt.Errorf("the key is a %T; Apple issues ECDSA P-256 "+
			"keys, so this is probably not the .p8 file", parsed)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", in.KeyID))
	if err != nil {
		return "", time.Time{}, err
	}

	expiry := now.Add(lifetime)
	claims := jwt.Claims{
		Issuer:   in.TeamID,
		Subject:  in.ClientID,
		Audience: jwt.Audience{"https://appleid.apple.com"},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(expiry),
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiry, nil
}

// AppleSecretExpiry reads the expiry out of an existing secret.
//
// Not verified -- there is no key here to verify with, and the point is to
// report when a stored secret dies rather than to trust it. An operator asking
// "when does this expire" gets an answer instead of a calendar reminder.
func AppleSecretExpiry(secret string) (time.Time, error) {
	tok, err := jwt.ParseSigned(secret, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return time.Time{}, fmt.Errorf("this does not look like an Apple client "+
			"secret: %w", err)
	}
	var c jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&c); err != nil {
		return time.Time{}, err
	}
	if c.Expiry == nil {
		return time.Time{}, fmt.Errorf("the secret carries no expiry, which Apple requires")
	}
	return c.Expiry.Time(), nil
}
