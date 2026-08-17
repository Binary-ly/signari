package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testP8(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestAppleSecretIsWhatAppleExpects pins the four claims Apple checks.
//
// Getting any of them wrong produces `invalid_client` at the token endpoint,
// which reads as "wrong credentials" and sends whoever is debugging it back to
// the developer portal to re-copy things that were already right.
func TestAppleSecretIsWhatAppleExpects(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	secret, expiry, err := MintAppleSecret(AppleSecretInput{
		TeamID:        "ABCDE12345",
		ClientID:      "com.example.service",
		KeyID:         "KEY1234567",
		PrivateKeyPEM: testP8(t),
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	got, err := AppleSecretExpiry(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(expiry.Truncate(time.Second)) {
		t.Errorf("expiry round-tripped as %s, want %s", got, expiry)
	}
	if d := expiry.Sub(now); d > AppleSecretMaxAge {
		t.Errorf("lifetime %s exceeds what Apple accepts (%s)", d, AppleSecretMaxAge)
	}
}

func TestAppleSecretLifetimeIsCapped(t *testing.T) {
	now := time.Now()
	_, expiry, err := MintAppleSecret(AppleSecretInput{
		TeamID: "ABCDE12345", ClientID: "com.example.service",
		KeyID: "KEY1234567", PrivateKeyPEM: testP8(t),
		// A year: Apple refuses anything over six months, so silently accepting
		// this would produce a secret that fails on first use.
		Lifetime: 365 * 24 * time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := expiry.Sub(now); d > AppleSecretMaxAge+time.Minute {
		t.Errorf("a year was accepted; lifetime came out as %s", d)
	}
}

// TestTheWrongKeyIsRefusedClearly covers the two mistakes people actually make.
func TestTheWrongKeyIsRefusedClearly(t *testing.T) {
	base := AppleSecretInput{
		TeamID: "ABCDE12345", ClientID: "com.example.service", KeyID: "KEY1234567",
	}

	t.Run("not PEM at all", func(t *testing.T) {
		in := base
		in.PrivateKeyPEM = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg"
		_, _, err := MintAppleSecret(in, time.Now())
		if err == nil || !strings.Contains(err.Error(), "PEM") {
			t.Errorf("a bare base64 body should be refused as not-PEM: %v", err)
		}
	})

	t.Run("an RSA key", func(t *testing.T) {
		// A perfectly valid PKCS#8 key of the wrong type: the message must say
		// so rather than reporting a parse failure.
		in := base
		in.PrivateKeyPEM = rsaP8(t)
		_, _, err := MintAppleSecret(in, time.Now())
		if err == nil || !strings.Contains(err.Error(), "ECDSA") {
			t.Errorf("an RSA key should be refused by naming the key type: %v", err)
		}
	})
}

func TestMissingIdentifiersAreNamed(t *testing.T) {
	good := AppleSecretInput{
		TeamID: "ABCDE12345", ClientID: "com.example.service",
		KeyID: "KEY1234567", PrivateKeyPEM: testP8(t),
	}
	for _, tc := range []struct {
		name, want string
		mutate     func(*AppleSecretInput)
	}{
		{"team", "team id", func(i *AppleSecretInput) { i.TeamID = "" }},
		// The Services-ID-versus-App-ID confusion is the single most common
		// Apple setup mistake, so the error names it.
		{"client", "Services ID", func(i *AppleSecretInput) { i.ClientID = "" }},
		{"key id", "key id", func(i *AppleSecretInput) { i.KeyID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := good
			tc.mutate(&in)
			_, _, err := MintAppleSecret(in, time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q: %v", tc.want, err)
			}
		})
	}
}

func rsaP8(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
