package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// An unbound credential is a bearer token, which is what key binding exists to
// prevent.
//
// The handler never passes a nil key, so this guard is unreachable through HTTP
// — which is exactly why it needs a direct test. A mutation disabling it broke
// nothing, because nothing was calling Issue with the case it defends against.
func TestIssuingWithoutAHolderKeyIsRefused(t *testing.T) {
	i := Issuer{
		CredentialIssuer: "https://issuer.test",
		Sign: func(payload []byte, typ string) (string, error) {
			return "unused", nil
		},
	}
	cfg := Configuration{
		ID: "Identity", Format: FormatSDJWTVC, VCT: "https://issuer.test/id",
		AlwaysClaims: []string{"sub"},
	}
	_, err := i.Issue(cfg, map[string]any{"sub": "u-1"}, nil, time.Now())
	if err == nil {
		t.Fatal("a credential was issued with no holder key, so it is bound to " +
			"nothing and anybody holding it could present it")
	}
	if !strings.Contains(err.Error(), "bearer") {
		t.Errorf("the error does not explain the consequence: %v", err)
	}
}

// A format we do not implement must be refused rather than silently treated as
// SD-JWT VC.
// testKey is a throwaway holder key.
func testKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &jose.JSONWebKey{Key: k.Public(), Algorithm: string(jose.ES256)}
}

func TestAnUnimplementedFormatIsRefused(t *testing.T) {
	i := Issuer{CredentialIssuer: "https://issuer.test",
		Sign: func([]byte, string) (string, error) { return "x", nil }}
	cfg := Configuration{ID: "mdoc", Format: "mso_mdoc", VCT: "org.iso.18013.5.1.mDL",
		AlwaysClaims: []string{"sub"}}
	if _, err := i.Issue(cfg, map[string]any{"sub": "u"}, testKey(t), time.Now()); err == nil {
		t.Fatal("an unimplemented credential format was issued as SD-JWT VC")
	}
}
