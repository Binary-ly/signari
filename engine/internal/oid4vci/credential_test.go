package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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

// §8.3 lets the issuer cap how many credentials one request mints, and the cap
// is load-bearing rather than tidy.
//
// Every proof costs a database round trip to spend its c_nonce, a signature
// verification, a subject read and a signature. The body is capped at a
// megabyte, which at roughly four hundred bytes per proof still admits a couple
// of thousand — so an unbounded array is one HTTP request that becomes thousands
// of database round trips.
func TestTheNumberOfProofsIsBounded(t *testing.T) {
	proofs := make([]json.RawMessage, MaxProofsPerRequest+1)
	for i := range proofs {
		proofs[i] = json.RawMessage(`"header.payload.signature"`)
	}
	req := CredentialRequest{
		ConfigurationID: "Identity",
		Proofs:          map[string][]json.RawMessage{ProofTypeJWT: proofs},
	}
	if _, err := req.Validate(); err == nil {
		t.Fatalf("%d proofs were accepted; one request would mint that many "+
			"credentials and spend that many nonces", len(proofs))
	}

	// And the limit itself is usable: a wallet batching keys must not be refused.
	req.Proofs[ProofTypeJWT] = proofs[:MaxProofsPerRequest]
	if _, err := req.Validate(); err != nil {
		t.Fatalf("exactly the limit was refused: %v", err)
	}
}
