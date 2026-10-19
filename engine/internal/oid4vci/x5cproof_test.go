package oid4vci

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// An x5c proof, as a wallet sends one: a JWS whose protected header carries the
// chain. The tests beside this one exercised ParseX5CChain and ResolveX5CKey
// directly and never a proof, and through a proof the header was never seen:
// go-jose parses `x5c` into a field of its own and leaves nothing in
// ExtraHeaders, where the key-source check looked. So every x5c proof was
// refused as naming no key, and one carrying jwk and x5c together was taken as
// a jwk proof, against §F.1's "MUST NOT be present if jwk or x5c is present".
func TestAProofCarryingAnX5CChainIsReadAsOne(t *testing.T) {
	root := newCA(t, "trusted-root")
	now := time.Now()
	leaf, leafKey := root.issue(t, "wallet", now.Add(time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	sign := func(withJWK bool) string {
		t.Helper()
		opts := (&jose.SignerOptions{}).
			WithType(jose.ContentType(TypProof)).
			WithHeader("x5c", chainHeader(leaf))
		if withJWK {
			opts = opts.WithHeader("jwk", &jose.JSONWebKey{Key: leafKey.Public(), Algorithm: string(jose.ES256)})
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: leafKey}, opts)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(goodProofClaims(now))
		obj, err := signer.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := obj.CompactSerialize()
		return s
	}

	ctx := ctxFor()
	ctx.TrustedX5CRoots = pool
	key, err := ValidateJWTProof(sign(false), ctx, now)
	if err != nil {
		t.Fatalf("an x5c proof to a configured root was refused: %v", err)
	}
	pub, ok := key.JWK.Key.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(leafKey.Public()) {
		t.Error("the key bound is not the leaf certificate's")
	}

	ctx.TrustedX5CRoots = nil
	if _, err := ValidateJWTProof(sign(false), ctx, now); err == nil ||
		!strings.Contains(err.Error(), "no trusted x5c roots") {
		t.Errorf("with no roots the proof gave %v, want the no-roots refusal", err)
	}

	ctx.TrustedX5CRoots = pool
	if _, err := ValidateJWTProof(sign(true), ctx, now); err == nil ||
		!strings.Contains(err.Error(), "more than one of kid, jwk") {
		t.Errorf("a proof carrying jwk and x5c gave %v, want the mutually-exclusive refusal", err)
	}
}
