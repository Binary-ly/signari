package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// Assertion verification, attacked rather than demonstrated.
//
// Each test forges something a real attacker would send. The happy path is one
// test; the rest are the ways a competitor's implementation of this same grant
// was broken in 2026.

func issuerKey(t *testing.T, kid string) (*rsa.PrivateKey, *JWKSCache) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: k.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig",
	}}}
	// The cache fetches from this stub, so no test touches the network.
	c := &JWKSCache{Fetch: func(context.Context, *http.Client, string) (*jose.JSONWebKeySet, error) {
		return set, nil
	}}
	return k, c
}

func signed(t *testing.T, k *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testCfg() Config {
	return Config{Kind: KindOIDC, JWKSOverride: "https://p/jwks",
		IssuerOverride: "https://platform.example"}
}

func TestAGenuineAssertionVerifies(t *testing.T) {
	k, cache := issuerKey(t, "k1")
	raw := signed(t, k, "k1", map[string]any{"iss": "https://platform.example", "sub": "w1"})

	payload, err := VerifyAssertion(context.Background(), nil, cache, testCfg(), raw)
	if err != nil {
		t.Fatalf("a genuine assertion was refused: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got["sub"] != "w1" {
		t.Errorf("payload sub = %v, want w1", got["sub"])
	}
}

// Algorithm confusion, CWE-347. The attacker takes the issuer's PUBLIC key -- which is
// public -- and uses it as an HMAC secret, then claims alg HS256. An
// implementation that lets the header choose the algorithm verifies it happily.
func TestAnHMACForgedWithThePublicKeyIsRefused(t *testing.T) {
	k, cache := issuerKey(t, "k1")

	// Build the attacker's token: same claims, HS256, secret = the public modulus.
	secret := k.Public().(*rsa.PublicKey).N.Bytes()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Skipf("could not build the HMAC forgery: %v", err)
	}
	obj, err := signer.Sign([]byte(`{"iss":"https://platform.example","sub":"victim"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyAssertion(context.Background(), nil, cache, testCfg(), raw); err == nil {
		t.Fatal("an HS256 assertion forged with the issuer's public key was ACCEPTED; " +
			"this is the algorithm-confusion bypass")
	}
}

// `alg: none` -- the other half of the same class.
func TestAnUnsignedAssertionIsRefused(t *testing.T) {
	_, cache := issuerKey(t, "k1")

	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	raw := enc(`{"alg":"none","typ":"JWT","kid":"k1"}`) + "." +
		enc(`{"iss":"https://platform.example","sub":"victim"}`) + "."

	if _, err := VerifyAssertion(context.Background(), nil, cache, testCfg(), raw); err == nil {
		t.Fatal("an unsigned assertion was accepted")
	}
}

// A signature from the wrong key must fail even when the kid matches.
func TestAnAssertionSignedByAnotherKeyIsRefused(t *testing.T) {
	_, cache := issuerKey(t, "k1")
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw := signed(t, attacker, "k1", map[string]any{"iss": "https://platform.example", "sub": "victim"})

	if _, err := VerifyAssertion(context.Background(), nil, cache, testCfg(), raw); err == nil {
		t.Fatal("an assertion signed by an unrelated key was accepted")
	}
}

// An unknown kid is a distinct answer from a bad signature: one is a rotation we
// have not caught up with, the other is an attack.
func TestAnUnknownKidIsReported(t *testing.T) {
	k, cache := issuerKey(t, "k1")
	raw := signed(t, k, "k-unknown", map[string]any{"iss": "https://platform.example", "sub": "w1"})

	_, err := VerifyAssertion(context.Background(), nil, cache, testCfg(), raw)
	if err == nil {
		t.Fatal("an assertion naming an unpublished key was accepted")
	}
	if !strings.Contains(err.Error(), "no key with id") {
		t.Errorf("error does not distinguish an unknown key: %v", err)
	}
}

// A provider with no JWKS URL must fail closed, not verify against nothing.
func TestAProviderWithNoKeysCannotVerify(t *testing.T) {
	_, cache := issuerKey(t, "k1")
	k2, _ := issuerKey(t, "k1")
	raw := signed(t, k2, "k1", map[string]any{"iss": "https://platform.example", "sub": "w1"})

	cfg := testCfg()
	cfg.JWKSOverride = ""
	if _, err := VerifyAssertion(context.Background(), nil, cache, cfg, raw); err == nil {
		t.Fatal("a provider with no JWKS URL verified an assertion")
	}
}

// The allow-list itself, asserted directly.
//
// TestAnHMACForgedWithThePublicKeyIsRefused above does NOT prove this. Mutation
// showed why: adding HS256 to assertionAlgorithms leaves it green, because
// go-jose refuses to verify an HMAC signature with an RSA public key whatever the
// parser permitted. That test exercises the key-type binding, which is a second
// and independent defence -- worth having, and not the one it appeared to cover.
//
// The property that actually needs pinning is that no symmetric algorithm is ever
// permitted for an assertion. An assertion comes from a party we share no secret
// with, so a symmetric algorithm verifying at all means the "secret" is something
// public. Stated as a property rather than demonstrated through a forgery,
// because a forgery needs a symmetric key in the issuer's published set to be
// realistic, and the point is that such a set must never be usable.
func TestNoSymmetricAlgorithmIsEverPermitted(t *testing.T) {
	for _, a := range assertionAlgorithms {
		switch a {
		case jose.HS256, jose.HS384, jose.HS512:
			t.Errorf("%s is permitted for assertions; a symmetric algorithm means "+
				"the verification secret is the issuer's public key", a)
		}
		if strings.HasPrefix(string(a), "HS") {
			t.Errorf("%s looks symmetric and is permitted", a)
		}
	}
	if len(assertionAlgorithms) == 0 {
		t.Fatal("the allow-list is empty, so nothing verifies at all")
	}
}

// An assertion that carries its own key is refused before the key set is even
// consulted.
//
// This check was written as defence in depth -- verification only ever uses keys
// fetched from the issuer, so an embedded key is inert today. Mutation showed
// that removing it broke no test, which is how a redundant-looking guard gets
// deleted in a refactor and stops being redundant.
func TestAnAssertionCarryingItsOwnKeyIsRefused(t *testing.T) {
	k, cache := issuerKey(t, "k1")

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte(`{"iss":"https://platform.example","sub":"w1"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyAssertion(context.Background(), nil, cache, testCfg(), raw)
	if err == nil {
		t.Fatal("an assertion carrying its own key material was accepted")
	}
	if !strings.Contains(err.Error(), "own key material") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
