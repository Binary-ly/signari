package clientauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// An assertion signed by a key the client never registered must be refused, and
// the refusal must SAY so.
//
// This guard was found disabled in committed source:
//
//	if false && (payload == nil) {
//	    return nil, fmt.Errorf("the client assertion was not signed by any registered key: %w", lastErr)
//	}
//
// A mutation-testing edit — the harness rewrites a guard as `if false && (<original
// condition>)` so the surrounding variables stay referenced and the package still
// compiles — that was committed along with unrelated test work and never reverted.
//
// It was not exploitable, and the reason is luck rather than design: with the
// guard dead, `payload` stays nil and `json.Unmarshal(nil, &c)` fails, so the
// assertion is still refused. The security property was resting on a JSON parse
// error instead of on the check written to enforce it — the same
// "unreachable by accident, not by construction" shape as the scope splitter.
//
// What it did cost was the error message: an integrator whose client signed with
// an unregistered key was told "the client assertion claims did not parse", which
// sends them to look at their claims rather than at their keys.
func TestAnAssertionFromAnUnregisteredKeyIsRefusedAndSaysWhy(t *testing.T) {
	registered := newKey(t, "registered")
	attacker := newKey(t, "registered") // same kid, different key

	assertion := attacker.sign(t, goodClaims())

	_, err := VerifyPrivateKeyJWT(assertion, testClientID, registered.jwks(t),
		testAudiences, time.Now())
	if err == nil {
		t.Fatal("an assertion signed by an unregistered key was ACCEPTED")
	}
	if !strings.Contains(err.Error(), "not signed by any registered key") {
		t.Errorf("the refusal was %q; it must name the real fault — the guard that "+
			"says so was once disabled and the fallback message sent integrators "+
			"to look at their claims instead of their keys", err)
	}
}

// FAPI 2.0 §5.4.1: "RSA keys shall have a minimum length of 2048 bits."
//
// Nothing enforced this. A client could register a 1024-bit RSA public key and
// authenticate with it indefinitely — below every recognised floor since NIST
// withdrew 1024-bit RSA in 2013.
//
// The same floor was already enforced on SAML encryption certificates in
// internal/saml/encrypt.go, so this was an inconsistency inside one codebase
// rather than a considered position.
func TestAWeakRSAKeyCannotAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		bits    int
		wantErr bool
	}{
		{1024, true},
		{2048, false},
	} {
		priv, err := rsa.GenerateKey(rand.Reader, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "rsa", Algorithm: "RS256", Use: "sig"}
		setJSON, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "rsa"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(goodClaims())
		obj, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		assertion, err := obj.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}

		_, err = VerifyPrivateKeyJWT(assertion, testClientID, string(setJSON),
			testAudiences, time.Now())
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("a %d-bit RSA key authenticated a client; FAPI 2.0 §5.4.1 sets "+
				"the floor at %d bits and NIST withdrew 1024-bit RSA in 2013", tc.bits, MinRSABits)
		case tc.wantErr && !strings.Contains(err.Error(), "RSA key"):
			t.Errorf("a %d-bit key was refused with %q, which does not name the "+
				"key length — the client that registers a weak key is the one "+
				"least likely to work out why", tc.bits, err)
		case !tc.wantErr && err != nil:
			t.Errorf("a %d-bit RSA key was refused: %v", tc.bits, err)
		}
	}
}

// A client with one strong key and one legacy weak key keeps working.
//
// The strength check runs against the key that ACTUALLY verified rather than
// filtering the registered set up front, so a client mid-rotation is not locked
// out by a key it is no longer signing with.
func TestAStrongKeyStillWorksAlongsideAWeakOne(t *testing.T) {
	strong := newKey(t, "strong")

	weakPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := jose.JSONWebKey{Key: &weakPriv.PublicKey, KeyID: "weak", Algorithm: "RS256", Use: "sig"}

	setJSON, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{weak, strong.pub}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyPrivateKeyJWT(strong.sign(t, goodClaims()), testClientID,
		string(setJSON), testAudiences, time.Now()); err != nil {
		t.Errorf("a client signing with its strong key was refused because a weak "+
			"key sits beside it in the set: %v", err)
	}
}
