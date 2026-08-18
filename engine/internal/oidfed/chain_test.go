package oidfed

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

// entity is a federation participant with a signing key.
type entity struct {
	id   string
	kid  string
	priv *ecdsa.PrivateKey
}

func newEntity(t *testing.T, id, kid string) *entity {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &entity{id: id, kid: kid, priv: k}
}

func (e *entity) jwks(t *testing.T) json.RawMessage {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: e.priv.Public(), KeyID: e.kid, Algorithm: "ES256", Use: "sig"},
	}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sign produces an Entity Statement signed by e, about sub, publishing subJWKS.
func (e *entity) sign(t *testing.T, sub string, subJWKS json.RawMessage, exp time.Time) Statement {
	t.Helper()
	claims := map[string]any{
		"iss":  e.id,
		"sub":  sub,
		"iat":  time.Now().Add(-time.Minute).Unix(),
		"exp":  exp.Unix(),
		"jwks": subJWKS,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: e.priv},
		(&jose.SignerOptions{}).WithType(Typ).WithHeader("kid", e.kid))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	st.Raw = raw
	return st
}

// chainFor builds leaf -> intermediate -> anchor, the §4.2 example topology.
func chainFor(t *testing.T) (leaf, inter, anchor *entity, chain []Statement) {
	t.Helper()
	leaf = newEntity(t, "https://leaf.example", "leaf-1")
	inter = newEntity(t, "https://inter.example", "inter-1")
	anchor = newEntity(t, "https://anchor.example", "anchor-1")

	exp := time.Now().Add(time.Hour)
	chain = []Statement{
		// ES[0]: the leaf's own Entity Configuration, self-signed.
		leaf.sign(t, leaf.id, leaf.jwks(t), exp),
		// ES[1]: the intermediate's Subordinate Statement ABOUT the leaf. Its
		// jwks is the leaf's keys, as the intermediate attests them.
		inter.sign(t, leaf.id, leaf.jwks(t), exp),
		// ES[2]: the anchor's Subordinate Statement about the intermediate.
		anchor.sign(t, inter.id, inter.jwks(t), exp),
	}
	return
}

func TestAValidChainValidates(t *testing.T) {
	_, _, anchor, chain := chainFor(t)
	res, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
	if err != nil {
		t.Fatalf("a well-formed chain was refused: %v", err)
	}
	if res.Subject != "https://leaf.example" {
		t.Errorf("subject = %q", res.Subject)
	}
	if res.TrustAnchor != anchor.id {
		t.Errorf("anchor = %q", res.TrustAnchor)
	}
	if res.Length != 3 {
		t.Errorf("length = %d", res.Length)
	}
}

// §10.2's step 7 is the one that carries trust:
//
//	"For each j = 0,...,i-1, verify that the signature of ES[j] validates with a
//	public key in ES[j+1]["jwks"]."
//
// A leaf whose configuration is signed with a key its superior does NOT attest
// is the whole attack: anybody can self-sign a configuration, so the
// self-signature check of step 5 admits every entity. Only the superior's
// attestation distinguishes them.
func TestALeafSignedWithAKeyItsSuperiorDoesNotAttestIsRefused(t *testing.T) {
	leaf, inter, anchor, chain := chainFor(t)
	exp := time.Now().Add(time.Hour)

	// The leaf rotates to a key the intermediate has never seen, and re-signs
	// its own configuration with it. Self-consistent, and unvouched-for.
	rogue := newEntity(t, leaf.id, "leaf-rogue")
	chain[0] = rogue.sign(t, leaf.id, rogue.jwks(t), exp)
	// ES[1] still attests the ORIGINAL leaf keys.
	chain[1] = inter.sign(t, leaf.id, leaf.jwks(t), exp)

	_, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
	if err == nil {
		t.Fatal("a leaf configuration signed with an unattested key was accepted. " +
			"Step 5's self-signature admits every entity; only step 7 -- checking " +
			"against the superior's attested jwks -- distinguishes them.")
	}
	if !strings.Contains(err.Error(), "superior") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// §10.2 step 6: "verify that ES[j]["iss"] == ES[j+1]["sub"]".
//
// Without it a chain can be assembled from statements that are each individually
// valid and describe unrelated entities.
func TestABrokenLinkIsRefused(t *testing.T) {
	_, _, anchor, chain := chainFor(t)
	other := newEntity(t, "https://elsewhere.example", "other-1")
	exp := time.Now().Add(time.Hour)

	// ES[2] now vouches for somebody else entirely, so ES[1].iss != ES[2].sub.
	chain[2] = anchor.sign(t, other.id, other.jwks(t), exp)

	if _, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now()); err == nil {
		t.Fatal("a chain whose links do not join was accepted")
	}
}

// §10.2 step 8-9: the chain must end at the anchor the caller trusts, verified
// with the anchor's own key held out of band.
func TestTheAnchorMustBeTheOneWeTrust(t *testing.T) {
	_, _, anchor, chain := chainFor(t)

	t.Run("a different anchor identifier", func(t *testing.T) {
		_, err := ValidateChain(chain, "https://other-anchor.example", anchor.jwks(t), time.Now())
		if err == nil {
			t.Fatal("a chain terminating at a different anchor was accepted")
		}
	})

	t.Run("the anchor's keys taken from the chain would be circular", func(t *testing.T) {
		// Somebody else's key set, i.e. not the anchor's real one.
		impostor := newEntity(t, anchor.id, "anchor-1")
		_, err := ValidateChain(chain, anchor.id, impostor.jwks(t), time.Now())
		if err == nil {
			t.Fatal("the final statement verified against the wrong anchor key")
		}
	})

	t.Run("no anchor keys at all", func(t *testing.T) {
		if _, err := ValidateChain(chain, anchor.id, nil, time.Now()); err == nil {
			t.Fatal("a chain validated with no out-of-band anchor keys")
		}
	})
}

// §10.4: "The expiration time of the whole Trust Chain is the minimum (exp)
// value within the Trust Chain."
//
// Taking the last, or the subject's, would let one long-lived statement extend
// the life of a chain whose weakest member has already expired.
func TestTheChainExpiresWhenItsEarliestMemberDoes(t *testing.T) {
	leaf, inter, anchor, _ := chainFor(t)
	soon := time.Now().Add(10 * time.Minute)
	late := time.Now().Add(10 * time.Hour)

	chain := []Statement{
		leaf.sign(t, leaf.id, leaf.jwks(t), late),
		inter.sign(t, leaf.id, leaf.jwks(t), soon), // the earliest
		anchor.sign(t, inter.id, inter.jwks(t), late),
	}
	res, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Expiry.Unix() != soon.Unix() {
		t.Fatalf("chain expiry = %s, want the earliest member's %s",
			res.Expiry.UTC().Format(time.RFC3339), soon.UTC().Format(time.RFC3339))
	}
}

// Timestamps, §10.2 steps 2 and 3.
func TestExpiredAndFutureStatementsAreRefused(t *testing.T) {
	leaf, inter, anchor, _ := chainFor(t)

	t.Run("an expired member", func(t *testing.T) {
		chain := []Statement{
			leaf.sign(t, leaf.id, leaf.jwks(t), time.Now().Add(-time.Minute)),
			inter.sign(t, leaf.id, leaf.jwks(t), time.Now().Add(time.Hour)),
			anchor.sign(t, inter.id, inter.jwks(t), time.Now().Add(time.Hour)),
		}
		if _, err := ValidateChain(chain, anchor.id, anchor.jwks(t), time.Now()); err == nil {
			t.Fatal("a chain containing an expired statement was accepted")
		}
	})
}

// A chain of one is an Entity Configuration with nothing vouching for it.
func TestAChainOfOneEstablishesNothing(t *testing.T) {
	leaf, _, anchor, _ := chainFor(t)
	only := []Statement{leaf.sign(t, leaf.id, leaf.jwks(t), time.Now().Add(time.Hour))}
	if _, err := ValidateChain(only, anchor.id, anchor.jwks(t), time.Now()); err == nil {
		t.Fatal("a single self-signed Entity Configuration was treated as a Trust Chain")
	}
}

// §3: "Entity Statement JWTs MUST include the kid (Key ID) header parameter".
//
// Without a kid the verifier has to try every key, which turns "signed by the
// key the superior attests" into "signed by any key in a set we were handed".
func TestAStatementWithoutAKidIsRefused(t *testing.T) {
	leaf := newEntity(t, "https://leaf.example", "leaf-1")
	claims, _ := json.Marshal(map[string]any{
		"iss": leaf.id, "sub": leaf.id,
		"iat":  time.Now().Add(-time.Minute).Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
		"jwks": json.RawMessage(leaf.jwks(t)),
	})
	// Deliberately no kid header.
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: leaf.priv},
		(&jose.SignerOptions{}).WithType(Typ))
	obj, _ := signer.Sign(claims)
	raw, _ := obj.CompactSerialize()

	var st Statement
	_ = json.Unmarshal(claims, &st)
	st.Raw = raw

	if err := verifyWith(st, leaf.jwks(t)); err == nil {
		t.Fatal("a statement with no kid header verified")
	}
}

// signClaims signs an arbitrary claim set, for tests that need a shape the
// `sign` helper does not produce — an empty authority_hints array, say.
func signClaims(t *testing.T, e *entity, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: e.priv},
		(&jose.SignerOptions{}).WithType(Typ).WithHeader("kid", e.kid))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
