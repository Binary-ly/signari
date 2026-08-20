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

// OID4VCI 1.0 Appendix D, key attestation.
//
// A key proof says "I hold this key". An attestation says "and a party you trust
// vouches that this key lives in hardware". Only the second means anything
// against a rooted wallet, because a software key signs a perfectly valid proof.

type attester struct {
	key *ecdsa.PrivateKey
	jwk *jose.JSONWebKey
}

func newAttester(t *testing.T) *attester {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &attester{key: k, jwk: &jose.JSONWebKey{Key: k.Public(), Algorithm: string(jose.ES256)}}
}

// sign builds an attestation over the given holder keys.
func (a *attester) sign(t *testing.T, typ string, keys []*jose.JSONWebKey, iat, exp int64, nonce string) string {
	t.Helper()
	var raws []json.RawMessage
	for _, k := range keys {
		b, err := k.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, b)
	}
	body := map[string]any{"attested_keys": raws, "iat": iat}
	if exp != 0 {
		body["exp"] = exp
	}
	if nonce != "" {
		body["nonce"] = nonce
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: a.key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAKeyAttestationIsAcceptedOnlyWhenItVerifies(t *testing.T) {
	att := newAttester(t)
	holder := newHolder(t)
	now := time.Now()
	trusted := []*jose.JSONWebKey{att.jwk}
	iat, exp := now.Unix(), now.Add(time.Hour).Unix()

	good := att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, iat, exp, "")
	set, err := VerifyKeyAttestation(good, trusted, nil, true, "", now)
	if err != nil {
		t.Fatalf("a conformant attestation was refused: %v", err)
	}
	if !set.Contains(holder.jwk) {
		t.Error("the attested key is not reported as attested")
	}

	// The legacy typ is accepted too: the specification renamed it and wallets
	// in the field emit both.
	if _, err := VerifyKeyAttestation(
		att.sign(t, TypKeyAttestationLegacy, []*jose.JSONWebKey{holder.jwk}, iat, exp, ""),
		trusted, nil, true, "", now); err != nil {
		t.Errorf("the legacy typ %q was refused: %v", TypKeyAttestationLegacy, err)
	}

	for name, tc := range map[string]struct {
		raw      string
		trusted  []*jose.JSONWebKey
		wantSaid string
	}{
		"no trusted attesters configured": {good, nil, "no trusted key attesters"},
		"signed by an untrusted attester": {
			newAttester(t).sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, iat, exp, ""),
			trusted, "does not verify against any trusted attester"},
		"wrong typ": {
			att.sign(t, "JWT", []*jose.JSONWebKey{holder.jwk}, iat, exp, ""),
			trusted, "typ"},
		"no attested_keys": {
			att.sign(t, TypKeyAttestation, nil, iat, exp, ""),
			trusted, "vouches for nothing"},
		"no iat": {
			att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, 0, exp, ""),
			trusted, "no iat"},
		"no exp, in a jwt proof": {
			att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, iat, 0, ""),
			trusted, "Appendix D.1"},
		"expired": {
			att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, iat, now.Add(-time.Minute).Unix(), ""),
			trusted, "expired"},
		"issued in the future": {
			att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, now.Add(2*time.Hour).Unix(), exp, ""),
			trusted, "future"},
	} {
		_, err := VerifyKeyAttestation(tc.raw, tc.trusted, nil, true, "", now)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSaid) {
			t.Errorf("%s: refused for the wrong reason: %v", name, err)
		}
	}
}

// The proof and the attestation have to describe the SAME key, or the
// attestation is decoration.
func TestAnAttestationMustCoverTheKeyTheProofUses(t *testing.T) {
	att := newAttester(t)
	holder, other := newHolder(t), newHolder(t)
	now := time.Now()
	iat, exp := now.Unix(), now.Add(time.Hour).Unix()

	ctx := ctxFor()
	ctx.TrustedAttesters = []*jose.JSONWebKey{att.jwk}

	// An attestation covering somebody else's key, attached to this holder's proof.
	wrong := att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{other.jwk}, iat, exp, "")
	raw := holder.signWithAttestation(t, goodProofClaims(now), true, "", wrong)
	if _, err := ValidateJWTProof(raw, ctx, now); err == nil {
		t.Fatal("a proof was accepted whose key_attestation vouches for a different " +
			"key; the request looks hardware-backed while the signing key is not")
	} else if !strings.Contains(err.Error(), "does not vouch") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// The matching attestation is accepted.
	right := att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, iat, exp, "")
	if _, err := ValidateJWTProof(
		holder.signWithAttestation(t, goodProofClaims(now), true, "", right), ctx, now); err != nil {
		t.Fatalf("a proof whose attestation covers its own key was refused: %v", err)
	}
}

// Appendix D is what makes `kid` resolvable: the keys travel with the proof, so
// there is nothing external to look up.
func TestAKidResolvesAgainstTheAttestedKeys(t *testing.T) {
	att := newAttester(t)
	holder := newHolder(t)
	holder.jwk.KeyID = "device-key-1"
	now := time.Now()
	iat, exp := now.Unix(), now.Add(time.Hour).Unix()

	ctx := ctxFor()
	ctx.TrustedAttesters = []*jose.JSONWebKey{att.jwk}
	attestation := att.sign(t, TypKeyAttestation, []*jose.JSONWebKey{holder.jwk}, iat, exp, "")

	// kid only -- no inline jwk -- which without an attestation is refused.
	raw := holder.signWithAttestation(t, goodProofClaims(now), false, "device-key-1", attestation)
	key, err := ValidateJWTProof(raw, ctx, now)
	if err != nil {
		t.Fatalf("a kid naming an attested key was refused: %v", err)
	}
	if key.JWK == nil {
		t.Fatal("no key returned, so nothing could be bound")
	}

	// A kid that names nothing in the attestation must not resolve.
	stray := holder.signWithAttestation(t, goodProofClaims(now), false, "not-attested", attestation)
	if _, err := ValidateJWTProof(stray, ctx, now); err == nil {
		t.Fatal("a kid outside attested_keys resolved")
	} else if !strings.Contains(err.Error(), "not among the attested_keys") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// And without an attestation, kid is still refused, as before.
	ctx.TrustedAttesters = nil
	bare := holder.sign(t, TypProof, goodProofClaims(now), false, "device-key-1")
	if _, err := ValidateJWTProof(bare, ctx, now); err == nil {
		t.Fatal("a bare kid resolved with no attestation to resolve it against")
	}
}
