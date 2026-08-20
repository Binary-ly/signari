package abca

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

// draft-ietf-oauth-attestation-based-client-auth-10, §7.1 and §7.2, rule by
// rule. Each test makes exactly one thing wrong, so a failure names the rule.

const testIssuer = "https://as.example.com"

type key struct {
	priv *ecdsa.PrivateKey
	jwk  jose.JSONWebKey
}

func newKey(t *testing.T) *key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key{priv: k, jwk: jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"}}
}

func (k *key) set() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k.jwk}}
}

// sign builds a JWT with a chosen typ and claims, so a test can make exactly one
// field wrong.
func (k *key) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderType, typ)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
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

// attestationFor builds a well-formed attestation from `attester` binding
// `instance`'s public key to clientID.
func attestationFor(t *testing.T, attester, instance *key, clientID string,
	mutate func(map[string]any)) string {

	t.Helper()
	raw, err := instance.jwk.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"sub": clientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(raw)},
	}
	if mutate != nil {
		mutate(claims)
	}
	return attester.sign(t, TypAttestation, claims)
}

func popFor(t *testing.T, instance *key, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"aud": testIssuer,
		"jti": "jti-" + t.Name(),
		"iat": time.Now().Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	return instance.sign(t, TypPoP, claims)
}

// The happy path, first: without this the refusals below could all be passing
// for the wrong reason.
func TestAValidAttestationAndPoPVerify(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	att, err := VerifyAttestation(attestationFor(t, attester, instance, "client-1", nil),
		attester.set(), time.Now())
	if err != nil {
		t.Fatalf("a well-formed attestation was refused: %v", err)
	}
	if att.ClientID != "client-1" {
		t.Fatalf("sub read as %q", att.ClientID)
	}
	if _, err := VerifyPoP(popFor(t, instance, nil), att.Key, testIssuer, "", time.Now()); err != nil {
		t.Fatalf("a well-formed PoP was refused: %v", err)
	}
}

// §7.1 rule 4: signed "with the public key of a known and trusted Client
// Attester". This is the entire trust model -- without it any party able to sign
// a JWT could vouch for any client.
func TestAnAttestationFromAnUnknownAttesterIsRefused(t *testing.T) {
	trusted, stranger, instance := newKey(t), newKey(t), newKey(t)
	_, err := VerifyAttestation(attestationFor(t, stranger, instance, "client-1", nil),
		trusted.set(), time.Now())
	if err == nil {
		t.Fatal("an attestation signed by an unregistered key was accepted: anybody " +
			"able to sign a JWT could then vouch for any client")
	}
	// Asserting the REASON, not merely the refusal.
	//
	// Bypassing the trust check left this test passing: with no trusted key
	// matched the payload stays nil, and the JSON decode of nil fails a few lines
	// later, so the call still errored. The test could not tell "no attester
	// vouched for this" from "the bytes did not parse", and would have gone on
	// passing if the trust check were deleted.
	if !strings.Contains(err.Error(), "trusted client attester") {
		t.Errorf("refused, but not as an untrusted attester: %v", err)
	}
}

func TestNoTrustedAttestersMeansNothingVerifies(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	for _, set := range []*jose.JSONWebKeySet{nil, {}} {
		if _, err := VerifyAttestation(attestationFor(t, attester, instance, "c", nil),
			set, time.Now()); err == nil {
			t.Fatal("an attestation verified against an empty trust set")
		}
	}
}

// §7.1 rule 5, and the reason is worth more than the rule: an attestation
// carrying a private key hands this server -- and every proxy the header passed
// through -- the key the PoP exists to prove exclusive possession of.
func TestAnAttestationCarryingAPrivateKeyIsRefused(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	private := jose.JSONWebKey{Key: instance.priv, Algorithm: "ES256"}
	raw, err := private.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	att := attestationFor(t, attester, instance, "client-1", func(c map[string]any) {
		c["cnf"] = map[string]any{"jwk": json.RawMessage(raw)}
	})
	_, err = VerifyAttestation(att, attester.set(), time.Now())
	if err == nil {
		t.Fatal("an attestation containing a PRIVATE key was accepted")
	}
	if !strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// §4: sub, exp and cnf are REQUIRED.
func TestEveryRequiredAttestationClaim(t *testing.T) {
	for _, missing := range []string{"sub", "exp", "cnf"} {
		t.Run("without "+missing, func(t *testing.T) {
			attester, instance := newKey(t), newKey(t)
			att := attestationFor(t, attester, instance, "client-1", func(c map[string]any) {
				delete(c, missing)
			})
			if _, err := VerifyAttestation(att, attester.set(), time.Now()); err == nil {
				t.Fatalf("an attestation with no %s claim was accepted; §4 makes it "+
					"REQUIRED", missing)
			}
		})
	}
}

// §4: "The Authorization Server or Resource Server MUST reject any JWT with an
// expiration time that has passed".
func TestAnExpiredAttestationIsRefused(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	att := attestationFor(t, attester, instance, "client-1", func(c map[string]any) {
		c["exp"] = time.Now().Add(-time.Hour).Unix()
	})
	if _, err := VerifyAttestation(att, attester.set(), time.Now()); err == nil {
		t.Fatal("an expired attestation was accepted")
	}
}

// §4 and §7.1 rule 2: typ is REQUIRED and exact. Substituting a PoP for an
// attestation is the cross-protocol confusion typ exists to stop.
func TestAnAttestationWithTheWrongTypIsRefused(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	for _, typ := range []string{"", "JWT", TypPoP, "oauth-client-attestation"} {
		raw, _ := instance.jwk.MarshalJSON()
		att := attester.sign(t, typ, map[string]any{
			"sub": "client-1", "exp": time.Now().Add(time.Hour).Unix(),
			"cnf": map[string]any{"jwk": json.RawMessage(raw)},
		})
		if _, err := VerifyAttestation(att, attester.set(), time.Now()); err == nil {
			t.Fatalf("an attestation with typ %q was accepted; §4 requires %q",
				typ, TypAttestation)
		}
	}
}

// §7.2 rule 4: the PoP verifies "with the public key contained in the cnf claim
// of the Client Attestation JWT" -- and with nothing else. This is the join
// between the two artefacts.
func TestAPoPSignedByAnyOtherKeyIsRefused(t *testing.T) {
	attester, instance, other := newKey(t), newKey(t), newKey(t)
	att, err := VerifyAttestation(attestationFor(t, attester, instance, "client-1", nil),
		attester.set(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPoP(popFor(t, other, nil), att.Key, testIssuer, "", time.Now()); err == nil {
		t.Fatal("a PoP signed by a key the attestation never named was accepted: the " +
			"attestation and the proof are then about different keys")
	}
	// The attester's own key must not work either -- it signs attestations, not
	// proofs, and accepting it would let the attester impersonate every instance
	// it has ever vouched for.
	if _, err := VerifyPoP(popFor(t, attester, nil), att.Key, testIssuer, "", time.Now()); err == nil {
		t.Fatal("a PoP signed by the ATTESTER's key was accepted")
	}
}

// §5.1: aud, jti and iat are all REQUIRED.
func TestEveryRequiredPoPClaim(t *testing.T) {
	for _, missing := range []string{"aud", "jti", "iat"} {
		t.Run("without "+missing, func(t *testing.T) {
			instance := newKey(t)
			pop := popFor(t, instance, func(c map[string]any) { delete(c, missing) })
			if _, err := VerifyPoP(pop, &instance.jwk, testIssuer, "", time.Now()); err == nil {
				t.Fatalf("a PoP with no %s claim was accepted; §5.1 makes it REQUIRED",
					missing)
			}
		})
	}
}

// §7.2 rule 7: for an authorization server the audience MUST be the RFC 8414
// issuer identifier. Without it a proof captured at one deployment replays at
// another that trusts the same attester.
func TestAPoPForAnotherAudienceIsRefused(t *testing.T) {
	instance := newKey(t)
	for _, aud := range []string{"https://elsewhere.example", testIssuer + "/oauth2/token", ""} {
		pop := popFor(t, instance, func(c map[string]any) { c["aud"] = aud })
		if _, err := VerifyPoP(pop, &instance.jwk, testIssuer, "", time.Now()); err == nil {
			t.Fatalf("a PoP addressed to %q was accepted by %q", aud, testIssuer)
		}
	}
}

// §7.2 rule 6: within an acceptable window, in both directions.
func TestAPoPOutsideTheAcceptableWindowIsRefused(t *testing.T) {
	instance := newKey(t)
	now := time.Now()
	for _, tc := range []struct {
		name string
		iat  time.Time
	}{
		{"too old", now.Add(-MaxPoPAge - MaxSkew - time.Second)},
		{"from the future", now.Add(MaxSkew + time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pop := popFor(t, instance, func(c map[string]any) { c["iat"] = tc.iat.Unix() })
			if _, err := VerifyPoP(pop, &instance.jwk, testIssuer, "", now); err == nil {
				t.Fatalf("a PoP issued %s was accepted", tc.name)
			}
		})
	}
}

// §7.2 rules 5 and 8: when the server issued a challenge it MUST be present and
// MUST match. Both failures are ChallengeError, because §7.4 requires the
// response to carry a fresh challenge -- a plain error would leave the client
// unable to retry.
func TestTheChallengeIsBindingWhenTheServerIssuedOne(t *testing.T) {
	instance := newKey(t)

	t.Run("absent", func(t *testing.T) {
		pop := popFor(t, instance, nil)
		_, err := VerifyPoP(pop, &instance.jwk, testIssuer, "expected-value", time.Now())
		if err == nil {
			t.Fatal("a PoP with no challenge was accepted where one was required")
		}
		if _, ok := err.(*ChallengeError); !ok {
			t.Fatalf("error is %T, not *ChallengeError; §7.4 requires the response "+
				"to carry a fresh challenge, and the caller cannot know to attach "+
				"one unless this is distinguishable: %v", err, err)
		}
	})

	t.Run("mismatched", func(t *testing.T) {
		pop := popFor(t, instance, func(c map[string]any) { c["challenge"] = "some-other-value" })
		_, err := VerifyPoP(pop, &instance.jwk, testIssuer, "expected-value", time.Now())
		if err == nil {
			t.Fatal("a PoP carrying the wrong challenge was accepted")
		}
		if _, ok := err.(*ChallengeError); !ok {
			t.Fatalf("error is %T, not *ChallengeError: %v", err, err)
		}
	})

	t.Run("matching", func(t *testing.T) {
		pop := popFor(t, instance, func(c map[string]any) { c["challenge"] = "expected-value" })
		if _, err := VerifyPoP(pop, &instance.jwk, testIssuer, "expected-value", time.Now()); err != nil {
			t.Fatalf("the correct challenge was refused: %v", err)
		}
	})
}

// §7.1/§7.2 rule 3: "is not none". Asserted at the parser, so an unsigned token
// never reaches claim handling.
func TestAnUnsignedTokenIsRefused(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	// alg=none, hand-built: no signer will produce one.
	unsigned := "eyJhbGciOiJub25lIiwidHlwIjoib2F1dGgtY2xpZW50LWF0dGVzdGF0aW9uK2p3dCJ9." +
		"eyJzdWIiOiJjbGllbnQtMSJ9."
	if _, err := VerifyAttestation(unsigned, attester.set(), time.Now()); err == nil {
		t.Fatal("an alg=none attestation was accepted")
	}
	if _, err := VerifyPoP(unsigned, &instance.jwk, testIssuer, "", time.Now()); err == nil {
		t.Fatal("an alg=none PoP was accepted")
	}
}

// §8: the published algorithm list must be the one the verifier enforces.
// Two copies drift, and they drift towards metadata promising what the verifier
// refuses -- so a client builds something correct by the published rules and is
// rejected by the server that published them.
func TestPublishedAlgorithmsAreTheEnforcedOnes(t *testing.T) {
	published := SigningAlgs()
	if len(published) != len(allowedAlgs) {
		t.Fatalf("metadata publishes %d algorithms, the verifier accepts %d",
			len(published), len(allowedAlgs))
	}
	for i, a := range allowedAlgs {
		if published[i] != string(a) {
			t.Fatalf("published[%d] = %q, enforced = %q", i, published[i], a)
		}
	}
	for _, a := range published {
		if a == "none" || strings.HasPrefix(a, "HS") {
			t.Fatalf("metadata publishes %q; §5.1 requires an asymmetric algorithm "+
				"and a symmetric attester key is one this server could forge with", a)
		}
	}
}

// §5.1 and §7.2 rule 2: the PoP's typ is REQUIRED and exact.
//
// Added after a mutation removing the PoP typ check survived the suite: the
// attestation had a typ test and the PoP did not. The case that matters is the
// last one — an ATTESTATION presented as a PoP. Both are signed JWTs, and the
// attestation is the long-lived, reusable artefact that travels in a header on
// every request, so without the typ check anyone who captured one could present
// it as the per-request proof. That is precisely the cross-protocol substitution
// `typ` exists to prevent, and nothing else in the verifier would have caught
// it: it is signed by a key the attestation names as soon as the attestation
// names its own signer.
func TestAPoPWithTheWrongTypIsRefused(t *testing.T) {
	attester, instance := newKey(t), newKey(t)

	for _, typ := range []string{"", "JWT", TypAttestation, "oauth-client-attestation-pop"} {
		pop := instance.sign(t, typ, map[string]any{
			"aud": testIssuer, "jti": "j1", "iat": time.Now().Unix(),
		})
		if _, err := VerifyPoP(pop, &instance.jwk, testIssuer, "", time.Now()); err == nil {
			t.Fatalf("a PoP with typ %q was accepted; §5.1 requires %q", typ, TypPoP)
		}
	}

	// The substitution, end to end: a real attestation, replayed as the proof.
	att := attestationFor(t, attester, instance, "client-1", nil)
	verified, err := VerifyAttestation(att, attester.set(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPoP(att, verified.Key, testIssuer, "", time.Now()); err == nil {
		t.Fatal("a Client Attestation JWT was accepted as its own proof of " +
			"possession: the long-lived artefact would satisfy the per-request one")
	}
}

// §4: exp is REQUIRED, and the refusal must say so.
//
// Added after a mutation removing the explicit check survived: with no exp the
// claim decodes to zero, the expiry comparison treats it as 1970, and the token
// is refused as *expired*. Safe, and unhelpful — an integrator reads "expired at
// 1970-01-01" and goes looking at clocks instead of at the claim they omitted.
// The guard exists for the message, so the message is what is asserted.
func TestAnAttestationWithNoExpSaysSo(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	att := attestationFor(t, attester, instance, "client-1", func(c map[string]any) {
		delete(c, "exp")
	})
	_, err := VerifyAttestation(att, attester.set(), time.Now())
	if err == nil {
		t.Fatal("an attestation with no exp was accepted")
	}
	if !strings.Contains(err.Error(), "no exp claim") {
		t.Fatalf("refused with %q; an absent exp must not be reported as an expiry "+
			"in 1970, which sends an integrator to look at clocks", err)
	}
}

// TestAnAttestationDatedInTheFutureIsRefused.
//
// §7.1 rule 6 asks that the attestation be "sufficiently fresh", checking `iat`
// or `exp`. `exp` is enforced, so freshness is covered and this is defence in
// depth — but it was untested, and a future `iat` is the same shape as the defect
// found in the Transaction Token verifier: a timestamp that moves the usable
// window rather than lengthening it.
//
// An attester whose clock is badly wrong produces these by accident; one that is
// compromised produces them on purpose.
func TestAnAttestationDatedInTheFutureIsRefused(t *testing.T) {
	attester, instance := newKey(t), newKey(t)
	now := time.Now()

	raw := attestationFor(t, attester, instance, "client-1", func(c map[string]any) {
		c["iat"] = now.Add(10 * time.Minute).Unix()
		c["exp"] = now.Add(20 * time.Minute).Unix()
	})
	_, err := VerifyAttestation(raw, attester.set(), now)
	if err == nil {
		t.Fatal("an attestation claiming to be issued ten minutes from now was accepted")
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("refused, but not as a future-dated attestation: %v", err)
	}

	// Modest skew is still tolerated: an attester whose clock is a few seconds
	// fast must not be unable to attest anything.
	ok := attestationFor(t, attester, instance, "client-1", func(c map[string]any) {
		c["iat"] = now.Add(5 * time.Second).Unix()
		c["exp"] = now.Add(10 * time.Minute).Unix()
	})
	if _, err := VerifyAttestation(ok, attester.set(), now); err != nil {
		t.Errorf("five seconds of clock skew was refused: %v", err)
	}
}
