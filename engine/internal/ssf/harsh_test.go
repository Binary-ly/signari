package ssf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// Adversarial tests for the SET receiver.
//
// This is the highest-consequence input surface in the product: accepting one
// forged Security Event Token terminates a named person's sessions, so anybody
// who can get a SET past this code has a repeatable denial of service against
// any user in the organisation.
//
// The tests in receive_test.go break one field at a time on an otherwise valid
// token. These are different: they are the attacks somebody would actually try.

// `alg: none` — the oldest JWT attack there is.
//
// A signature is a claim about who sent this; `none` is the assertion that
// nobody did. The defence is the explicit algorithm allow-list passed to
// jose.ParseSigned, and this test exists so that removing it fails something.
func TestAlgNoneIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	header := b64(t, map[string]any{"alg": "none", "typ": TypSET, "kid": tr.kid})
	body := b64(t, goodClaims(now))
	raw := header + "." + body + "." // empty signature

	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now); err == nil {
		t.Fatal("a token signed with alg=none was accepted; anybody could end " +
			"anybody's sessions by writing JSON")
	}
}

// Algorithm confusion: sign with HMAC, using the transmitter's PUBLIC key as the
// shared secret.
//
// The classic form of this attack works when a verifier picks the algorithm from
// the token's own header and then hands whatever key it found to a generic
// verify function — the public key is public, so the attacker can compute a
// valid HS256 MAC over any claims they like.
//
// TWO independent defences refuse it here, and it is worth being precise about
// which one actually fires, because a mutation showed the obvious answer is
// wrong. Widening the permitted algorithm list to include HS256 does NOT make
// this test fail: the verification loop hands each JWKS key to tok.Verify, and
// go-jose will not verify an HS256 signature with an ECDSA public key, so the
// type mismatch refuses it regardless.
//
// So the allow-list is defence in depth rather than the load-bearing check, and
// no test here can distinguish its removal. Saying otherwise in this comment
// would be the same defect this repository has twice found in its own code: a
// comment asserting a control that is not the one doing the work.
func TestHMACAlgorithmConfusionIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	pub, err := x509.MarshalPKIXPublicKey(tr.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	raw := hmacToken(t, map[string]any{"alg": "HS256", "typ": TypSET, "kid": tr.kid},
		goodClaims(now), pub)

	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now); err == nil {
		t.Fatal("a SET signed with HS256 over the transmitter's public key was " +
			"accepted; the public key is public, so this is forgery by anybody")
	}
}

// Cross-source forgery, which is the attack that matters in a multi-tenant
// deployment.
//
// The existing suite covers a key we do not trust at all. This is narrower and
// more realistic: TWO transmitters are legitimately configured, and one of them
// signs a token claiming to be the other. A receiver that resolves the key set
// from anything other than the claimed source's own configuration accepts it.
func TestOneConfiguredSourceCannotSpeakAsAnother(t *testing.T) {
	victim := newTransmitter(t)
	attacker := newTransmitter(t)
	now := time.Now()

	// The attacker signs, with its own perfectly valid key, a token whose `iss`
	// is the victim's.
	claims := goodClaims(now) // iss is https://transmitter.test — the victim's
	raw := attacker.sign(t, TypSET, claims, attacker.key, attacker.kid)

	// Verified against the VICTIM's source configuration, which is what the
	// handler selects on the strength of the token's unverified `iss`.
	if _, err := Verify(context.Background(), &KeyFetcher{}, victim.source(), raw, now); err == nil {
		t.Fatal("a configured transmitter signed a token in another transmitter's " +
			"name and it was accepted; any tenant could revoke any other tenant's " +
			"sessions")
	}
}

// The converse, so the test above cannot pass because everything is refused:
// the attacker speaking as ITSELF is accepted.
func TestTheSecondSourceStillWorksInItsOwnName(t *testing.T) {
	attacker := newTransmitter(t)
	now := time.Now()

	src := attacker.source()
	src.Issuer = "https://second.test"
	claims := goodClaims(now)
	claims["iss"] = "https://second.test"

	raw := attacker.sign(t, TypSET, claims, attacker.key, attacker.kid)
	if _, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now); err != nil {
		t.Fatalf("a genuine second transmitter was refused: %v", err)
	}
}

// §4.1.8: several audiences are permitted when the transmitter knows they are
// the same entity. Ours must be found among them rather than having to be alone.
func TestAnAudienceArrayContainingUsIsAccepted(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	c := goodClaims(now)
	c["aud"] = []string{"https://other.test", "https://signari.test", "https://third.test"}
	raw := tr.sign(t, TypSET, c, nil, tr.kid)

	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now); err != nil {
		t.Fatalf("a SET listing us among several audiences was refused: %v", err)
	}
}

// §4.2.3: "Receivers MUST ignore any fields they do not understand from the SSF
// events they receive."
//
// The opposite of the event-TYPE rule, and the pair is easy to conflate: an
// unknown event type is refused because it is an assertion we cannot act on
// safely, while an unknown FIELD is ignored because refusing it makes every
// transmitter extension a breaking change.
func TestUnknownFieldsAreIgnoredRatherThanRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	c := goodClaims(now)
	c["some_future_claim"] = "whatever"
	c["txn"] = "8675309"
	ev := c["events"].(map[string]any)[EventSessionRevoked].(map[string]any)
	ev["a_field_from_a_later_profile"] = map[string]any{"nested": true}

	got, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw(t, tr, c), now)
	if err != nil {
		t.Fatalf("a SET carrying fields we do not know was refused: %v\n"+
			"§4.2.3 makes ignoring them a MUST, and refusing makes every "+
			"transmitter extension a breaking change", err)
	}
	if got.Type != EventSessionRevoked {
		t.Fatalf("type = %q", got.Type)
	}
	if got.Subject.Sub != "user-42" {
		t.Fatalf("the subject was lost among the unknown fields: %+v", got.Subject)
	}
}

// A payload that is not JSON at all, and one that is JSON but not an object.
// Both must be refused rather than panicking or reading as an empty SET.
func TestMalformedPayloadsAreRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	for _, body := range []string{`"just a string"`, `[1,2,3]`, `null`, `{`} {
		header := b64(t, map[string]any{"alg": "ES256", "typ": TypSET, "kid": tr.kid})
		payload := base64.RawURLEncoding.EncodeToString([]byte(body))
		// A real signature over the real payload, so only the SHAPE is wrong.
		signed := signRaw(t, tr.key, header, payload)
		if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), signed, now); err == nil {
			t.Errorf("payload %q was accepted", body)
		}
	}
}

// A token with TWO signatures, in the JSON general serialisation RFC 7515
// defines.
//
// go-jose parses that form, so this is not hypothetical: without the count
// check, `tok.Signatures[0].Header` reads the FIRST signature's header while the
// verification loop may succeed on the second. An attacker who can get one
// legitimate signature alongside their own then controls which header is
// inspected and which key is checked — the `kid`, the `typ` and the algorithm
// are all read from a signature that was never the one verified.
//
// Constructed with one real key and one attacker key over the same payload, so
// the token is genuinely dual-signed rather than merely malformed.
//
// WHICH defence fires: go-jose's. Disabling our explicit count check still
// refuses this token, with "no key verifies it" — jose.JSONWebSignature.Verify
// declines a multi-signature object and requires VerifyMulti instead. So our
// check is defence in depth, and no test here can distinguish its removal.
//
// It is kept, and this comment exists, because that inheritance is exactly the
// kind of thing that stops being true quietly: a JOSE library change, or a
// future need for VerifyMulti, would make our guard the only thing standing and
// nothing would have told us.
func TestATokenWithTwoSignaturesIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	payload := b64(t, goodClaims(now))
	h1 := b64(t, map[string]any{"alg": "ES256", "typ": TypSET, "kid": tr.kid})
	h2 := b64(t, map[string]any{"alg": "ES256", "typ": TypSET, "kid": "attacker"})

	general, err := json.Marshal(map[string]any{
		"payload": payload,
		"signatures": []map[string]any{
			{"protected": h1, "signature": ecdsaSig(t, tr.key, h1, payload)},
			{"protected": h2, "signature": ecdsaSig(t, other, h2, payload)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, verr := Verify(context.Background(), &KeyFetcher{}, tr.source(), string(general), now); verr == nil {
		t.Fatal("a dual-signed token was accepted; the header inspected and the " +
			"key verified can then be different signatures")
	}
}

// And the same construction with ONE signature must still work, or the test
// above would pass merely because the general serialisation is unsupported.
func TestTheGeneralSerialisationWithOneSignatureStillVerifies(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	payload := b64(t, goodClaims(now))
	h1 := b64(t, map[string]any{"alg": "ES256", "typ": TypSET, "kid": tr.kid})
	general, err := json.Marshal(map[string]any{
		"payload": payload,
		"signatures": []map[string]any{
			{"protected": h1, "signature": ecdsaSig(t, tr.key, h1, payload)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), string(general), now); err != nil {
		t.Fatalf("a singly-signed general serialisation was refused, so the "+
			"dual-signature test above proves nothing: %v", err)
	}
}

// --- helpers -------------------------------------------------------------

func raw(t *testing.T, tr *transmitter, claims map[string]any) string {
	t.Helper()
	return tr.sign(t, TypSET, claims, nil, tr.kid)
}

func b64(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hmacToken builds an HS256 token by hand, since a JOSE library will refuse to
// sign one with an EC public key as the secret.
func hmacToken(t *testing.T, header map[string]any, claims map[string]any, secret []byte) string {
	t.Helper()
	h := b64(t, header)
	p := b64(t, claims)
	mac := hmacSHA256(secret, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func signRaw(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	return header + "." + payload + "." + ecdsaSig(t, key, header, payload)
}

// ecdsaSig produces the raw R||S signature JWS uses for ES256.
func ecdsaSig(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	sum := sha256Sum([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
