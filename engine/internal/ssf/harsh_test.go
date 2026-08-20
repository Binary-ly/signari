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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// A signed SET whose payload names a claim twice.
//
// Not attacker-craftable — producing one needs the transmitter's key. What it
// produces is divergence: we act on Go's reading while a SIEM reading the same
// bytes records another, and an audit trail that disagrees with the action it
// describes is the one failure this product cannot afford.
func TestASETWithADuplicatedClaimIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	// Two `aud` claims: ours first, somebody else's second. Go keeps the last
	// for a slice, a first-wins parser keeps ours, and the two disagree about
	// whether this token was even addressed to us.
	payload := `{"iss":"https://transmitter.test","jti":"dup-1","iat":` +
		itoa64(now.Unix()) + `,` +
		`"aud":["https://signari.test"],"aud":["https://elsewhere.test"],` +
		`"events":{"` + EventSessionRevoked + `":{"subject":{"format":"iss_sub",` +
		`"iss":"https://transmitter.test","sub":"user-42"},` +
		`"event_timestamp":` + itoa64(now.Unix()) + `}}}`

	header := b64(t, map[string]any{"alg": "ES256", "typ": TypSET, "kid": tr.kid})
	enc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	raw := header + "." + enc + "." + ecdsaSig(t, tr.key, header, enc)

	_, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now)
	if err == nil {
		t.Fatal("a SET naming `aud` twice was accepted; which audience applies " +
			"depends on the parser, so we and any downstream reader could disagree " +
			"about whether it was addressed to us at all")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// And a normal SET, whose entities legitimately repeat key NAMES across
// different objects, is unaffected.
func TestANormalSETIsNotSeenAsDuplicated(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(),
		tr.sign(t, TypSET, goodClaims(now), nil, tr.kid), now); err != nil {
		t.Fatalf("a genuine SET was refused as duplicated: %v", err)
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// TestASETWithoutAnIssuedAtIsRefused.
//
// RFC 8417 §2.2 makes `iat` REQUIRED of a Security Event Token. The receiver
// refuses one without it — and nothing tested that, which matters more here than
// it first appears.
//
// The check immediately below it rejects a token minted in the future. With `iat`
// absent that check reads `time.Unix(0, 0)` — 1970 — which is comfortably not in
// the future, so it passes. The two guards look like one defence and are not: the
// second cannot substitute for the first, because the value it inspects is the
// one that is missing.
//
// Same shape as the defects found in the Transaction Token verifier and in ABCA
// this week: a timestamp guard that the missing timestamp switches off.
func TestASETWithoutAnIssuedAtIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()

	claims := goodClaims(now)
	delete(claims, "iat")

	raw := tr.sign(t, TypSET, claims, nil, tr.kid)
	if _, err := Verify(context.Background(), &KeyFetcher{}, tr.source(), raw, now); err == nil {
		t.Fatal("a SET with no iat was accepted; RFC 8417 §2.2 makes it REQUIRED, " +
			"and the future-dating check below cannot stand in for it -- with iat " +
			"absent it inspects 1970 and passes")
	}
}

// TestASETSignedAgainstAnEmptyKeySetIsRefused.
//
// A transmitter whose JWKS is empty — misconfigured, mid-rotation, or serving an
// error page with a 200 — must not verify anything. The failure mode this guards
// is a verifier that treats "no keys to check against" as "nothing objected".
func TestASETSignedAgainstAnEmptyKeySetIsRefused(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	raw := tr.sign(t, TypSET, goodClaims(now), nil, tr.kid)

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer empty.Close()

	src := tr.source()
	src.JWKSURI = empty.URL

	if _, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now); err == nil {
		t.Fatal("a SET verified against a transmitter serving an empty key set; " +
			"having nothing to check a signature against is not the same as the " +
			"signature being good")
	}
}

// TestAJWKSEndpointThatErrorsDoesNotVerifyAnything.
//
// The other half: a transmitter's key endpoint returning 500. A receiver that
// fell back to accepting the event would be trusting whoever could take that
// endpoint down.
func TestAJWKSEndpointThatErrorsDoesNotVerifyAnything(t *testing.T) {
	tr := newTransmitter(t)
	now := time.Now()
	raw := tr.sign(t, TypSET, goodClaims(now), nil, tr.kid)

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer broken.Close()

	src := tr.source()
	src.JWKSURI = broken.URL

	if _, err := Verify(context.Background(), &KeyFetcher{}, src, raw, now); err == nil {
		t.Fatal("a SET was accepted while the transmitter's JWKS endpoint was " +
			"failing; an outage at the transmitter must not become a way to have " +
			"unverified events acted on")
	}
}
