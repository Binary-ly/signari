package sdjwt

import (
	"encoding/json"
	"strings"
	"testing"
)

// The specification's own worked example, §4.2.3.
//
// This is the single most valuable test in the package, because the rule it
// checks is the one the specification felt the need to state twice in bold:
//
//	"The input to the hash function MUST be the base64url-encoded Disclosure,
//	NOT the bytes encoded by the base64url string."
//
// Hashing the decoded JSON is the obvious reading, produces a plausible-looking
// digest, and yields a credential no verifier on earth will accept. The vector
// below is the difference between the two.
func TestTheSpecificationsOwnDigestVector(t *testing.T) {
	const disclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
	const want = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"

	if got := DigestOf(disclosure); got != want {
		t.Fatalf("digest = %q, want %q\nThe likely cause is hashing the DECODED "+
			"disclosure rather than the base64url string.", got, want)
	}
}

// And the same vector decodes to the claim the specification says it does, so
// the test above cannot pass against a disclosure we misread.
func TestTheSpecificationsVectorDecodes(t *testing.T) {
	const disclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"

	d, err := Parse(disclosure)
	if err != nil {
		t.Fatal(err)
	}
	if d.Salt != "_26bc4LT-ac6q2KI6cBW5es" {
		t.Errorf("salt = %q", d.Salt)
	}
	if d.Name != "family_name" {
		t.Errorf("name = %q", d.Name)
	}
	if d.Value != "Möbius" {
		t.Errorf("value = %v; the non-ASCII value is the point of this vector", d.Value)
	}
}

// A round trip: what we build must hash to what we publish.
func TestDisclosureDigestsMatchThePayload(t *testing.T) {
	payload, ds, err := Payload(
		map[string]any{"iss": "https://issuer.test", "vct": "https://issuer.test/id"},
		map[string]any{"given_name": "Alice", "family_name": "Smith", "over_18": true},
	)
	if err != nil {
		t.Fatal(err)
	}
	sd, ok := payload["_sd"].([]string)
	if !ok || len(sd) != 3 {
		t.Fatalf("_sd = %v, want three digests", payload["_sd"])
	}
	if payload["_sd_alg"] != AlgSHA256 {
		t.Errorf("_sd_alg = %v", payload["_sd_alg"])
	}
	// Every disclosure's digest must appear in _sd, or the holder cannot prove
	// the claim belongs to the credential.
	inSD := map[string]bool{}
	for _, d := range sd {
		inSD[d] = true
	}
	for _, d := range ds {
		if !inSD[d.Digest()] {
			t.Errorf("disclosure %q has digest %q, which is not in _sd", d.Name, d.Digest())
		}
	}
	// And the values must NOT be in the payload — that is the whole point.
	for _, name := range []string{"given_name", "family_name", "over_18"} {
		if _, present := payload[name]; present {
			t.Errorf("%q appears in the payload in the clear, so it is not "+
				"selectively disclosable at all", name)
		}
	}
}

// §4.2.4.1: "The Issuer MUST hide the original order of the claims in the array."
//
// Sorting the digests does it: they are hashes, so their order says nothing
// about the names that produced them. Without this, the position of a digest
// leaks the alphabetical rank of its claim name.
func TestTheDigestArrayIsSortedNotClaimOrdered(t *testing.T) {
	payload, _, err := Payload(nil, map[string]any{
		"zebra": 1, "apple": 2, "mango": 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	sd := payload["_sd"].([]string)
	for i := 1; i < len(sd); i++ {
		if sd[i-1] > sd[i] {
			t.Fatalf("_sd is not sorted: %v", sd)
		}
	}
}

// Salts must be unique per claim (§4.2.1), or two claims with the same value
// produce the same disclosure and the same digest — which tells a verifier the
// two claims are equal without either being revealed.
func TestSaltsAreUniquePerClaim(t *testing.T) {
	_, ds, err := Payload(nil, map[string]any{"a": "same", "b": "same"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 {
		t.Fatalf("got %d disclosures", len(ds))
	}
	if ds[0].Salt == ds[1].Salt {
		t.Fatal("two claims share a salt")
	}
	if ds[0].Digest() == ds[1].Digest() {
		t.Fatal("two claims with equal values produced equal digests, which " +
			"reveals that they are equal")
	}
}

// The structural names cannot be selectively disclosed: revealing a claim called
// `_sd` would collide with the digest array itself.
func TestStructuralNamesAreRefused(t *testing.T) {
	for _, name := range []string{"_sd", "..."} {
		if _, err := NewDisclosure(name, "x"); err == nil {
			t.Errorf("%q was accepted as a disclosable claim name", name)
		}
	}
}

// A claim cannot be both always-visible and selectively disclosable: revealing
// it would put the name in the payload twice.
func TestAClaimCannotBeBothVisibleAndDisclosable(t *testing.T) {
	if _, _, err := Payload(
		map[string]any{"given_name": "Alice"},
		map[string]any{"given_name": "Alice"},
	); err == nil {
		t.Fatal("a claim was accepted as both always-visible and disclosable")
	}
}

// HTML escaping would change the bytes, and the bytes are what is hashed. Go's
// default encoder rewrites <, > and & — so a claim value containing one of them
// would hash differently here than in any other implementation.
func TestValuesContainingHTMLCharactersHashPortably(t *testing.T) {
	d, err := newDisclosureWithSalt("saltsaltsaltsalt", "note", "a<b&c>d")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Parse(d.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Value != "a<b&c>d" {
		t.Fatalf("value round-tripped as %v; HTML escaping changed the bytes", raw.Value)
	}
	if strings.Contains(string(mustDecode(t, d.Encoded)), `<`) {
		t.Error("the disclosure contains an escaped <, so its digest will not " +
			"match what another implementation computes")
	}
}

// The combined serialisation and its parser agree.
func TestCombineAndSplitRoundTrip(t *testing.T) {
	_, ds, err := Payload(nil, map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	s := Combine("header.payload.signature", ds)
	if !strings.HasSuffix(s, Separator) {
		t.Fatal("the issuance serialisation must end with a separator, or a " +
			"verifier cannot tell it from a credential truncated in transit")
	}
	jwt, disclosures, kb, err := Split(s)
	if err != nil {
		t.Fatal(err)
	}
	if jwt != "header.payload.signature" || len(disclosures) != 2 || kb != "" {
		t.Fatalf("split gave %q / %d disclosures / kb %q", jwt, len(disclosures), kb)
	}
}

func TestSplitRefusesMalformed(t *testing.T) {
	for _, in := range []string{"", "noseparator", "jwt~~b~"} {
		if _, _, _, err := Split(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	d, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal([]any{d.Salt, d.Name, d.Value})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The issuance path and the verifier helper must compute the same digest.
//
// They were two implementations of §4.2.3, and a mutation that broke only the
// issuance one passed every test — because the specification's vector exercises
// DigestOf while issuance calls Disclosure.Digest. This ties them together, and
// checks the issuance path against the published vector directly.
func TestIssuanceAndVerificationAgreeOnTheDigest(t *testing.T) {
	const encoded = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
	const want = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"

	d, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Digest(); got != want {
		t.Fatalf("Disclosure.Digest() = %q, want the specification's %q", got, want)
	}
	if d.Digest() != DigestOf(encoded) {
		t.Fatal("the issuance path and the verifier helper disagree")
	}
}
