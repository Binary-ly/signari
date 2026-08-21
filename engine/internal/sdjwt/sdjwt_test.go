package sdjwt

import (
	"encoding/base64"
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
	// At LEAST three: §4.2.5 decoy digests pad the array, and asserting an exact
	// length here would make the privacy feature look like a bug.
	if !ok || len(sd) < 3 {
		t.Fatalf("_sd = %v, want at least the three real digests", payload["_sd"])
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
	// Decoded with base64 DIRECTLY, not through mustDecode.
	//
	// mustDecode parses the Disclosure and then re-marshals it with
	// json.Marshal, which escapes HTML by default -- so it returned escaped
	// bytes whatever the package had produced, and this assertion could never
	// fire. Turning SetEscapeHTML back on broke no test, which is how the
	// inertness was found: by mutating rather than by reading.
	onTheWire := string(mustBase64(t, d.Encoded))
	if strings.Contains(onTheWire, `\u003c`) || strings.Contains(onTheWire, `\u0026`) {
		t.Errorf("the disclosure escapes HTML characters: %s", onTheWire)
	}
	if !strings.Contains(onTheWire, "a<b&c>d") {
		t.Errorf("the value does not appear literally on the wire: %s", onTheWire)
	}
}

// mustBase64 returns the actual bytes of a Disclosure as transmitted.
//
// The distinction from mustDecode is the point: this is what a verifier hashes
// (RFC 9901 §4.2.3), whereas mustDecode shows the round-tripped VALUES and tells
// you nothing about the encoding.
func mustBase64(t *testing.T, encoded string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return b
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

func TestFrameClaimsCannotBeSelectivelyDisclosed(t *testing.T) {
	for _, name := range []string{"iss", "iat", "nbf", "exp", "cnf", "vct", "status"} {
		if _, err := NewDisclosure(name, "x"); err == nil {
			t.Errorf("%q was accepted as selectively disclosable", name)
		}
		if _, _, err := Payload(nil, map[string]any{name: "x"}); err == nil {
			t.Errorf("Payload accepted %q as selectively disclosable", name)
		}
	}
}

// §4.2.5: decoy digests hide how many claims are being withheld.
//
// Without them `len(_sd)` is exactly the number of claims in the credential, so
// a verifier holding two disclosures out of five learns three were held back and
// can press for them. The count must also VARY: a fixed number of decoys is
// worse than none, because a verifier who knows the issuer always adds three
// simply subtracts three.
func TestDecoyDigestsPadAndVary(t *testing.T) {
	const claims = 4
	sel := map[string]any{"a": 1, "b": 2, "c": 3, "d": 4}

	seen := map[int]bool{}
	for i := 0; i < 40; i++ {
		payload, ds, err := Payload(nil, sel)
		if err != nil {
			t.Fatal(err)
		}
		if len(ds) != claims {
			t.Fatalf("got %d disclosures, want %d — decoys must not become "+
				"disclosures, or the holder could open them", len(ds), claims)
		}
		sd := payload["_sd"].([]string)
		if len(sd) < claims {
			t.Fatalf("_sd has %d digests for %d claims", len(sd), claims)
		}
		seen[len(sd)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("_sd length was always %v across 40 credentials; a fixed amount "+
			"of padding is subtracted as easily as none", seen)
	}
}

// A decoy must not be openable: no disclosure corresponds to it, which is what
// §4.2.5 says the holder will see.
func TestDecoysHaveNoDisclosure(t *testing.T) {
	payload, ds, err := Payload(nil, map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]bool{}
	for _, d := range ds {
		real[d.Digest()] = true
	}
	decoys := 0
	for _, digest := range payload["_sd"].([]string) {
		if !real[digest] {
			decoys++
		}
	}
	// Every real disclosure must still be present; the extras are the decoys.
	for _, d := range ds {
		found := false
		for _, digest := range payload["_sd"].([]string) {
			if digest == d.Digest() {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the disclosure for %q is not in _sd", d.Name)
		}
	}
	t.Logf("%d decoy digests alongside %d real claims", decoys, len(ds))
}

// §4.1: "The same digest value MUST NOT appear more than once in the SD-JWT."
//
// Real digests cannot collide — unique salts, SHA-256 — so this is about the
// decoys, which are random and compared against nothing. Negligible probability,
// unconditional requirement.
func TestNoDigestAppearsTwice(t *testing.T) {
	for i := 0; i < 50; i++ {
		payload, _, err := Payload(nil, map[string]any{"a": 1, "b": 2, "c": 3})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, d := range payload["_sd"].([]string) {
			if seen[d] {
				t.Fatalf("digest %q appears twice", d)
			}
			seen[d] = true
		}
	}
}

// §4.1: "The payload MUST NOT contain the claims _sd or ... except for the
// purpose of conveying digests."
//
// An always-visible claim by either name would be overwritten by the digest
// array, so the credential would quietly not say what was configured.
func TestReservedNamesCannotBeAlwaysVisibleClaims(t *testing.T) {
	for _, name := range []string{"_sd", "..."} {
		if _, _, err := Payload(map[string]any{name: "value"}, nil); err == nil {
			t.Errorf("%q was accepted as an always-visible claim", name)
		}
	}
}

// The duplicate-digest guard, forced.
//
// §4.1 forbids a digest appearing twice, and SHA-256 will not oblige by chance —
// so the guard was unprovable and a mutation removing it broke nothing. Swapping
// the decoy source for one that always returns the same value makes the case
// reachable, and now the rule is demonstrated rather than asserted.
func TestDuplicateDigestsAreDroppedWhenTheSourceRepeats(t *testing.T) {
	original := decoySource
	t.Cleanup(func() { decoySource = original })
	decoySource = func() (string, error) { return "AAAArepeatedDecoyDigestAAAA", nil }

	for i := 0; i < 20; i++ {
		payload, _, err := Payload(nil, map[string]any{"a": 1, "b": 2, "c": 3})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, d := range payload["_sd"].([]string) {
			if seen[d] {
				t.Fatalf("digest %q appears twice even though the guard should have "+
					"dropped the repeat", d)
			}
			seen[d] = true
		}
	}
}

// And a decoy that collides with a REAL digest must not be added either — that
// would make one digest ambiguous between a disclosure and nothing.
func TestADecoyCollidingWithARealDigestIsDropped(t *testing.T) {
	// Build once to learn a real digest.
	_, ds, err := Payload(nil, map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	realDigest := ds[0].Digest()

	original := decoySource
	t.Cleanup(func() { decoySource = original })
	decoySource = func() (string, error) { return realDigest, nil }

	payload, ds2, err := Payload(nil, map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, d := range payload["_sd"].([]string) {
		if d == ds2[0].Digest() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("the real digest appears %d times; a decoy colliding with it "+
			"would make that digest ambiguous", count)
	}
}

// TestTheSaltCarriesTheEntropyTheRFCRequires.
//
// RFC 9901 §9.3, "Entropy of the Salt":
//
//	"The salt value MUST be cryptographically random ... The salt value MUST
//	contain at least 128 bits of cryptographically secure random data."
//
// This is not decoration. The digest of a Disclosure is public, and a Disclosure
// is `[salt, name, value]` — so a verifier who can guess the salt can confirm a
// claim the holder chose NOT to reveal, by hashing candidate values until one
// matches. For a claim with a small domain — a date of birth, a postcode, a
// boolean — the value space is trivial, and the salt is the only thing making
// the digest opaque.
//
// Written because the guarantee was untested: shrinking the salt from 16 bytes
// to 8 broke no test at all. A security parameter nothing measures is one that
// can be reduced by a refactor nobody reviews closely.
func TestTheSaltCarriesTheEntropyTheRFCRequires(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		d, err := NewDisclosure("age_over_18", true)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(d.Salt)
		if err != nil {
			t.Fatalf("the salt is not base64url: %v", err)
		}
		if len(raw)*8 < 128 {
			t.Fatalf("the salt is %d bits; RFC 9901 §9.3 requires at least 128, and "+
				"the salt is the only thing stopping a verifier brute-forcing a "+
				"withheld claim from its digest", len(raw)*8)
		}
		if seen[d.Salt] {
			t.Fatal("the same salt was produced twice; §9.3 requires a fresh one per " +
				"Disclosure, and a repeat makes two digests linkable")
		}
		seen[d.Salt] = true
	}
}

// TestAValueContainingHTMLCharactersIsEncodedLiterally.
//
// Go's json.Encoder rewrites `<`, `>` and `&` into \u003c, \u003e and \u0026 by
// default. newDisclosureWithSalt turns that off.
//
// What that buys needs stating precisely, because the package comment overstates
// it. Hashing is self-consistent either way: we hash the encoding we transmit,
// and a verifier following RFC 9901 §4.2.3 hashes the string as RECEIVED, so an
// escaped Disclosure would still verify and still decode to the same value.
//
// What escaping actually costs is interoperability with anything that
// re-serialises before hashing -- non-conformant, and something real wallets have
// done -- and readability when somebody is debugging a credential by hand. The
// specification's own examples are unescaped.
//
// So it is a defensive choice rather than a load-bearing one, and it was
// untested: turning escaping back on broke nothing, because the only test of it
// compared re-marshalled bytes instead of the bytes on the wire.
func TestAValueContainingHTMLCharactersIsEncodedLiterally(t *testing.T) {
	d, err := NewDisclosure("employer", "Smith & Sons <Ltd>")
	if err != nil {
		t.Fatal(err)
	}
	onTheWire := string(mustBase64(t, d.Encoded))

	for _, esc := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(onTheWire, esc) {
			t.Errorf("the disclosure contains %s; Go escaped an HTML character, which "+
				"is not what the specification's examples show and differs from what "+
				"a re-serialising verifier would produce.\n%s", esc, onTheWire)
		}
	}
	if !strings.Contains(onTheWire, "Smith & Sons <Ltd>") {
		t.Errorf("the value does not appear literally in the disclosure: %s", onTheWire)
	}

	// And it still round-trips, which must not be traded away for readability.
	back, err := Parse(d.Encoded)
	if err != nil {
		t.Fatalf("the disclosure did not parse back: %v", err)
	}
	if back.Value != "Smith & Sons <Ltd>" {
		t.Errorf("value round-tripped as %#v", back.Value)
	}
	if DigestOf(d.Encoded) != d.Digest() {
		t.Error("the digest does not match the encoded form it is taken over")
	}
}

func TestRedListCoversEverySectionTwoTwoTwoThreeClaim(t *testing.T) {
	// draft-ietf-oauth-sd-jwt-vc-18 §2.2.2.3, first list: "MUST NOT be included
	// in the Disclosures, i.e., cannot be selectively disclosed".
	mustNotBeDisclosed := []string{
		"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status",
	}
	for _, claim := range mustNotBeDisclosed {
		if !RedList[claim] {
			t.Errorf("§2.2.2.3 forbids selectively disclosing %q and RedList permits "+
				"it; an issuer can build a credential whose %q a holder simply "+
				"withholds", claim, claim)
		}
	}

	// The second list: "MAY be included in Disclosures". `sub` must stay out of
	// RedList -- blocking it would make a conformant credential unissuable.
	if RedList["sub"] {
		t.Error("§2.2.2.3 permits selectively disclosing `sub`; blocking it makes " +
			"a conformant credential unissuable")
	}
	// `iat` is the documented deviation. If this fires, the deviation was removed
	// and the comment on RedList is now stale.
	if !RedList["iat"] {
		t.Error("`iat` left RedList; §2.2.2.3 permits disclosing it, so this may " +
			"well be right -- but the comment on RedList still calls it a " +
			"deliberate deviation and must be updated with it")
	}
}

// The two claims the drift actually cost us, through the function an issuer calls.
//
// Unit-testing the map would pass against a RedList nothing consults; this goes
// through NewDisclosure, which is what issuance uses.
func TestTypeMetadataIntegrityCannotBeMadeSelectivelyDisclosable(t *testing.T) {
	for _, claim := range []string{"vct#integrity", "aka_vcts"} {
		if _, err := NewDisclosure(claim, "anything"); err == nil {
			t.Errorf("NewDisclosure(%q) succeeded; a holder could withhold it, and "+
				"for vct#integrity that leaves the verifier trusting whatever the "+
				"Type Metadata URL serves at verification time -- the substitution "+
				"§5 exists to prevent", claim)
		}
	}
}
