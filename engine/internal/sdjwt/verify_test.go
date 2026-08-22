package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

// Verification, RFC 9901 §7.1.
//
// The strongest test available is the round trip: issue with this package, verify
// with this package, and check the claim set that comes out is the one that went
// in. It catches any disagreement between the two halves about the digest
// construction — which §4.2.3 warns about twice and which is the mistake that
// makes a credential verify nowhere.

func encodedDisclosures(t *testing.T, ds []Disclosure) []string {
	t.Helper()
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Encoded)
	}
	return out
}

func TestIssuanceAndVerificationAgree(t *testing.T) {
	always := map[string]any{"iss": "https://issuer.test", "vct": "https://vct.test/id"}
	selective := map[string]any{
		"given_name":  "Ada",
		"family_name": "Lovelace",
		"birthdate":   "1815-12-10",
	}
	payload, ds, err := Payload(always, selective)
	if err != nil {
		t.Fatal(err)
	}

	// Through JSON, because that is what verification actually receives: a
	// verifier unmarshals a signed payload rather than being handed the issuer's
	// in-memory map.
	got, err := Reconstruct(overTheWire(t, payload), encodedDisclosures(t, ds))
	if err != nil {
		t.Fatalf("a credential this package issued did not verify: %v", err)
	}

	want := map[string]any{
		"iss": "https://issuer.test", "vct": "https://vct.test/id",
		"given_name": "Ada", "family_name": "Lovelace", "birthdate": "1815-12-10",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reconstructed = %v\nwant %v", got, want)
	}
	// The machinery must not survive into the result.
	for _, k := range []string{"_sd", "_sd_alg"} {
		if _, present := got[k]; present {
			t.Errorf("%q survived into the reconstructed claims", k)
		}
	}
}

// The point of the format: presenting fewer disclosures yields fewer claims, and
// still verifies.
func TestPresentingASubsetDisclosesOnlyThose(t *testing.T) {
	payload, ds, err := Payload(
		map[string]any{"iss": "https://issuer.test"},
		map[string]any{"given_name": "Ada", "birthdate": "1815-12-10"})
	if err != nil {
		t.Fatal(err)
	}
	var only []string
	for _, d := range ds {
		if d.Name == "given_name" {
			only = append(only, d.Encoded)
		}
	}
	if len(only) != 1 {
		t.Fatalf("expected one matching disclosure, got %d", len(only))
	}

	got, err := Reconstruct(overTheWire(t, payload), only)
	if err != nil {
		t.Fatalf("a subset presentation did not verify: %v", err)
	}
	if got["given_name"] != "Ada" {
		t.Errorf("given_name = %v, want Ada", got["given_name"])
	}
	if _, present := got["birthdate"]; present {
		t.Error("birthdate appeared without its disclosure being presented")
	}
}

// §7.1.4.5: a disclosure the credential does not reference must be rejected, not
// ignored. Ignoring it lets a holder append anything to a presentation.
func TestAnUnreferencedDisclosureIsRejected(t *testing.T) {
	payload, ds, err := Payload(
		map[string]any{"iss": "https://issuer.test"},
		map[string]any{"given_name": "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	forged, err := NewDisclosure("is_admin", true)
	if err != nil {
		t.Fatal(err)
	}
	presented := append(encodedDisclosures(t, ds), forged.Encoded)

	got, rerr := Reconstruct(payload, presented)
	if rerr == nil {
		t.Fatalf("a disclosure the credential never referenced was accepted, "+
			"yielding %v", got)
	}
}

// §7.1.4.3.2.2.2.2: a disclosure must not claim the name `_sd` or `...`.
func TestADisclosureCannotClaimAReservedName(t *testing.T) {
	for _, name := range []string{"_sd", "..."} {
		// Built by hand: NewDisclosure refuses these at issuance, which is the
		// other half of the same rule. A verifier must refuse them even when the
		// issuer did not.
		enc := handDisclosure(t, "salt-value-aaaaaaaaaaaaaaaaaaaaaa", name, "x")
		payload := map[string]any{
			"iss": "https://issuer.test",
			"_sd": []any{DigestOf(enc)},
		}
		if _, err := Reconstruct(payload, []string{enc}); err == nil {
			t.Errorf("a disclosure claiming the reserved name %q was accepted", name)
		}
	}
}

// §7.1.4.3.2.2.2.3: a disclosure must not overwrite a claim already present.
func TestADisclosureCannotCollideWithAnExistingClaim(t *testing.T) {
	enc := handDisclosure(t, "salt-value-aaaaaaaaaaaaaaaaaaaaaa", "iss", "https://attacker.test")
	payload := map[string]any{
		"iss": "https://issuer.test",
		"_sd": []any{DigestOf(enc)},
	}
	got, err := Reconstruct(payload, []string{enc})
	if err == nil {
		t.Fatalf("a disclosure overwrote a claim the issuer signed directly: %v", got)
	}
}

// §7.1.4.4: the same digest must not appear more than once in the payload.
//
// The repeat is placed at DIFFERENT nesting levels, and that is the whole design
// of this test. Repeating a digest inside one `_sd` array is caught by the
// name-collision rule instead — mutation proved it: removing the duplicate-digest
// guard entirely left the naive version green, because the second copy tried to
// write a claim name that was already there.
//
// Across levels there is no collision to fall back on, so only §7.1.4.4 can
// refuse this. It matters because a digest reachable twice means one disclosure
// populating two places, which is not what the issuer signed.
func TestADuplicatedDigestIsRejected(t *testing.T) {
	enc := handDisclosure(t, "salt-value-aaaaaaaaaaaaaaaaaaaaaa", "given_name", "Ada")
	dig := DigestOf(enc)
	payload := map[string]any{
		"iss":     "https://issuer.test",
		"_sd":     []any{dig},
		"address": map[string]any{"_sd": []any{dig}},
	}
	if _, err := Reconstruct(payload, []string{enc}); err == nil {
		t.Fatal("a payload reaching one digest from two places was accepted")
	}
}

// The same disclosure presented twice.
func TestTheSameDisclosurePresentedTwiceIsRejected(t *testing.T) {
	payload, ds, err := Payload(
		map[string]any{"iss": "https://issuer.test"},
		map[string]any{"given_name": "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	one := ds[0].Encoded
	if _, rerr := Reconstruct(payload, []string{one, one}); rerr == nil {
		t.Fatal("the same disclosure was accepted twice")
	}
}

// An unknown hash algorithm must be refused rather than assumed.
func TestAnUnknownHashAlgorithmIsRefused(t *testing.T) {
	payload := map[string]any{"iss": "https://issuer.test", "_sd_alg": "sha-1"}
	if _, err := Reconstruct(payload, nil); err == nil {
		t.Fatal("an unknown _sd_alg was accepted; digests would match nothing")
	}
}

// _sd must hold strings. A non-string entry is a malformed credential, and
// skipping it would let an issuer hide a claim behind something verifiers ignore.
func TestANonStringDigestIsRefused(t *testing.T) {
	payload := map[string]any{"iss": "https://issuer.test", "_sd": []any{42}}
	if _, err := Reconstruct(payload, nil); err == nil {
		t.Fatal("a non-string _sd entry was accepted")
	}
}

// Undisclosed array items are omitted rather than left as placeholders: a
// placeholder tells the verifier how many items were withheld and where.
func TestUndisclosedArrayItemsAreOmitted(t *testing.T) {
	a := handArrayDisclosure(t, "salt-value-aaaaaaaaaaaaaaaaaaaaaa", "GB")
	b := handArrayDisclosure(t, "salt-value-bbbbbbbbbbbbbbbbbbbbbb", "FR")
	payload := map[string]any{
		"iss": "https://issuer.test",
		"nationalities": []any{
			map[string]any{"...": DigestOf(a)},
			map[string]any{"...": DigestOf(b)},
		},
	}
	got, err := Reconstruct(payload, []string{a})
	if err != nil {
		t.Fatalf("an array presentation did not verify: %v", err)
	}
	list, ok := got["nationalities"].([]any)
	if !ok {
		t.Fatalf("nationalities = %T, want an array", got["nationalities"])
	}
	if len(list) != 1 || list[0] != "GB" {
		t.Errorf("nationalities = %v, want exactly [GB] with the undisclosed item "+
			"absent rather than a placeholder", list)
	}
}

// An array disclosure has TWO elements. Accepting a three-element one would put
// a claim name into an array as if it were a value.
func TestAnObjectDisclosureIsNotAcceptedForAnArrayItem(t *testing.T) {
	obj := handDisclosure(t, "salt-value-aaaaaaaaaaaaaaaaaaaaaa", "given_name", "Ada")
	payload := map[string]any{
		"iss":  "https://issuer.test",
		"list": []any{map[string]any{"...": DigestOf(obj)}},
	}
	if _, err := Reconstruct(payload, []string{obj}); err == nil {
		t.Fatal("a three-element object disclosure was accepted for an array item")
	}
}

// handDisclosure builds an object disclosure without going through
// NewDisclosure, so tests can construct what an issuer must not.
func handDisclosure(t *testing.T, salt, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func handArrayDisclosure(t *testing.T, salt string, value any) string {
	t.Helper()
	raw, err := json.Marshal([]any{salt, value})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// overTheWire round-trips a payload through JSON, so a test exercises the types a
// verifier really sees rather than the issuer's in-memory ones.
func overTheWire(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
