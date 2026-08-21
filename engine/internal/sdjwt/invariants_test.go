package sdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// The second turn on RFC 9901: attacking the properties rather than reading them.
//
// The first pass extracted all 154 normative uses across 37 sections and found
// three defects. What it established by READING is that the format holds
// together — digests match, nothing leaks, salts are unique. Selective
// disclosure is worthless if any of those is false in a case nobody tried, so
// this generates the cases nobody tried.
//
// The claim vocabulary is chosen to break things: names that collide with the
// structural members `_sd` and `...`, names on the red list, values containing
// the characters Go's JSON encoder escapes by default (`<`, `>`, `&`) because
// the digest is taken over bytes and escaping changes them, nested objects,
// arrays, and the empty string.

var claimNames = []string{
	"email", "given_name", "_sd", "...", "iss", "aud", "exp", "cnf", "vct",
	"status", "nbf", "iat", "", "über", "a.b", "0", "sub",
}

var claimValues = []any{
	"plain", "<script>", "a&b", "quote\"inside", "", 0, 1.5, true, nil,
	map[string]any{"nested": "<b>"}, []any{1, "two", nil},
}

func TestPayloadNeverLeaksASelectivelyDisclosableClaim(t *testing.T) {
	rng := rand.New(rand.NewSource(20260821))

	var built, refused int
	for i := 0; i < 3000; i++ {
		always := map[string]any{}
		selective := map[string]any{}
		for j := rng.Intn(4); j > 0; j-- {
			always[claimNames[rng.Intn(len(claimNames))]] = claimValues[rng.Intn(len(claimValues))]
		}
		// Selective values are made UNIQUE per iteration, and that is not
		// cosmetic. Drawn from the shared vocabulary, a selective claim regularly
		// collides with an always-visible one -- the first run of this test
		// reported `sub` "leaking" because an unrelated `iat` happened to carry
		// the same string. A leak assertion over non-distinctive values reports
		// coincidences, and the failure looks exactly like the real thing.
		//
		// The adversarial characters are kept: `<`, `>` and `&` are what Go's JSON
		// encoder escapes by default, and the digest is taken over bytes, so an
		// escaping slip would change them.
		for j := rng.Intn(5); j > 0; j-- {
			name := claimNames[rng.Intn(len(claimNames))]
			selective[name] = fmt.Sprintf("SECRET-%d-%d-<a&b>", i, j)
		}

		payload, ds, err := Payload(always, selective)
		if err != nil {
			refused++
			continue
		}
		built++

		raw, merr := json.Marshal(payload)
		if merr != nil {
			t.Fatalf("the payload does not marshal: %v", merr)
		}
		body := string(raw)

		// 1. No selectively disclosable claim NAME appears as a payload key.
		for name := range selective {
			if _, present := payload[name]; present {
				t.Fatalf("the claim %q is selectively disclosable and appears in the "+
					"payload in the clear, so it is not selectively disclosable at all",
					name)
			}
		}

		// 2. Every always-visible claim survives with its exact value.
		for name, want := range always {
			got, present := payload[name]
			if !present {
				t.Fatalf("the always-visible claim %q was dropped from the payload", name)
			}
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			if string(gj) != string(wj) {
				t.Fatalf("always-visible claim %q changed: %s -> %s", name, wj, gj)
			}
		}

		// 3. Every disclosure's digest is in `_sd`, computed the way §4.2.3
		//    requires -- over the base64url text, not the bytes it encodes.
		sd := map[string]bool{}
		if arr, ok := payload["_sd"].([]string); ok {
			for _, d := range arr {
				sd[d] = true
			}
		}
		salts := map[string]bool{}
		for _, d := range ds {
			if !sd[DigestOf(d.Encoded)] {
				t.Fatalf("the disclosure for %q has a digest that is not in _sd, so a "+
					"verifier would reject it", d.Name)
			}
			// 4. §9.3: at least 128 bits, and unique per claim.
			if salts[d.Salt] {
				t.Fatalf("two disclosures share the salt %q; §4.2.1 requires one per "+
					"claim and a shared salt links them", d.Salt)
			}
			salts[d.Salt] = true
			if n := len(d.Salt); n < 22 {
				t.Fatalf("salt %q is %d characters, under 128 bits of base64url", d.Salt, n)
			}

			// 5. The disclosure round-trips: what a holder presents parses back to
			//    the name and value the issuer put in.
			back, perr := Parse(d.Encoded)
			if perr != nil {
				t.Fatalf("a disclosure this package produced does not parse: %v", perr)
			}
			if back.Name != d.Name {
				t.Fatalf("disclosure name changed through encoding: %q -> %q", d.Name, back.Name)
			}
			bj, _ := json.Marshal(back.Value)
			oj, _ := json.Marshal(d.Value)
			if string(bj) != string(oj) {
				t.Fatalf("disclosure value for %q changed through encoding: %s -> %s",
					d.Name, oj, bj)
			}

			// 6. The VALUE must not appear in the payload text. This is the
			//    property the whole format exists for, and it is the one an
			//    escaping or serialisation slip would break silently.
			if sv, ok := d.Value.(string); ok && len(sv) > 3 && strings.Contains(body, sv) {
				t.Fatalf("the value of the selectively disclosable claim %q appears "+
					"in the payload: %s", d.Name, body)
			}
		}

		// 7. §4.1: "The same digest value MUST NOT appear more than once."
		if arr, ok := payload["_sd"].([]string); ok {
			seen := map[string]bool{}
			for _, d := range arr {
				if seen[d] {
					t.Fatalf("the digest %q appears twice in _sd", d)
				}
				seen[d] = true
			}
			// 8. Decoys make the count uninformative, so there must be at least as
			//    many digests as disclosures.
			if len(arr) < len(ds) {
				t.Fatalf("_sd holds %d digests for %d disclosures", len(arr), len(ds))
			}
			if payload["_sd_alg"] != AlgSHA256 {
				t.Fatalf("_sd_alg = %v", payload["_sd_alg"])
			}
		}
	}

	if built < 150 || refused < 150 {
		t.Fatalf("the generator is lopsided: %d built, %d refused", built, refused)
	}
	t.Logf("%d built, %d refused", built, refused)
}

// Every red-listed name must be refused through BOTH entry points, whatever
// else is in the request.
func TestRedListedClaimsAreRefusedEveryWay(t *testing.T) {
	for name := range RedList {
		if _, err := NewDisclosure(name, "x"); err == nil {
			t.Errorf("NewDisclosure accepted the red-listed claim %q", name)
		}
		if _, _, err := Payload(map[string]any{}, map[string]any{name: "x"}); err == nil {
			t.Errorf("Payload accepted the red-listed claim %q as selective", name)
		}
	}
	for _, structural := range []string{"_sd", "..."} {
		if _, err := NewDisclosure(structural, "x"); err == nil {
			t.Errorf("NewDisclosure accepted the structural name %q", structural)
		}
		if _, _, err := Payload(map[string]any{structural: "x"}, map[string]any{}); err == nil {
			t.Errorf("Payload accepted %q as an always-visible claim", structural)
		}
	}
}

// The disclosure text must carry `<`, `>` and `&` literally, not as `<`.
//
// `newDisclosureWithSalt` turns Go's HTML escaping off, and says why: escaping
// "changes the bytes, and the bytes are what is hashed". Nothing tested it, and
// nothing could: re-enabling escaping is SELF-CONSISTENT. The disclosure is
// built escaped, the digest is computed over the escaped text, `_sd` matches,
// and a verifier hashing the text it received agrees. Every property in this
// file passes, and so does the specification's own vector, because the value in
// it (`Möbius`) contains no character Go escapes.
//
// It is still wrong, and the failure mode is somebody else's: a holder library
// that parses a disclosure and re-serialises it before presenting would emit the
// unescaped form, and the digest would no longer match. The canonical, minimal
// form is what the specification's examples show and what every other
// implementation will produce.
//
// So the decision is pinned here — an assertion about bytes, which is the only
// kind that can see this.
func TestDisclosureTextIsNotHTMLEscaped(t *testing.T) {
	d, err := NewDisclosure("note", `a<b&c>d`)
	if err != nil {
		t.Fatal(err)
	}
	back, err := b64Decode(d.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range []string{"<", "&", ">"} {
		if !strings.Contains(back, ch) {
			t.Errorf("the disclosure text does not contain %q literally: %s", ch, back)
		}
	}
	for _, esc := range []string{`\u003c`, `\u0026`, `\u003e`} {
		if strings.Contains(back, esc) {
			t.Errorf("the disclosure text is HTML-escaped (%s): %s\n"+
				"The digest is taken over these bytes. A holder that re-serialises "+
				"the disclosure would produce the unescaped form and the digest "+
				"would stop matching.", esc, back)
		}
	}
	// And it must still round-trip to the value that went in.
	parsed, err := Parse(d.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Value != `a<b&c>d` {
		t.Errorf("value round-tripped to %v", parsed.Value)
	}
}

// b64Decode is a test helper: the disclosure as its JSON text.
func b64Decode(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return string(b), err
}
