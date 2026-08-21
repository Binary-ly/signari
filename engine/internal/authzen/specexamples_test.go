package authzen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// Every JSON example in AuthZEN 1.0 Final, extracted from the specification and
// decoded by the types that serve the API.
//
// This is a third kind of check, and it exists because the first two could not
// have found what it finds. Reading the specification's prose says what the
// fields mean; extracting its prohibitions says what must not happen; neither
// notices a field that our struct simply has no home for. A wire field with no
// corresponding struct member decodes silently into nothing, and the endpoint
// answers confidently with the field ignored.
//
// The rule enforced here is asymmetric on purpose:
//
//   - DROPPED or CHANGED is a failure. The specification put a value on the wire
//     and it did not survive a decode/encode cycle, which means either we do not
//     model it or we model it wrongly.
//   - ADDED an empty value is tolerated. Go's zero values serialise, so a
//     non-pointer `Subject` on a boxcar entry that omitted one comes back as
//     `{"type":"","id":""}`. That is a serialisation artifact of a receiver, not
//     a decoding failure -- see TestBoxcarEntriesWouldMisreportAnOmittedSubject
//     for the condition under which it stops being harmless.
//   - ADDED a NON-empty value is a failure. Inventing content is worse than
//     losing it.
func TestEverySpecExampleSurvivesDecoding(t *testing.T) {
	files, err := filepath.Glob("testdata/spec/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("the spec example corpus is missing; this test is vacuous without it (%v)", err)
	}
	checked := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var orig map[string]any
		if json.Unmarshal(raw, &orig) != nil {
			continue // not a JSON object: metadata fragments and the like
		}
		for _, target := range targetsFor(orig) {
			if err := json.Unmarshal(raw, target); err != nil {
				t.Errorf("%s: a specification example did not decode as %T: %v",
					filepath.Base(f), target, err)
				continue
			}
			out, err := json.Marshal(target)
			if err != nil {
				t.Errorf("%s: re-encoding as %T failed: %v", filepath.Base(f), target, err)
				continue
			}
			var back map[string]any
			if err := json.Unmarshal(out, &back); err != nil {
				t.Errorf("%s: %T re-encoded to invalid JSON: %v", filepath.Base(f), target, err)
				continue
			}
			checked++
			var problems []string
			diffJSON("", orig, back, &problems)
			if len(problems) > 0 {
				t.Errorf("%s decoded by %T lost or altered specification content:\n  %v\n"+
					"  raw: %s", filepath.Base(f), target, problems, raw)
			}
		}
	}
	// Guards against the corpus silently ceasing to classify: a refactor that
	// renamed a field could leave every example falling through to `nil` and the
	// test would pass having checked nothing.
	if checked < 20 {
		t.Fatalf("only %d examples were classified and checked; the corpus has %d "+
			"files, so the classifier has stopped recognising the wire format",
			checked, len(files))
	}
}

// targetsFor picks the type(s) the API would decode this body into.
//
// Returns more than one where the specification's example is a bare entity: §5.1
// Subject and §5.2 Resource are the same three members on the wire (`type`, `id`,
// `properties`), so an example of one is equally an example of the other and both
// are checked. That is not pedantry -- it is the only reason this corpus covers
// `Subject.Properties` at all. The full-request examples happen to put
// `properties` only on `action` and `resource`, so a first version of this
// classifier skipped every bare entity, and renaming Subject's `properties` tag
// to something else left the whole suite green.
func targetsFor(o map[string]any) []any {
	switch {
	case o["evaluations"] != nil:
		if ev, ok := o["evaluations"].([]any); ok && len(ev) > 0 {
			if m, ok := ev[0].(map[string]any); ok && m["decision"] != nil {
				return []any{&EvaluationsResponse{}}
			}
		}
		return []any{&Evaluations{}}
	case o["decision"] != nil:
		return []any{&Response{}}
	case o["results"] != nil:
		return []any{&SearchResponse{}}
	case o["page"] != nil:
		return []any{&SearchRequest{}}
	case o["subject"] != nil, o["resource"] != nil, o["action"] != nil:
		return []any{&Request{}}
	// Bare entities: the examples that define the entity shapes themselves.
	case o["type"] != nil:
		return []any{&Subject{}, &Resource{}}
	case o["name"] != nil:
		return []any{&Action{}}
	}
	return nil
}

// diffJSON records every place `got` fails to reproduce `want`, ignoring added
// empty values. See the asymmetry note on TestEverySpecExampleSurvivesDecoding.
func diffJSON(path string, want, got any, out *[]string) {
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if wok && gok {
		seen := map[string]bool{}
		var keys []string
		for k := range wm {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		for k := range gm {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			w, wp := wm[k]
			g, gp := gm[k]
			switch {
			case wp && !gp:
				if specDesignatesExtensible(path, k) {
					continue
				}
				*out = append(*out, fmt.Sprintf("DROPPED %s.%s (%v)", path, k, w))
			case !wp && gp:
				if !isEmptyJSON(g) {
					*out = append(*out, fmt.Sprintf("INVENTED %s.%s (%v)", path, k, g))
				}
			default:
				diffJSON(path+"."+k, w, g, out)
			}
		}
		return
	}
	wa, wok := want.([]any)
	ga, gok := got.([]any)
	if wok && gok {
		if len(wa) != len(ga) {
			*out = append(*out, fmt.Sprintf("LENGTH %s: %d became %d", path, len(wa), len(ga)))
			return
		}
		for i := range wa {
			diffJSON(fmt.Sprintf("%s[%d]", path, i), wa[i], ga[i], out)
		}
		return
	}
	if !reflect.DeepEqual(want, got) {
		*out = append(*out, fmt.Sprintf("CHANGED %s: %v became %v", path, want, got))
	}
}

// specDesignatesExtensible reports whether the specification's own example put a
// deliberately-undefined member at this path to demonstrate extensibility.
//
// There is exactly one, and hard-coding it is the point: §10.1.1 requires a
// receiver to ignore unknown fields, so dropping `options.another_option` on
// re-encode is conformant rather than lossy -- but making that a general rule
// would gut this test, because "we dropped it" and "we never modelled it" look
// identical from the outside. The exception is one path, named, and every other
// dropped field is still a failure.
//
// TestUnknownOptionsAreIgnoredWithoutLosingKnownOnes checks the half that
// actually matters: ignoring the unknown member must not cost us the known one
// beside it.
func specDesignatesExtensible(path, key string) bool {
	return path == ".options" && key == "another_option"
}

// isEmptyJSON reports whether v carries no information: "", 0, false, null, or a
// map/slice all of whose members are themselves empty.
func isEmptyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case float64:
		return t == 0
	case []any:
		for _, e := range t {
			if !isEmptyJSON(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, e := range t {
			if !isEmptyJSON(e) {
				return false
			}
		}
		return true
	}
	return false
}

// The condition under which the tolerated artifact above stops being tolerable.
//
// A boxcar entry that omits `subject` inherits the batch default -- Request.Merge
// applies it field by field, which is what §6.3 requires and what this codebase
// does correctly as a PDP. But Request.Subject is a value, not a pointer, so
// "omitted" and "present and empty" are the same state once decoded, and
// re-encoding an omitted subject produces `{"type":"","id":""}`.
//
// That is invisible today because nothing here ever sends an Evaluations body:
// this package implements the PDP side, and a PDP only ever receives one. The
// moment someone writes a PEP client on these types, each boxcar entry ships an
// explicit empty subject, and a PDP that merges all-or-nothing rather than field
// by field will read it as "this entry overrides the default with nobody" instead
// of "this entry didn't say".
//
// This test does not assert the bug is absent -- it is not, structurally. It
// asserts the reasoning above still holds, so that the day it stops holding, this
// fails and names why.
func TestBoxcarEntriesWouldMisreportAnOmittedSubject(t *testing.T) {
	var b Evaluations
	body := `{"subject":{"type":"user","id":"alice@example.com"},
	          "evaluations":[{"action":{"name":"can_read"},
	                          "resource":{"type":"document","id":"a.md"}}]}`
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatal(err)
	}

	// The half that must keep working: the default reaches the entry.
	merged := b.Evaluations[0].Merge(b)
	if merged.Subject.ID != "alice@example.com" || merged.Subject.Type != "user" {
		t.Fatalf("§6.3 default did not reach the boxcar entry: %+v", merged.Subject)
	}

	// The half that documents the latent defect. If this stops being true --
	// because Request.Subject became a pointer, or omitempty was added -- the
	// comment above is stale and the PEP hazard is gone.
	out, _ := json.Marshal(b.Evaluations[0])
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	sub, present := m["subject"]
	if !present {
		t.Skip("Request.Subject now omits an absent subject; the PEP hazard " +
			"described above is fixed and this test should be deleted")
	}
	if !isEmptyJSON(sub) {
		t.Fatalf("an omitted subject re-encoded as something non-empty (%v), which "+
			"is neither the documented artifact nor the fix", sub)
	}
}

// §10.1.1's "receivers MUST ignore unknown fields" is only half a requirement.
// Ignoring an unknown member must not take a known sibling with it -- a decoder
// that bails on the first unrecognised key, or one that treats the whole `options`
// object as opaque, both "ignore" the unknown field and both lose the semantic
// that decides whether a boxcar stops at the first deny.
//
// The body is the specification's own example, which is why `another_option` is
// spelled exactly that way.
func TestUnknownOptionsAreIgnoredWithoutLosingKnownOnes(t *testing.T) {
	body := `{"subject":{"type":"user","id":"alice@example.com"},
	          "evaluations":[{"action":{"name":"can_read"},
	                          "resource":{"type":"doc","id":"1"}}],
	          "options":{"evaluations_semantic":"execute_all",
	                     "another_option":"value"}}`
	var b Evaluations
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatalf("an unknown member inside `options` made the whole request "+
			"undecodable, which §10.1.1 forbids: %v", err)
	}
	if b.Options == nil {
		t.Fatal("`options` decoded to nothing; the unknown member took the object with it")
	}
	if b.Options.Semantic != "execute_all" {
		t.Fatalf("evaluations_semantic = %q, want execute_all -- the known option "+
			"was lost alongside the unknown one, so the boxcar would fall back to "+
			"a default semantic the caller did not ask for", b.Options.Semantic)
	}
}
