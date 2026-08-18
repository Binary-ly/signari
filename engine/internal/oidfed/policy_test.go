package oidfed

import (
	"encoding/json"
	"strings"
	"testing"
)

// Metadata policy operators, against §6.1.3.1's text rather than against an
// intuition about what each name suggests.
//
// Almost every case here is one where the obvious reading is wrong: `subset_of`
// modifies rather than rejects, `essential` merges with OR rather than AND,
// `one_of` merges to an intersection while `superset_of` merges to a union, and
// two of the operators cannot be combined at all.

func apply(t *testing.T, metadata, policy string) (map[string]any, error) {
	t.Helper()
	var md map[string]any
	if err := json.Unmarshal([]byte(metadata), &md); err != nil {
		t.Fatal(err)
	}
	var rawPolicy map[string]any
	if err := json.Unmarshal([]byte(policy), &rawPolicy); err != nil {
		t.Fatal(err)
	}
	tp := TypePolicy{}
	for param, ops := range rawPolicy {
		pp := ParamPolicy{}
		for name, v := range ops.(map[string]any) {
			pp[name] = v
		}
		if err := validateParamPolicy(TypeRelyingParty, param, pp); err != nil {
			return nil, err
		}
		tp[param] = pp
	}
	return ApplyPolicy(TypeRelyingParty, md, tp)
}

// §6.1.3.1.5: subset_of "is assigned the intersection between the values of the
// operator and the metadata parameter... subset_of is a potential value modifier
// in addition to it being a value check."
//
// The natural implementation rejects instead. Rejecting means one policy can
// only serve subordinates that publish exactly what it permits, which defeats
// the point of writing a policy for a whole federation.
func TestSubsetOfTrimsRatherThanRejects(t *testing.T) {
	out, err := apply(t,
		`{"response_types": ["code", "token", "id_token"]}`,
		`{"response_types": {"subset_of": ["code", "id_token"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	got := out["response_types"].([]any)
	if len(got) != 2 || got[0] != "code" || got[1] != "id_token" {
		t.Errorf("response_types = %v, want [code id_token]", got)
	}
}

// The last two rows of Table 1 in §6.1.3.1.8, which are the ones that catch a
// wrong implementation: with the parameter ABSENT, essential:true is an error
// and essential:false leaves it absent -- it does not become [].
func TestTable1AbsentParameterWithSubsetOf(t *testing.T) {
	_, err := apply(t, `{}`,
		`{"scope_x": {"essential": true, "subset_of": ["a","b","c"]}}`)
	if err == nil {
		t.Error("an absent parameter marked essential was accepted")
	}

	out, err := apply(t, `{}`,
		`{"scope_x": {"essential": false, "subset_of": ["a","b","c"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if v, present := out["scope_x"]; present {
		t.Errorf("an absent voluntary parameter became %v; Table 1's last row says "+
			"it stays absent", v)
	}
}

// The third and fourth rows: an intersection that is empty is [] and NOT an
// error. A policy that trims everything leaves an empty list, which downstream
// code can then judge for itself.
func TestAnEmptyIntersectionIsAnEmptyArrayNotAnError(t *testing.T) {
	out, err := apply(t, `{"p": ["a","e"]}`, `{"p": {"subset_of": ["d","f"]}}`)
	if err != nil {
		t.Fatalf("an empty intersection was treated as an error: %v", err)
	}
	got, ok := out["p"].([]any)
	if !ok || len(got) != 0 {
		t.Errorf("p = %v, want []", out["p"])
	}
}

// §6.1.3.1.1: value with a null operator value REMOVES the parameter, and
// §6.1.3 forbids any operator outputting null.
func TestValueNullRemovesTheParameter(t *testing.T) {
	out, err := apply(t, `{"p": "x", "q": "y"}`, `{"p": {"value": null}}`)
	if err != nil {
		t.Fatal(err)
	}
	if v, present := out["p"]; present {
		t.Errorf("p is still present as %v (null means remove, not set to null)", v)
	}
	if out["q"] != "y" {
		t.Errorf("an unrelated parameter was disturbed: %v", out["q"])
	}
}

// §6.1.3.1.2: "If the metadata parameter is absent, it MUST be initialized with
// the value of this operator", and duplicates are not added twice.
func TestAddInitialisesAndDoesNotDuplicate(t *testing.T) {
	out, err := apply(t, `{}`, `{"p": {"add": ["a","b"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(out["p"].([]any)) != 2 {
		t.Errorf("p = %v, want [a b] from an absent parameter", out["p"])
	}

	out, err = apply(t, `{"p": ["a"]}`, `{"p": {"add": ["a","b"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	got := out["p"].([]any)
	if len(got) != 2 {
		t.Errorf("p = %v; a value already present was added a second time", got)
	}
}

// The order of application, which §6.1.3.1 fixes: subset_of (5th) runs before
// superset_of (6th). So a policy demanding a value that its own subset_of has
// just removed must FAIL -- it describes a set nothing can satisfy.
//
// An implementation that checked superset_of first would accept this, because at
// that moment the value is still there.
func TestSupersetOfIsCheckedAfterSubsetOfHasTrimmed(t *testing.T) {
	// Legal as a combination -- subset_of is a superset of superset_of -- so the
	// combination check passes and only the ORDER of application decides.
	_, err := apply(t,
		`{"p": ["a","b"]}`,
		`{"p": {"subset_of": ["a"], "superset_of": ["a"]}}`)
	if err != nil {
		t.Fatalf("a satisfiable policy was refused: %v", err)
	}

	_, err = apply(t,
		`{"p": ["b"]}`,
		`{"p": {"subset_of": ["a"], "superset_of": ["a"]}}`)
	if err == nil {
		t.Fatal("subset_of removed the only value and superset_of still passed, so " +
			"the operators ran in the wrong order")
	}
}

// §6.1.3.1.8: the `scope` parameter is "to be regarded and processed as a string
// array by policy operators", and the result is re-joined with spaces.
//
// Without this the operator compares the whole string "openid profile email"
// against individual scope values and matches none, so a subset_of on scope
// silently narrows every client to nothing.
func TestScopeIsProcessedAsAnArrayAndRejoined(t *testing.T) {
	out, err := apply(t,
		`{"scope": "openid profile email offline_access"}`,
		`{"scope": {"subset_of": ["openid","profile","email"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := out["scope"].(string)
	if !ok {
		t.Fatalf("scope became %T; §6.1.3.1.8 says the result is a "+
			"space-separated string", out["scope"])
	}
	if got != "openid profile email" {
		t.Errorf("scope = %q, want %q", got, "openid profile email")
	}
}

// The three combinations §6.1.3.1 does NOT permit. one_of constrains a single
// value; add, subset_of and superset_of operate on arrays.
func TestOneOfMayNotBeCombinedWithTheArrayOperators(t *testing.T) {
	for _, other := range []string{"add", "subset_of", "superset_of"} {
		doc := `{"p": {"one_of": ["a"], "` + other + `": ["a"]}}`
		if _, err := apply(t, `{"p": "a"}`, doc); err == nil {
			t.Errorf("one_of combined with %s was accepted", other)
		}
	}
	// And the ones that ARE permitted still work.
	if _, err := apply(t, `{"p": "a"}`,
		`{"p": {"one_of": ["a","b"], "default": "a", "essential": true}}`); err != nil {
		t.Errorf("a permitted combination was refused: %v", err)
	}
}

// §6.1.3.1.1: value combined with one_of requires the value to be among the
// options. A policy that fixes a value its own check forbids is broken whatever
// the subject publishes, so it fails at validation rather than application.
func TestAValueOutsideItsOwnOneOfIsAPolicyError(t *testing.T) {
	if _, err := apply(t, `{"p": "a"}`,
		`{"p": {"value": "z", "one_of": ["a","b"]}}`); err == nil {
		t.Error("a value outside its own one_of was accepted")
	}
}

// value:null with essential:true is the one explicitly excluded combination:
// one removes the parameter and the other requires it.
func TestValueNullWithEssentialTrueIsRefused(t *testing.T) {
	if _, err := apply(t, `{"p": "a"}`,
		`{"p": {"value": null, "essential": true}}`); err == nil {
		t.Error("value:null with essential:true was accepted")
	}
	// essential:false is fine -- the parameter is voluntary and gets removed.
	out, err := apply(t, `{"p": "a"}`, `{"p": {"value": null, "essential": false}}`)
	if err != nil {
		t.Fatalf("value:null with essential:false was refused: %v", err)
	}
	if _, present := out["p"]; present {
		t.Error("the parameter survived value:null")
	}
}

// §6.1.3.1.7 puts essential LAST, and this is the case that depends on it.
//
// The parameter is absent and the policy both supplies a default and marks it
// essential. Applied last, essential judges the parameter as `default` left it
// -- present -- and passes. Applied any earlier, it judges the metadata as
// published and refuses an entity whose policy was about to fix the omission.
//
// Written after a mutation that moved essential to the front of the order
// survived every other test here: nothing else in this file distinguishes its
// position, because none of one_of, subset_of or superset_of change whether a
// parameter is present.
func TestEssentialIsJudgedAfterDefaultHasFilledTheParameter(t *testing.T) {
	out, err := apply(t, `{}`, `{"p": {"default": "x", "essential": true}}`)
	if err != nil {
		t.Fatalf("a parameter the policy itself defaults was refused as missing: %v", err)
	}
	if out["p"] != "x" {
		t.Errorf("p = %v, want the default", out["p"])
	}

	// And with nothing to supply a value, essential still refuses.
	if _, err := apply(t, `{}`, `{"p": {"essential": true}}`); err == nil {
		t.Error("an absent essential parameter with no default was accepted")
	}
}

// Two superiors, two policies, one merged constraint.
//
// Everything above tests a single policy. This is the case §6.1.4.1 is actually
// about: an Intermediate narrowing what the Trust Anchor allowed. The subject
// publishes three response types, the anchor permits two, the intermediate
// permits two overlapping in one -- and the merged subset_of is the
// intersection, so exactly one survives.
//
// Note on the merge DIRECTION, which §6.1.4.1 calls crucial: every standard
// operator's merge is commutative (union, intersection, equality, OR), so with
// only standard operators the resolved policy is the same read from either end.
// The direction still matters, and is implemented as specified, because
// §6.1.3.2 lets a federation define additional operators whose merges need not
// be -- and because an error message that names the wrong superior sends an
// operator to the wrong federation authority.
func TestPoliciesFromTwoSuperiorsMergeToTheIntersection(t *testing.T) {
	fromAnchor := ParamPolicy{OpSubsetOf: []any{"code", "id_token"}}
	fromIntermediate := ParamPolicy{OpSubsetOf: []any{"id_token", "token"}}

	if err := mergeParamPolicy(TypeRelyingParty, "response_types",
		fromAnchor, fromIntermediate); err != nil {
		t.Fatal(err)
	}

	out, err := ApplyPolicy(TypeRelyingParty,
		map[string]any{"response_types": []any{"code", "id_token", "token"}},
		TypePolicy{"response_types": fromAnchor})
	if err != nil {
		t.Fatal(err)
	}
	got := out["response_types"].([]any)
	if len(got) != 1 || got[0] != "id_token" {
		t.Fatalf("response_types = %v, want only id_token: the intermediate may "+
			"narrow what the anchor allowed and may not widen it", got)
	}
}

// The Hierarchy principle (§6.1.1), stated as a test: "Once applied to a
// metadata parameter, a metadata policy cannot be repealed or made more
// permissive by Intermediate Entities that are subordinate in the Trust Chain."
//
// An intermediate that tries to permit something the anchor forbade gets an
// intersection that does not contain it.
func TestASubordinateCannotWidenWhatASuperiorForbade(t *testing.T) {
	fromAnchor := ParamPolicy{OpSubsetOf: []any{"code"}}
	greedy := ParamPolicy{OpSubsetOf: []any{"code", "token", "id_token"}}

	if err := mergeParamPolicy(TypeRelyingParty, "response_types",
		fromAnchor, greedy); err != nil {
		t.Fatal(err)
	}
	merged := fromAnchor[OpSubsetOf].([]any)
	if len(merged) != 1 || merged[0] != "code" {
		t.Fatalf("subset_of merged to %v; an intermediate widened its superior's "+
			"policy", merged)
	}
}

// --- merge rules (§6.1.3.1, "Operator value merge") ----------------------

func mergeTwo(t *testing.T, op string, a, b string) (any, error) {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal([]byte(a), &av); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(b), &bv); err != nil {
		t.Fatal(err)
	}
	return mergeOperatorValues(TypeRelyingParty, "p", op, av, bv)
}

// Each operator merges differently, and the differences are the whole of
// §6.1.1's Hierarchy principle: a subordinate may narrow what a superior allowed
// and may never widen it.
func TestOperatorMergeRules(t *testing.T) {
	// one_of: intersection, and an empty one is an error -- no value could
	// satisfy both superiors.
	got, err := mergeTwo(t, OpOneOf, `["a","b","c"]`, `["b","c","d"]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.([]any)) != 2 {
		t.Errorf("one_of merge = %v, want the intersection [b c]", got)
	}
	if _, err := mergeTwo(t, OpOneOf, `["a"]`, `["b"]`); err == nil {
		t.Error("two one_of policies with no overlap merged without error")
	}

	// subset_of: intersection, and an empty one is NOT an error -- the empty
	// array is a permitted value, unlike one_of, which would permit nothing.
	got, err = mergeTwo(t, OpSubsetOf, `["a"]`, `["b"]`)
	if err != nil {
		t.Fatalf("an empty subset_of intersection was an error: %v", err)
	}
	if len(got.([]any)) != 0 {
		t.Errorf("subset_of merge = %v, want []", got)
	}

	// superset_of and add: union. Two superiors each demanding something means
	// the subject must have both.
	got, err = mergeTwo(t, OpSupersetOf, `["a"]`, `["b"]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.([]any)) != 2 {
		t.Errorf("superset_of merge = %v, want the union [a b]", got)
	}

	// essential: logical OR, so a subordinate can make a voluntary parameter
	// essential but cannot make an essential one voluntary.
	got, err = mergeTwo(t, OpEssential, `true`, `false`)
	if err != nil {
		t.Fatal(err)
	}
	if got != true {
		t.Errorf("essential merge of true and false = %v, want true (OR, not AND)", got)
	}

	// value and default: equal or error. A superior fixing a value is not
	// something a subordinate may restate differently.
	if _, err := mergeTwo(t, OpValue, `"a"`, `"b"`); err == nil {
		t.Error("two different values merged without error")
	}
	if _, err := mergeTwo(t, OpDefault, `"a"`, `"b"`); err == nil {
		t.Error("two different defaults merged without error")
	}
	if _, err := mergeTwo(t, OpValue, `"a"`, `"a"`); err != nil {
		t.Errorf("two equal values failed to merge: %v", err)
	}
}

// The merge is re-validated afterwards, because two individually legal policies
// can combine into an illegal one.
//
// Here each statement alone is fine -- a subset_of that contains its superset_of
// -- but merged, subset_of narrows to {a} while superset_of widens to {a,b}, and
// subset_of is then no longer a superset of superset_of. §6.1.1: "An
// Intermediate that introduces a conflict among the metadata policies causes the
// Trust Chain to be deemed invalid."
func TestAMergeThatProducesAnIllegalCombinationIsAPolicyError(t *testing.T) {
	current := ParamPolicy{
		OpSubsetOf:   []any{"a", "b"},
		OpSupersetOf: []any{"a"},
	}
	next := ParamPolicy{
		OpSubsetOf:   []any{"a"},
		OpSupersetOf: []any{"b"},
	}
	err := mergeParamPolicy(TypeRelyingParty, "p", current, next)
	if err == nil {
		t.Fatal("a merge producing subset_of {a} with superset_of {a,b} was accepted")
	}
	if !strings.Contains(err.Error(), "superset_of") {
		t.Errorf("the error does not name the conflict: %v", err)
	}
}

// §6.1.3: "When the metadata parameter has a JSON value type that is not
// supported, the operator MUST produce a policy error."
//
// A scalar reaching an array operator must fail rather than be wrapped in a
// one-element array -- wrapping would let subset_of quietly succeed against a
// parameter that is not a list at all.
func TestAnArrayOperatorAgainstAScalarIsAPolicyError(t *testing.T) {
	if _, err := apply(t, `{"p": "a"}`, `{"p": {"subset_of": ["a","b"]}}`); err == nil {
		t.Error("subset_of was applied to a string parameter")
	}
}

// Determinism (§6.1.1): the same inputs must give the same output, including the
// order of array values, or a resolved client's redirect_uris would reshuffle
// between resolutions of an unchanged chain.
func TestResolutionIsDeterministic(t *testing.T) {
	const md = `{"p": ["c","a","b"], "q": ["x","y"]}`
	const pol = `{"p": {"subset_of": ["a","b","c"]}, "q": {"add": ["z"]}}`

	first, err := apply(t, md, pol)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(first)
	for i := 0; i < 25; i++ {
		out, err := apply(t, md, pol)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(out)
		if string(got) != string(want) {
			t.Fatalf("run %d differed:\n %s\n %s", i, want, got)
		}
	}
}
