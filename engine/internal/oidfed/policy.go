package oidfed

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Metadata policy: OpenID Federation 1.0 §6.1.
//
// # What a policy is for, and why refusing to apply one was not good enough
//
// A superior constrains its subordinates through `metadata_policy`: which
// signing algorithms a relying party may ask for, which scopes, which redirect
// URIs. §6.1.4 makes applying it part of chain validation rather than an
// optional extra:
//
//	"If a policy error or another error is encountered during the metadata
//	policy resolution or its application, the Trust Chain MUST be considered
//	invalid."
//
// Until now this package refused any chain carrying a policy. That was the right
// failure while the operators were unimplemented -- resolving a chain and then
// using the leaf's own metadata produces the answer the SUBORDINATE wanted
// rather than the one its federation allows -- but it also meant Signari could
// not join any federation that uses policy, which is most of them.
//
// # The two halves
//
// §6.1.4.1 RESOLUTION merges the policies of every Subordinate Statement in the
// chain into one, from the most superior downwards. §6.1.4.2 APPLICATION runs
// the merged policy against the subject's metadata. They are separate because
// merging can fail on its own: two superiors can state policies that cannot both
// hold, and that is a broken federation regardless of what any subject publishes.
//
// # Determinism
//
// §6.1.1 lists it as a principle: "The resolution and application of metadata
// policies in a Trust Chain is deterministic." Everything here that could depend
// on map iteration order sorts first, so the same chain always yields the same
// metadata and the same error.

// Policy operator names (§6.1.3.1).
const (
	OpValue      = "value"
	OpAdd        = "add"
	OpDefault    = "default"
	OpOneOf      = "one_of"
	OpSubsetOf   = "subset_of"
	OpSupersetOf = "superset_of"
	OpEssential  = "essential"
)

// operatorOrder is the sequence §6.1.3.1 fixes for application.
//
// Each operator's definition states its own position -- `value` is "First",
// `essential` is "Last", and the rest are each specified as "After <previous>".
// Written out here rather than derived, because the order is not an
// implementation choice: `subset_of` trimming values BEFORE `superset_of` checks
// them is what makes a policy that demands what it also forbids fail, which is
// the behaviour §6.1.1 calls Equal Opportunity.
var operatorOrder = []string{
	OpValue, OpAdd, OpDefault, OpOneOf, OpSubsetOf, OpSupersetOf, OpEssential,
}

func isStandardOperator(name string) bool {
	for _, o := range operatorOrder {
		if o == name {
			return true
		}
	}
	return false
}

// ParamPolicy is the operators applying to one metadata parameter.
type ParamPolicy map[string]any

// TypePolicy is the parameter policies for one Entity Type.
type TypePolicy map[string]ParamPolicy

// Policy is a whole `metadata_policy` claim: Entity Type → parameter → operator.
//
// The three levels of §6.1.2, kept as three maps, because the merge in §6.1.4.1
// is defined level by level and flattening them would mean re-deriving which
// level a given conflict belongs to.
type Policy map[string]TypePolicy

// allowedCombinations records which operators may appear together (§6.1.3.1).
//
// Each operator "MUST declare what other operators it may be combined with...
// Combinations that are not allowed MUST produce a policy error." The
// declarations are symmetric in the specification, and the three absences are
// the interesting content: `one_of` may be combined with `value`, `default` and
// `essential` and NOTHING else, so `add`+`one_of`, `one_of`+`subset_of` and
// `one_of`+`superset_of` are each a policy error.
//
// That is not an arbitrary gap. `one_of` constrains a single value while `add`,
// `subset_of` and `superset_of` operate on arrays, so combining them would be
// asking one parameter to be both.
var allowedCombinations = map[string]map[string]bool{
	OpValue:      {OpAdd: true, OpDefault: true, OpOneOf: true, OpSubsetOf: true, OpSupersetOf: true, OpEssential: true},
	OpAdd:        {OpValue: true, OpDefault: true, OpSubsetOf: true, OpSupersetOf: true, OpEssential: true},
	OpDefault:    {OpValue: true, OpAdd: true, OpOneOf: true, OpSubsetOf: true, OpSupersetOf: true, OpEssential: true},
	OpOneOf:      {OpValue: true, OpDefault: true, OpEssential: true},
	OpSubsetOf:   {OpValue: true, OpAdd: true, OpDefault: true, OpSupersetOf: true, OpEssential: true},
	OpSupersetOf: {OpValue: true, OpAdd: true, OpDefault: true, OpSubsetOf: true, OpEssential: true},
	OpEssential:  {OpValue: true, OpAdd: true, OpDefault: true, OpOneOf: true, OpSubsetOf: true, OpSupersetOf: true},
}

// PolicyError is a §6.1.4 policy error. Every one invalidates the chain.
type PolicyError struct {
	EntityType string
	Parameter  string
	Reason     string
}

func (e *PolicyError) Error() string {
	switch {
	case e.EntityType == "":
		return "metadata policy error: " + e.Reason
	case e.Parameter == "":
		return fmt.Sprintf("metadata policy error in %s: %s", e.EntityType, e.Reason)
	}
	return fmt.Sprintf("metadata policy error in %s.%s: %s", e.EntityType, e.Parameter, e.Reason)
}

func policyErr(entityType, param, format string, args ...any) *PolicyError {
	return &PolicyError{EntityType: entityType, Parameter: param,
		Reason: fmt.Sprintf(format, args...)}
}

// ResolvePolicy merges the policies of a chain's Subordinate Statements (§6.1.4.1).
//
// chain is the order ValidateChain expects: the subject's Entity Configuration
// first, then each superior's Subordinate Statement, ending with the Trust
// Anchor's. §6.1.4.1 fixes the direction of the merge and calls it crucial:
//
//	"It MUST begin with the Subordinate Statement issued by the most Superior
//	Entity and end with the Subordinate Statement issued by the Immediate
//	Superior of the Trust Chain subject."
//
// So the iteration runs BACKWARDS over the chain. Getting this the other way
// round does not fail loudly: it produces a valid-looking policy in which a
// subordinate's operators are merged first, which for order-dependent merges
// silently changes what the federation permits.
func ResolvePolicy(chain []Statement) (Policy, error) {
	if len(chain) < 2 {
		return nil, nil // nothing above the subject, so no Subordinate Statements
	}

	// §6.1.4.1: "The resolution process MUST FIRST gather the names of all policy
	// operators other than the standard ones... that are declared as critical."
	//
	// First, over the whole chain, before any policy is looked at -- because a
	// superior may declare an operator critical that only a subordinate uses, and
	// gathering as we go would let that one through.
	crit := map[string]bool{}
	for i := 1; i < len(chain); i++ {
		names, err := metadataPolicyCritOf(chain[i])
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			crit[n] = true
		}
	}

	var current Policy
	for i := len(chain) - 1; i >= 1; i-- {
		next, err := metadataPolicyOf(chain[i])
		if err != nil {
			return nil, err
		}
		if next == nil {
			continue
		}
		if err := validatePolicy(next, crit); err != nil {
			return nil, err
		}
		if current == nil {
			current = next
			continue
		}
		if err := mergePolicy(current, next); err != nil {
			return nil, err
		}
	}
	return current, nil
}

// validatePolicy checks one statement's policy before it is merged (§6.1.4.1).
//
// "It MUST ensure the data structure is compliant and that every metadata
// parameter policy contains only allowed operator combinations... It MUST also
// be ensured that the metadata_policy contains no operators that cannot be
// understood and processed whose names are among the collected
// metadata_policy_crit values."
//
// Unknown operators are DELETED here rather than carried, because §6.1.3.2 says
// "Implementations MUST ignore additional operators that are not understood" --
// and an operator kept in the structure but skipped at application time is one
// somebody later mistakes for supported.
func validatePolicy(p Policy, crit map[string]bool) error {
	for entityType, tp := range p {
		for param, pp := range tp {
			for _, name := range sortedKeys(pp) {
				if isStandardOperator(name) {
					continue
				}
				if crit[name] {
					// §6.1.3.2: "If an additional operator listed in
					// metadata_policy_crit is not understood or cannot be
					// processed, then this MUST produce a policy error and the
					// Trust Chain MUST be considered invalid."
					return policyErr(entityType, param,
						"the operator %q is declared critical in metadata_policy_crit "+
							"and this implementation does not understand it, so the "+
							"constraint it expresses cannot be honoured", name)
				}
				delete(pp, name)
			}
			if err := validateParamPolicy(entityType, param, pp); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateParamPolicy enforces the operator combination rules (§6.1.3).
func validateParamPolicy(entityType, param string, pp ParamPolicy) error {
	names := sortedKeys(pp)
	for _, a := range names {
		for _, b := range names {
			if a == b {
				continue
			}
			if !allowedCombinations[a][b] {
				return policyErr(entityType, param,
					"the operators %q and %q may not be combined: %s constrains a "+
						"single value while the other operates on arrays, so a "+
						"parameter cannot satisfy both", a, b, a)
			}
		}
	}

	// The conditional combinations. Each is stated in the operator's own
	// definition, and each describes a policy that is self-contradictory rather
	// than merely strict -- a `value` outside its own `one_of`, an `add` of
	// something `subset_of` forbids.
	val, hasVal := pp[OpValue]
	if hasVal {
		if val == nil {
			// "MAY be combined with default if the value of value is not null."
			if _, ok := pp[OpDefault]; ok {
				return policyErr(entityType, param,
					"value is null, which removes the parameter, and default would "+
						"then supply one: the two cannot both apply")
			}
			// "MAY be combined with essential, except when value is null and
			// essential is true."
			if e, ok := pp[OpEssential]; ok {
				b, ok := e.(bool)
				if !ok {
					return policyErr(entityType, param,
						"essential must be a boolean, got %s", jsonKind(e))
				}
				if b {
					return policyErr(entityType, param,
						"value is null, which removes the parameter, while essential "+
							"is true, which requires it to be present")
				}
			}
		}
		if adds, ok := pp[OpAdd]; ok {
			if err := requireSubset(entityType, param, adds, val, "add", "value"); err != nil {
				return err
			}
		}
		if opts, ok := pp[OpOneOf]; ok && val != nil {
			list, err := asArray(entityType, param, OpOneOf, opts)
			if err != nil {
				return err
			}
			if !containsValue(list, val) {
				return policyErr(entityType, param,
					"value %s is not among the one_of options %s", jsonOf(val), jsonOf(opts))
			}
		}
		if sub, ok := pp[OpSubsetOf]; ok && val != nil {
			if err := requireSubset(entityType, param, val, sub, "value", "subset_of"); err != nil {
				return err
			}
		}
		if sup, ok := pp[OpSupersetOf]; ok && val != nil {
			if err := requireSubset(entityType, param, sup, val, "superset_of", "value"); err != nil {
				return err
			}
		}
	}
	if adds, ok := pp[OpAdd]; ok {
		if sub, ok := pp[OpSubsetOf]; ok {
			if err := requireSubset(entityType, param, adds, sub, "add", "subset_of"); err != nil {
				return err
			}
		}
	}
	if sub, ok := pp[OpSubsetOf]; ok {
		if sup, ok := pp[OpSupersetOf]; ok {
			// "MAY be combined with superset_of, in which case the values of
			// subset_of MUST be a superset of the values of superset_of."
			if err := requireSubset(entityType, param, sup, sub, "superset_of", "subset_of"); err != nil {
				return err
			}
		}
	}
	if e, ok := pp[OpEssential]; ok {
		if _, isBool := e.(bool); !isBool {
			return policyErr(entityType, param,
				"essential must be a boolean, got %s", jsonKind(e))
		}
	}
	return nil
}

// requireSubset checks that every value of `inner` appears in `outer`.
func requireSubset(entityType, param string, inner, outer any, innerName, outerName string) error {
	in, err := asArray(entityType, param, innerName, inner)
	if err != nil {
		return err
	}
	out, err := asArray(entityType, param, outerName, outer)
	if err != nil {
		return err
	}
	for _, v := range in {
		if !containsValue(out, v) {
			return policyErr(entityType, param,
				"%s contains %s, which %s does not permit", innerName, jsonOf(v), outerName)
		}
	}
	return nil
}

// mergePolicy merges a subordinate's policy into the current one (§6.1.4.1).
//
// Three levels, top down, exactly as the specification describes them: entity
// types, then parameters, then operators. Anything present only in the
// subordinate is copied; anything present in both is merged one level deeper.
func mergePolicy(current, next Policy) error {
	for _, entityType := range sortedTypeKeys(next) {
		nt := next[entityType]
		ct, ok := current[entityType]
		if !ok {
			current[entityType] = nt
			continue
		}
		for _, param := range sortedParamKeys(nt) {
			np := nt[param]
			cp, ok := ct[param]
			if !ok {
				ct[param] = np
				continue
			}
			if err := mergeParamPolicy(entityType, param, cp, np); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeParamPolicy merges operators for one parameter (§6.1.4.1, operator level).
func mergeParamPolicy(entityType, param string, current, next ParamPolicy) error {
	for _, name := range sortedKeys(next) {
		nv := next[name]
		cv, ok := current[name]
		if !ok {
			current[name] = nv
			continue
		}
		merged, err := mergeOperatorValues(entityType, param, name, cv, nv)
		if err != nil {
			return err
		}
		current[name] = merged
	}
	// §6.1.4.1: "If the resulting metadata parameter policy contains combinations
	// that are not allowed... this MUST produce a policy error."
	//
	// Re-checked AFTER the merge, not only before it. Two policies that are each
	// individually legal can combine into one that is not -- a superior's
	// `subset_of` narrowed until it no longer contains a subordinate's
	// `superset_of` is the case that matters, and it is exactly the conflict
	// §6.1.1 says makes the chain invalid.
	return validateParamPolicy(entityType, param, current)
}

// mergeOperatorValues applies each operator's own merge rule (§6.1.3.1).
func mergeOperatorValues(entityType, param, name string, current, next any) (any, error) {
	switch name {
	case OpValue:
		// "Allowed only when the operator values are equal."
		if !sameValue(current, next) {
			return nil, policyErr(entityType, param,
				"two superiors set value to different things (%s and %s); a "+
					"subordinate cannot repeal what a superior fixed",
				jsonOf(current), jsonOf(next))
		}
		return current, nil

	case OpDefault:
		// "The operator values MUST be equal."
		if !sameValue(current, next) {
			return nil, policyErr(entityType, param,
				"two superiors set different defaults (%s and %s)",
				jsonOf(current), jsonOf(next))
		}
		return current, nil

	case OpAdd, OpSupersetOf:
		// "The result of merging... is the union of the values."
		a, err := asArray(entityType, param, name, current)
		if err != nil {
			return nil, err
		}
		b, err := asArray(entityType, param, name, next)
		if err != nil {
			return nil, err
		}
		return union(a, b), nil

	case OpOneOf:
		// "...is the intersection of the operator values. If the intersection is
		// empty, this MUST result in a policy error."
		a, err := asArray(entityType, param, name, current)
		if err != nil {
			return nil, err
		}
		b, err := asArray(entityType, param, name, next)
		if err != nil {
			return nil, err
		}
		got := intersection(a, b)
		if len(got) == 0 {
			return nil, policyErr(entityType, param,
				"the one_of options of two superiors do not overlap (%s and %s), so "+
					"no value could satisfy both", jsonOf(current), jsonOf(next))
		}
		return got, nil

	case OpSubsetOf:
		// "...is the intersection of the operator values. Note that the resulting
		// intersection may thus be an empty array []."
		//
		// Empty is NOT an error here, unlike one_of. The difference is real: an
		// empty subset_of permits the empty array, which is a value; an empty
		// one_of permits nothing at all.
		a, err := asArray(entityType, param, name, current)
		if err != nil {
			return nil, err
		}
		b, err := asArray(entityType, param, name, next)
		if err != nil {
			return nil, err
		}
		return intersection(a, b), nil

	case OpEssential:
		// "...is the logical disjunction (OR) of the operator values."
		//
		// OR rather than AND, so a subordinate can make a parameter essential
		// that a superior left voluntary but cannot make a superior's essential
		// parameter optional. That is §6.1.1's Hierarchy principle in one line.
		a, aok := current.(bool)
		b, bok := next.(bool)
		if !aok || !bok {
			return nil, policyErr(entityType, param, "essential must be a boolean")
		}
		return a || b, nil
	}
	return nil, policyErr(entityType, param, "unknown operator %q", name)
}

// ApplyPolicy applies a resolved Entity Type policy to metadata (§6.1.4.2).
//
// Returns the resolved metadata. The input is not modified.
func ApplyPolicy(entityType string, metadata map[string]any, tp TypePolicy) (map[string]any, error) {
	out := make(map[string]any, len(metadata))
	for k, v := range metadata {
		out[k] = v
	}
	if tp == nil {
		return out, nil
	}

	for _, param := range sortedParamKeys(tp) {
		pp := tp[param]
		val, present := out[param]

		// §6.1.3.1.8: the `scope` parameter "is to be regarded and processed as a
		// string array by policy operators", and the result is re-joined into a
		// space-separated string. Without this a `subset_of` on scope compares one
		// long string against a list of individual scope values and matches
		// nothing, so the policy silently narrows every client to no scopes at all.
		asScope := param == "scope" && present && isString(val)
		if asScope {
			val = splitScopeValue(val.(string))
		}

		newVal, newPresent, err := applyOperators(entityType, param, val, present, pp)
		if err != nil {
			return nil, err
		}
		if !newPresent {
			delete(out, param)
			continue
		}
		if asScope {
			if arr, ok := newVal.([]any); ok {
				newVal = joinScopeValue(arr)
			}
		}
		// §6.1.3: "An operator MUST NOT output a metadata parameter with the null
		// value." A parameter is removed, not set to null.
		if newVal == nil {
			delete(out, param)
			continue
		}
		out[param] = newVal
	}
	return out, nil
}

// applyOperators runs one parameter's operators in the fixed order.
func applyOperators(entityType, param string, val any, present bool,
	pp ParamPolicy) (any, bool, error) {

	for _, name := range operatorOrder {
		cfg, ok := pp[name]
		if !ok {
			continue
		}
		switch name {
		case OpValue:
			// "The metadata parameter MUST be assigned the value of the operator.
			// When the value of the operator is null, the metadata parameter MUST
			// be removed."
			if cfg == nil {
				val, present = nil, false
				continue
			}
			val, present = cfg, true

		case OpAdd:
			// "The value or values of this operator MUST be added... Values that
			// are already present MUST NOT be added another time. If the metadata
			// parameter is absent, it MUST be initialized with the value of this
			// operator."
			adds, err := asArray(entityType, param, name, cfg)
			if err != nil {
				return nil, false, err
			}
			if !present {
				val, present = append([]any{}, adds...), true
				continue
			}
			cur, err := asArray(entityType, param, name, val)
			if err != nil {
				return nil, false, err
			}
			val = union(cur, adds)

		case OpDefault:
			// "If the metadata parameter is absent, it MUST be set to the value of
			// the operator. If the metadata parameter is present, this operator has
			// no effect."
			if !present {
				val, present = cfg, true
			}

		case OpOneOf:
			// "If the metadata parameter is present, its value MUST be one of
			// those listed in the operator value."
			if !present {
				continue
			}
			opts, err := asArray(entityType, param, name, cfg)
			if err != nil {
				return nil, false, err
			}
			if !containsValue(opts, val) {
				return nil, false, policyErr(entityType, param,
					"the published value %s is not one of %s", jsonOf(val), jsonOf(cfg))
			}

		case OpSubsetOf:
			// "If the metadata parameter is present, it is assigned the
			// intersection between the values of the operator and the metadata
			// parameter." A value modifier, not only a check -- so a client
			// asking for more than the federation permits is TRIMMED rather than
			// rejected, which is what lets one policy serve subordinates that
			// publish different things.
			if !present {
				continue
			}
			allowed, err := asArray(entityType, param, name, cfg)
			if err != nil {
				return nil, false, err
			}
			cur, err := asArray(entityType, param, name, val)
			if err != nil {
				return nil, false, err
			}
			val = intersection(cur, allowed)

		case OpSupersetOf:
			// "If the metadata parameter is present, its values MUST contain those
			// specified in the operator value."
			//
			// Applied AFTER subset_of, per the stated order, so a policy whose
			// subset_of has already removed what its superset_of demands fails
			// here. That is the intended outcome: the two operators together
			// describe a set the metadata cannot satisfy.
			if !present {
				continue
			}
			required, err := asArray(entityType, param, name, cfg)
			if err != nil {
				return nil, false, err
			}
			cur, err := asArray(entityType, param, name, val)
			if err != nil {
				return nil, false, err
			}
			for _, r := range required {
				if !containsValue(cur, r) {
					return nil, false, policyErr(entityType, param,
						"the value must contain %s and does not (it is %s)",
						jsonOf(r), jsonOf(val))
				}
			}

		case OpEssential:
			// "If the value of this operator is true, then the metadata parameter
			// MUST be present."
			//
			// Last, so it judges the parameter as the earlier operators left it.
			// Table 1 of §6.1.3.1.8 is the case worth stating: with essential
			// false and the parameter absent, the subset_of check is skipped and
			// the parameter stays absent -- it does not become [].
			b, ok := cfg.(bool)
			if !ok {
				return nil, false, policyErr(entityType, param,
					"essential must be a boolean, got %s", jsonKind(cfg))
			}
			if b && !present {
				return nil, false, policyErr(entityType, param,
					"the policy marks this parameter essential and the entity "+
						"publishes no value for it")
			}
		}
	}
	return val, present, nil
}

// --- value helpers -------------------------------------------------------
//
// Comparison is by canonical JSON encoding rather than by Go equality.
//
// §6.1.3.1.8 makes object support OPTIONAL for most operators precisely because
// "some JSON libraries may have issues comparing JSON objects". Go's encoder
// sorts object keys, so encoding is a total, stable order for every JSON value
// including nested objects -- which means supporting them costs nothing here and
// removes a class of "policy silently did not match" that is very hard to see.

func valueKey(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

func sameValue(a, b any) bool { return valueKey(a) == valueKey(b) }

func containsValue(list []any, v any) bool {
	want := valueKey(v)
	for _, item := range list {
		if valueKey(item) == want {
			return true
		}
	}
	return false
}

func union(a, b []any) []any {
	out := append([]any{}, a...)
	for _, v := range b {
		if !containsValue(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// intersection keeps the order of the FIRST argument.
//
// §6.1.3 says "The order of the result of such an operator value merge is not
// defined", so any order is conformant -- but an undefined order is not the same
// as an arbitrary one. Preserving the left operand's order makes the output a
// function of the input, which is what §6.1.1's Determinism principle asks for.
func intersection(a, b []any) []any {
	out := []any{}
	for _, v := range a {
		if containsValue(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// asArray coerces an operator or metadata value to a JSON array.
//
// §6.1.3: "When the metadata parameter has a JSON value type that is not
// supported, the operator MUST produce a policy error." A scalar reaching an
// array operator is that error, not something to wrap in a one-element array --
// wrapping would let `subset_of` succeed against a parameter that is not a list
// at all, which is the shape of an accidental permit.
func asArray(entityType, param, op string, v any) ([]any, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, policyErr(entityType, param,
			"the %s operator works on arrays and this is %s", op, jsonKind(v))
	}
	return arr, nil
}

func isString(v any) bool { _, ok := v.(string); return ok }

func splitScopeValue(s string) []any {
	out := []any{}
	for _, f := range strings.Fields(s) {
		out = append(out, f)
	}
	return out
}

func joinScopeValue(arr []any) string {
	parts := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

func jsonOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unencodable>"
	}
	return string(b)
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case float64, json.Number:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	}
	return fmt.Sprintf("%T", v)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedParamKeys(m map[string]ParamPolicy) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTypeKeys(m map[string]TypePolicy) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- reading the claims off a statement ----------------------------------

func metadataPolicyOf(st Statement) (Policy, error) {
	payload, err := claimsOf(st)
	if err != nil {
		return nil, err
	}
	var claims struct {
		MetadataPolicy map[string]map[string]map[string]json.RawMessage `json:"metadata_policy"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("the metadata_policy of the statement issued by %s "+
			"did not parse: %w", st.Issuer, err)
	}
	if claims.MetadataPolicy == nil {
		return nil, nil
	}
	p := Policy{}
	for entityType, params := range claims.MetadataPolicy {
		tp := TypePolicy{}
		for param, ops := range params {
			pp := ParamPolicy{}
			for name, raw := range ops {
				var v any
				if err := json.Unmarshal(raw, &v); err != nil {
					return nil, policyErr(entityType, param,
						"the %s operator value did not parse: %v", name, err)
				}
				pp[name] = v
			}
			tp[param] = pp
		}
		p[entityType] = tp
	}
	return p, nil
}

func metadataPolicyCritOf(st Statement) ([]string, error) {
	payload, err := claimsOf(st)
	if err != nil {
		return nil, err
	}
	var claims struct {
		Crit []string `json:"metadata_policy_crit"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims.Crit, nil
}

// superiorMetadataOf reads the `metadata` claim a superior asserted about its
// subordinate (§3.1.1).
func superiorMetadataOf(st Statement) (map[string]map[string]any, error) {
	payload, err := claimsOf(st)
	if err != nil {
		return nil, err
	}
	var claims struct {
		Metadata map[string]map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims.Metadata, nil
}
