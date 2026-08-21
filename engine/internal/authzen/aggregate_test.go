package authzen

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustModel(t *testing.T, doc string) *Model {
	t.Helper()
	var m Model
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	if err := m.validate(); err != nil {
		t.Fatalf("model did not validate: %v", err)
	}
	return &m
}

const aggregateModel = `
policies:
  managed_device:
    device_managed: true
  in_hours:
    time:
      days: [mon, tue, wed, thu, fri]
      from: "09:00"
      to: "17:00"
      zone: UTC
  second_factor:
    mfa: true
types:
  document:
    relations:
      owner: []
      editor: [owner]
    permissions:
      write: [editor]
    require:
      write:
        strategy: %s
        policies: [managed_device, second_factor]
`

func ruleFor(t *testing.T, strategy string) Rule {
	t.Helper()
	m := mustModel(t, strings_Replace(aggregateModel, strategy))
	r, ok := m.ConditionFor("document", "write")
	if !ok {
		t.Fatal("no rule for document.write")
	}
	return r
}

func strings_Replace(doc, strategy string) string {
	return strings.Replace(doc, "%s", strategy, 1)
}

// The three strategies, against the same two policies, with the facts varied so
// each row distinguishes them.
func TestDecisionStrategies(t *testing.T) {
	both := Facts{DeviceManaged: true, MFA: true}
	one := Facts{DeviceManaged: true}
	neither := Facts{}

	cases := []struct {
		strategy                       string
		wantBoth, wantOne, wantNeither bool
	}{
		{StrategyUnanimous, true, false, false},
		{StrategyAffirmative, true, true, false},
		{StrategyConsensus, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.strategy, func(t *testing.T) {
			r := ruleFor(t, tc.strategy)
			if got := r.SatisfiedBy(both); got != tc.wantBoth {
				t.Errorf("both satisfied = %v, want %v", got, tc.wantBoth)
			}
			if got := r.SatisfiedBy(one); got != tc.wantOne {
				t.Errorf("one satisfied = %v, want %v", got, tc.wantOne)
			}
			if got := r.SatisfiedBy(neither); got != tc.wantNeither {
				t.Errorf("neither satisfied = %v, want %v", got, tc.wantNeither)
			}
		})
	}
}

// Consensus with THREE policies, where two of three genuinely is a majority.
// Without this the consensus row above is indistinguishable from unanimous.
func TestConsensusPassesOnARealMajority(t *testing.T) {
	m := mustModel(t, `
policies:
  a: {device_managed: true}
  b: {mfa: true}
  c: {email_verified: true}
types:
  document:
    relations: {owner: []}
    permissions: {write: [owner]}
    require:
      write:
        strategy: consensus
        policies: [a, b, c]
`)
	r, _ := m.ConditionFor("document", "write")

	if !r.SatisfiedBy(Facts{DeviceManaged: true, MFA: true}) {
		t.Error("two of three did not reach consensus")
	}
	if r.SatisfiedBy(Facts{DeviceManaged: true}) {
		t.Error("one of three reached consensus")
	}
}

// An inline requirement is ANDed with the combined policies, never outvoted.
//
// Otherwise adding a policy under `affirmative` could REMOVE a requirement
// written directly beside it, which is the opposite of what somebody editing the
// rule expects.
func TestAnInlineRequirementIsNotOutvoted(t *testing.T) {
	m := mustModel(t, `
policies:
  a: {device_managed: true}
  b: {email_verified: true}
types:
  document:
    relations: {owner: []}
    permissions: {write: [owner]}
    require:
      write:
        mfa: true
        strategy: affirmative
        policies: [a, b]
`)
	r, _ := m.ConditionFor("document", "write")

	// Affirmative is satisfied by policy a, but mfa is written inline.
	if r.SatisfiedBy(Facts{DeviceManaged: true}) {
		t.Fatal("an affirmative policy satisfied a rule whose inline mfa requirement " +
			"was not met")
	}
	if !r.SatisfiedBy(Facts{DeviceManaged: true, MFA: true}) {
		t.Fatal("both the inline requirement and a policy were met and it still refused")
	}
}

// A rule naming a policy that does not exist must not parse.
//
// It is the dangerous typo: the rule still loads, the clause never fires, and
// the permission is quietly granted.
func TestARuleNamingAnUndefinedPolicyIsRefused(t *testing.T) {
	var m Model
	if err := yaml.Unmarshal([]byte(`
policies:
  managed_device: {device_managed: true}
types:
  document:
    relations: {owner: []}
    permissions: {write: [owner]}
    require:
      write:
        policies: [managed_devcie]
`), &m); err != nil {
		t.Fatal(err)
	}
	err := m.validate()
	if err == nil {
		t.Fatal("a rule naming an undefined policy was accepted; the requirement " +
			"would silently not apply")
	}
	if !strings.Contains(err.Error(), "managed_devcie") {
		t.Errorf("the error does not name the typo: %v", err)
	}
}

func TestModelValidationRejectsBadCompositions(t *testing.T) {
	cases := map[string]string{
		"unknown strategy": `
policies: {a: {mfa: true}}
types:
  d: {relations: {o: []}, permissions: {w: [o]}, require: {w: {strategy: sometimes, policies: [a]}}}`,
		"strategy with no policies": `
policies: {a: {mfa: true}}
types:
  d: {relations: {o: []}, permissions: {w: [o]}, require: {w: {strategy: consensus, mfa: true}}}`,
		"empty policy": `
policies: {a: {}}
types:
  d: {relations: {o: []}, permissions: {w: [o]}, require: {w: {policies: [a]}}}`,
		"nested composition": `
policies:
  a: {mfa: true}
  b: {policies: [a]}
types:
  d: {relations: {o: []}, permissions: {w: [o]}, require: {w: {policies: [b]}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			var m Model
			if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
				t.Fatal(err)
			}
			if err := m.validate(); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// The refusal names which policies failed. "Consensus not reached" tells an
// operator nothing about which rule to go and look at.
func TestTheRefusalNamesTheFailedPolicies(t *testing.T) {
	r := ruleFor(t, StrategyUnanimous)
	got := r.Unmet(Facts{DeviceManaged: true})
	if !strings.Contains(got, "second_factor") {
		t.Errorf("Unmet = %q; it should name the policy that failed", got)
	}
}
