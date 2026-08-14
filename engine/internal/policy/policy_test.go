package policy

import (
	"strings"
	"testing"
)

const validFile = `
version: 1
policies:
  - name: admin-console-requires-mfa-and-membership
    when:
      client: admin-console
    require:
      groups: [admins]
      mfa: true
    message: The admin console requires multi-factor authentication.
tests:
  - name: an admin with MFA gets in
    given: {client: admin-console, groups: [admins], mfa: true}
    expect: allow
  - name: an admin WITHOUT MFA does not
    given: {client: admin-console, groups: [admins], mfa: false}
    expect: deny
  - name: a non-admin with MFA does not
    given: {client: admin-console, groups: [staff], mfa: true}
    expect: deny
  - name: another client is unaffected
    given: {client: wiki, groups: [], mfa: false}
    expect: allow
`

func TestValidFileLoads(t *testing.T) {
	f, err := Parse([]byte(validFile))
	if err != nil {
		t.Fatalf("a valid policy was refused: %v", err)
	}
	if len(f.Policies) != 1 || len(f.Tests) != 4 {
		t.Errorf("parsed %d rules, %d tests", len(f.Policies), len(f.Tests))
	}
}

// TestAPolicyThatFailsItsOwnTestsWillNotLoad is the property this package
// exists for.
//
// The rule demands MFA. The author wrote a test saying MFA is not needed. One
// of the two is wrong, and either way the file must not deploy -- because
// whichever they meant, the deployment would not do it.
func TestAPolicyThatFailsItsOwnTestsWillNotLoad(t *testing.T) {
	const lying = `
version: 1
policies:
  - name: requires-mfa
    when: {client: admin-console}
    require: {mfa: true}
tests:
  - name: I believe MFA is not required here
    given: {client: admin-console, mfa: false}
    expect: allow
`
	_, err := Parse([]byte(lying))
	if err == nil {
		t.Fatal("a policy whose behaviour contradicts its own tests was LOADED")
	}
	if !strings.Contains(err.Error(), "does not do what its tests say") {
		t.Errorf("the error should say the tests disagree; got %v", err)
	}
	// And it must name the failing case, so the author knows which.
	if !strings.Contains(err.Error(), "I believe MFA is not required here") {
		t.Errorf("the error should name the failing test; got %v", err)
	}
}

// TestAFileWithNoTestsIsRefused. A policy with no tests is one whose author has
// not written down what they meant, and the whole design compares the two.
func TestAFileWithNoTestsIsRefused(t *testing.T) {
	const noTests = `
version: 1
policies:
  - name: deny-everything
    deny: true
`
	if _, err := Parse([]byte(noTests)); err == nil {
		t.Fatal("a policy with no tests was accepted")
	}
}

// TestMisspelledFieldIsRefused.
//
// `any_groups` is not a field; `any_group` is. Silently ignoring it leaves a
// rule that appears to restrict and demands nothing -- the most dangerous
// possible typo in a file like this.
func TestMisspelledFieldIsRefused(t *testing.T) {
	const typo = `
version: 1
policies:
  - name: staff-only
    when: {client: wiki}
    require:
      any_groups: [staff]
tests:
  - name: anybody
    given: {client: wiki}
    expect: deny
`
	err := func() error { _, e := Parse([]byte(typo)); return e }()
	if err == nil {
		t.Fatal("a misspelled condition field was silently ignored")
	}
	if !strings.Contains(err.Error(), "any_groups") {
		t.Errorf("the error should name the unknown field; got %v", err)
	}
}

func TestUnnamedRuleIsRefused(t *testing.T) {
	const unnamed = `
version: 1
policies:
  - when: {client: x}
    deny: true
tests:
  - name: t
    given: {client: x}
    expect: deny
`
	if _, err := Parse([]byte(unnamed)); err == nil {
		t.Fatal("a rule with no name was accepted; a refusal could not be traced to it")
	}
}

func TestDenyAndRequireTogetherIsRefused(t *testing.T) {
	const both = `
version: 1
policies:
  - name: confused
    when: {client: x}
    deny: true
    require: {mfa: true}
tests:
  - name: t
    given: {client: x}
    expect: deny
`
	if _, err := Parse([]byte(both)); err == nil {
		t.Fatal("a rule that both denies and requires was accepted")
	}
}

func TestBadCIDRIsRefused(t *testing.T) {
	const bad = `
version: 1
policies:
  - name: office-only
    when: {client: x}
    require:
      from_networks: ["10.0.0.0/8", "not-a-network"]
tests:
  - name: t
    given: {client: x, ip: "10.0.0.5"}
    expect: allow
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("an unparseable network was accepted")
	}
}

// TestNoMatchingRuleAllows. Adding a policy file to a running deployment must
// not lock everybody out of everything.
func TestNoMatchingRuleAllows(t *testing.T) {
	f, err := Parse([]byte(validFile))
	if err != nil {
		t.Fatal(err)
	}
	if d := f.Evaluate(Request{Client: "some-other-app"}); !d.Allowed {
		t.Error("a request matching no rule was denied")
	}
}

// TestCatchAllDenyIsExpressible -- default-deny is available, and visible in
// the file rather than being an invisible property of the engine.
func TestCatchAllDenyIsExpressible(t *testing.T) {
	const closed = `
version: 1
default: deny
policies:
  - name: wiki-needs-staff
    when: {client: wiki}
    require: {any_group: [staff, admins]}
tests:
  - name: staff reach the wiki
    given: {client: wiki, groups: [staff]}
    expect: allow
  - name: outsiders do not
    given: {client: wiki, groups: []}
    expect: deny
  - name: an unlisted client is closed
    given: {client: anything-else}
    expect: deny
`
	f, err := Parse([]byte(closed))
	if err != nil {
		t.Fatalf("a default-deny policy was refused: %v", err)
	}
	d := f.Evaluate(Request{Client: "unknown"})
	if d.Allowed {
		t.Error("the catch-all did not deny")
	}
	if d.Rule != "(default)" {
		t.Errorf("rule = %q, want the default named", d.Rule)
	}
}

func TestNetworkRestriction(t *testing.T) {
	const netPolicy = `
version: 1
policies:
  - name: admin-from-office-only
    when: {client: admin}
    require:
      from_networks: ["10.0.0.0/8", "192.168.1.0/24"]
tests:
  - name: from the office
    given: {client: admin, ip: "10.1.2.3"}
    expect: allow
  - name: from the other office
    given: {client: admin, ip: "192.168.1.50"}
    expect: allow
  - name: from anywhere else
    given: {client: admin, ip: "203.0.113.9"}
    expect: deny
  - name: with NO address at all
    given: {client: admin}
    expect: deny
`
	if _, err := Parse([]byte(netPolicy)); err != nil {
		t.Fatalf("the network policy failed its own tests: %v", err)
	}
}

// TestUnknownAddressFailsClosed is worth its own test.
//
// Treating "we do not know where this came from" as "inside the office" is how
// a network restriction becomes decorative behind a proxy that strips the
// address.
func TestUnknownAddressFailsClosed(t *testing.T) {
	f := &File{Policies: []Rule{{
		Name:    "office-only",
		Require: Conditions{FromNetworks: []string{"10.0.0.0/8"}},
	}}}
	for _, ip := range []string{"", "not-an-ip", "  "} {
		if d := f.Evaluate(Request{Client: "x", IP: ip}); d.Allowed {
			t.Errorf("an unparseable address (%q) satisfied a network restriction", ip)
		}
	}
}

func TestScopeMatching(t *testing.T) {
	const scoped = `
version: 1
policies:
  - name: admin-scope-needs-mfa
    when: {scope: admin}
    require: {mfa: true}
tests:
  - name: admin scope with MFA
    given: {client: app, scope: "openid admin", mfa: true}
    expect: allow
  - name: admin scope without MFA
    given: {client: app, scope: "openid admin", mfa: false}
    expect: deny
  - name: ordinary scopes are unaffected
    given: {client: app, scope: "openid profile", mfa: false}
    expect: allow
  - name: a scope that merely CONTAINS the word does not match
    given: {client: app, scope: "openid administrator", mfa: false}
    expect: allow
`
	if _, err := Parse([]byte(scoped)); err != nil {
		t.Fatalf("the scope policy failed its own tests: %v", err)
	}
}

func TestFirstRefusalWins(t *testing.T) {
	const two = `
version: 1
policies:
  - name: first
    when: {client: x}
    require: {mfa: true}
  - name: second
    when: {client: x}
    require: {groups: [admins]}
tests:
  - name: fails the first
    given: {client: x, mfa: false, groups: [admins]}
    expect: deny
  - name: passes both
    given: {client: x, mfa: true, groups: [admins]}
    expect: allow
`
	f, err := Parse([]byte(two))
	if err != nil {
		t.Fatal(err)
	}
	d := f.Evaluate(Request{Client: "x", MFA: false, Groups: []string{"admins"}})
	if d.Rule != "first" {
		t.Errorf("rule = %q, want the first refusal to be reported", d.Rule)
	}
}

func TestVersionIsChecked(t *testing.T) {
	if _, err := Parse([]byte("version: 2\npolicies: []\ntests: []\n")); err == nil {
		t.Error("an unsupported version was accepted")
	}
}

// TestImpossibleTravelCondition.
//
// Note the third case: the condition is satisfied when the check could not run.
// A condition that failed whenever it could not be evaluated would lock out
// every first-time user and every deployment without a GeoIP database -- which
// is how a risk signal becomes an outage.
func TestImpossibleTravelCondition(t *testing.T) {
	const travel = `
version: 1
policies:
  - name: refuse-impossible-travel
    when: {client: bank}
    require: {no_impossible_travel: true}
    message: This sign-in came from an unexpected place. Contact support.
tests:
  - name: an ordinary sign-in
    given: {client: bank, impossible_travel: false}
    expect: allow
  - name: a sign-in from two places at once
    given: {client: bank, impossible_travel: true}
    expect: deny
  - name: a first sign-in, with nothing to compare against
    given: {client: bank}
    expect: allow
`
	if _, err := Parse([]byte(travel)); err != nil {
		t.Fatalf("the travel policy failed its own tests: %v", err)
	}
}
