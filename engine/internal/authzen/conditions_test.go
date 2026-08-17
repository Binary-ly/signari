package authzen

import (
	"strings"
	"testing"
	"time"
)

// The extended condition language.
//
// The point of these is not that the features work -- it is that the SPLIT
// between what we verify and what the caller asserts holds, because that split
// is the whole argument for this design over a policy language that mixes them.

const timedModel = `
types:
  ledger:
    relations:
      clerk: []
    permissions:
      post: [clerk]
    require:
      post:
        mfa: true
        subject_active: true
        time:
          days: [mon, tue, wed, thu, fri]
          from: "09:00"
          to: "17:00"
          zone: "Europe/London"
        asserted:
          resource:
            classification: [internal, restricted]
          networks: ["10.0.0.0/8"]
tests:
  - name: inside hours, on the network, everything satisfied
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    at: "2026-08-17T09:30:00Z"
    ip: "10.1.2.3"
    resource_properties: {classification: internal}
    allow: true
  - name: same request at three in the morning
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    at: "2026-08-17T03:30:00Z"
    ip: "10.1.2.3"
    resource_properties: {classification: internal}
    allow: false
  - name: same request on a Sunday
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    at: "2026-08-16T09:30:00Z"
    ip: "10.1.2.3"
    resource_properties: {classification: internal}
    allow: false
  - name: from outside the permitted network
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    at: "2026-08-17T09:30:00Z"
    ip: "203.0.113.9"
    resource_properties: {classification: internal}
    allow: false
  - name: a classification the policy does not allow
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    at: "2026-08-17T09:30:00Z"
    ip: "10.1.2.3"
    resource_properties: {classification: public}
    allow: false
  - name: the caller simply omits the classification
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    at: "2026-08-17T09:30:00Z"
    ip: "10.1.2.3"
    allow: false
  - name: a deactivated account that still holds the relation
    subject: user:alice
    action: post
    resource: ledger:1
    relations: [clerk]
    mfa: true
    active: false
    at: "2026-08-17T09:30:00Z"
    ip: "10.1.2.3"
    resource_properties: {classification: internal}
    allow: false
`

func TestTheExtendedConditionsHoldTheirOwnTests(t *testing.T) {
	if _, err := ParseModel([]byte(timedModel)); err != nil {
		t.Fatalf("the model did not load: %v", err)
	}
}

// An omitted property must not satisfy a requirement about it. Otherwise a
// caller bypasses the rule by leaving the field out, which is the easiest
// bypass there is.
func TestAnOmittedAssertionIsNotASatisfiedOne(t *testing.T) {
	c := Condition{Asserted: &Asserted{Resource: map[string][]string{
		"classification": {"internal"},
	}}}
	if c.SatisfiedBy(Facts{ResourceProps: map[string]any{}}) {
		t.Fatal("an absent property satisfied a requirement about it")
	}
	if c.SatisfiedBy(Facts{}) {
		t.Fatal("nil properties satisfied a requirement")
	}
	if !c.SatisfiedBy(Facts{ResourceProps: map[string]any{"classification": "internal"}}) {
		t.Fatal("a matching property did not satisfy it")
	}
}

// A window with no clock must refuse, not pass.
func TestATimeWindowWithNoClockRefuses(t *testing.T) {
	c := Condition{Time: &TimeWindow{From: "09:00", To: "17:00", Zone: "UTC"}}
	if c.SatisfiedBy(Facts{}) {
		t.Fatal("a time window was satisfied by not knowing the time")
	}
	in, _ := time.Parse(time.RFC3339, "2026-08-17T10:00:00Z")
	if !c.SatisfiedBy(Facts{Now: in}) {
		t.Fatal("ten in the morning fell outside 09:00-17:00 UTC")
	}
}

// A window that wraps midnight is one window, not none.
func TestAWindowCanWrapMidnight(t *testing.T) {
	c := Condition{Time: &TimeWindow{From: "22:00", To: "06:00", Zone: "UTC"}}
	for _, tc := range []struct {
		at   string
		want bool
	}{
		{"2026-08-17T23:00:00Z", true},
		{"2026-08-17T02:00:00Z", true},
		{"2026-08-17T12:00:00Z", false},
		{"2026-08-17T21:59:00Z", false},
	} {
		at, _ := time.Parse(time.RFC3339, tc.at)
		if got := c.SatisfiedBy(Facts{Now: at}); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.at, got, tc.want)
		}
	}
}

// The zone is not optional, because "09:00" without one is nine o'clock
// somewhere.
func TestAModelRefusesConditionsItCannotEvaluate(t *testing.T) {
	for _, c := range []struct{ name, yaml, want string }{
		{
			"a time window with no zone",
			"types:\n  d:\n    relations:\n      o: []\n    permissions:\n      r: [o]\n    require:\n      r:\n        time: {from: \"09:00\", to: \"17:00\"}\n",
			"needs a `zone`",
		},
		{
			"a zone that does not exist",
			"types:\n  d:\n    relations:\n      o: []\n    permissions:\n      r: [o]\n    require:\n      r:\n        time: {from: \"09:00\", to: \"17:00\", zone: \"Mars/Olympus\"}\n",
			"not an IANA time zone",
		},
		{
			"a malformed CIDR",
			"types:\n  d:\n    relations:\n      o: []\n    permissions:\n      r: [o]\n    require:\n      r:\n        asserted: {networks: [\"10.0.0/8\"]}\n",
			"not a CIDR",
		},
		{
			"a resource requirement allowing no values",
			"types:\n  d:\n    relations:\n      o: []\n    permissions:\n      r: [o]\n    require:\n      r:\n        asserted:\n          resource:\n            level: []\n",
			"allows no values",
		},
		{
			"a day that is not a day",
			"types:\n  d:\n    relations:\n      o: []\n    permissions:\n      r: [o]\n    require:\n      r:\n        time: {days: [funday], zone: \"UTC\"}\n",
			"is not a day",
		},
		{
			// A time-window rule whose tests do not pin the clock passes or
			// fails depending on when CI runs, which is worse than no test.
			"a time rule whose test does not pin the clock",
			"types:\n  d:\n    relations:\n      o: []\n    permissions:\n      r: [o]\n    require:\n      r:\n        time: {from: \"09:00\", to: \"17:00\", zone: \"UTC\"}\ntests:\n  - name: t\n    subject: user:a\n    action: r\n    resource: d:1\n    relations: [o]\n    allow: true\n",
			"pin the clock",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseModel([]byte(c.yaml))
			if err == nil {
				t.Fatal("it loaded")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// Every verified requirement must be unaffected by anything the caller sends.
//
// This is the property the whole split exists for: if it ever fails, the
// `asserted:` section is decoration and a compromised relying party can grant
// itself anything.
func TestTheCallerCannotSatisfyAVerifiedRequirement(t *testing.T) {
	c := Condition{MFA: true, SubjectActive: true, EmailVerified: true}

	// A caller stuffing every plausible field into the asserted half.
	forged := Facts{
		ResourceProps: map[string]any{
			"mfa": true, "subject_active": true, "email_verified": true,
			"authenticated": true, "admin": true,
		},
		IP: "10.0.0.1",
	}
	if c.SatisfiedBy(forged) {
		t.Fatal("caller-supplied properties satisfied requirements we verify " +
			"ourselves; the trust boundary does not hold")
	}
	if !c.SatisfiedBy(Facts{MFA: true, Active: true, EmailVerified: true}) {
		t.Fatal("the verified facts did not satisfy it")
	}
}
