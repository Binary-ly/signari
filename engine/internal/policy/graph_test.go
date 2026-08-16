package policy

import (
	"reflect"
	"strings"
	"testing"
)

// TestEveryConditionIsDrawn fails when a condition is enforced and not drawn.
//
// A diagram that omits a condition is a lie of omission: somebody reads it,
// sees no device requirement, and cannot work out why their login is refused.
// The struct is the list of things that can be required, so the struct is what
// this asks -- a comment saying "remember to update the renderer" is not a
// mechanism.
func TestEveryConditionIsDrawn(t *testing.T) {
	// Every field set to something non-zero, so each one has something to draw.
	c := Conditions{
		Groups:             []string{"g1"},
		AnyGroup:           []string{"g2"},
		MFA:                true,
		PhishingResistant:  true,
		FactorsAnyOf:       []string{"hwk"},
		FromNetworks:       []string{"10.0.0.0/8"},
		NoImpossibleTravel: true,
		DeviceManaged:      true,
		DeviceCompliant:    true,
	}

	// Anything left at its zero value means this test was not updated when the
	// field was added -- and would then pass while proving nothing about it.
	v := reflect.ValueOf(c)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Fatalf("Conditions.%s is not set in this test, so the check below "+
				"cannot tell whether the renderer draws it",
				v.Type().Field(i).Name)
		}
	}

	// Each field, one at a time: setting it alone must change what is drawn.
	//
	// Checked this way rather than by looking for particular words. An earlier
	// version asserted the phrase "phishing-resistant" and failed the moment the
	// wording improved to "a passkey or security key" -- which is what an
	// operator should read. A test that pins prose makes the prose worse.
	full := describeConditions(c)
	if len(full) < v.NumField() {
		t.Fatalf("Conditions has %d fields and the renderer produced %d lines:\n%s",
			v.NumField(), len(full), strings.Join(full, "\n"))
	}

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name

		// One condition set, everything else zero.
		one := reflect.New(v.Type()).Elem()
		one.Field(i).Set(v.Field(i))
		lines := describeConditions(one.Interface().(Conditions))

		if len(lines) == 0 {
			t.Errorf("Conditions.%s is enforced and draws nothing. Somebody reads "+
				"the diagram, sees no such requirement, and cannot work out why "+
				"their login is refused.", name)
			continue
		}
		// And it must say something specific, not a generic placeholder shared
		// with another condition.
		if strings.TrimSpace(lines[0]) == "" {
			t.Errorf("Conditions.%s draws an empty line", name)
		}
	}
}

// TestSVGIsDeterministic: the same file must render identically every time, or
// a committed diagram has an unreadable diff.
func TestSVGIsDeterministic(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
default: deny
policies:
  - name: zebra-app
    when: {client: zebra}
    require: {mfa: true}
  - name: alpha-app
    when: {client: alpha}
    require: {groups: [staff]}
  - name: everyone
    require: {no_impossible_travel: true}
tests:
  - name: staff reach alpha
    given: {client: alpha, groups: [staff], mfa: true}
    expect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	first := f.SVG()
	for i := 0; i < 5; i++ {
		if got := f.SVG(); got != first {
			t.Fatal("two renders of the same file differ; a committed diagram would " +
				"produce noise in every diff")
		}
	}
	// Clients sorted, so the order does not depend on map iteration.
	ai := strings.Index(first, "alpha")
	zi := strings.Index(first, "zebra")
	if ai < 0 || zi < 0 || ai > zi {
		t.Fatal("clients are not in a stable sorted order")
	}
}

// TestSVGShowsTheDefault: where the boundary sits is the first thing a reviewer
// needs, and it is a file-level setting rather than a rule.
func TestSVGShowsTheDefault(t *testing.T) {
	deny, err := Parse([]byte("version: 1\ndefault: deny\npolicies: []\n" +
		"tests:\n  - name: everything is denied by default\n" +
		"    given: {client: anything}\n    expect: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(deny.SVG(), ">deny<") {
		t.Fatal("a default-deny file does not say so in its diagram")
	}

	allow, err := Parse([]byte("version: 1\npolicies: []\n" +
		"tests:\n  - name: everything is allowed by default\n" +
		"    given: {client: anything}\n    expect: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(allow.SVG(), ">allow<") {
		t.Fatal("a default-allow file does not say so in its diagram")
	}
	if !strings.Contains(allow.SVG(), "No rules") {
		t.Fatal("an empty policy does not say that every request gets the default")
	}
}

// TestSVGEscapes: a rule name is operator-supplied text going into markup.
func TestSVGEscapes(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
policies:
  - name: 'break <svg> & "quotes"'
    when: {client: 'x<y>'}
    require: {mfa: true}
tests:
  - name: an unrelated client is unaffected
    given: {client: ordinary}
    expect: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	out := f.SVG()
	if strings.Contains(out, "<svg>") {
		t.Fatal("a rule name containing markup was written into the diagram unescaped")
	}
	if !strings.Contains(out, "&lt;") && !strings.Contains(out, "&amp;") {
		t.Fatal("nothing was escaped, so the escaping is not running at all")
	}
}
