package scim

import "testing"

// RFC 7644 §3.5.2's path grammar, and §3.4.2.2's filter operators.
//
// Written as a parser rather than a regular expression per call site because the
// two call sites had diverged: groups recognised `members[value eq "x"]` and
// users recognised no filtered path at all, recording them as unsupported and
// answering 200.

func TestPathShapes(t *testing.T) {
	cases := []struct {
		in         string
		attr, sub  string
		hasFilter  bool
		schemaPart string
	}{
		{in: "active", attr: "active"},
		{in: "name.givenName", attr: "name", sub: "givenname"},
		{in: `emails[type eq "work"]`, attr: "emails", hasFilter: true},
		{in: `emails[type eq "work"].value`, attr: "emails", sub: "value", hasFilter: true},
		{in: `members[value eq "abc"]`, attr: "members", hasFilter: true},
		// Fully qualified, which Entra sends for extension attributes.
		{in: "urn:ietf:params:scim:schemas:core:2.0:User:emails", attr: "emails",
			schemaPart: "urn:ietf:params:scim:schemas:core:2.0:User"},
		// A colon INSIDE a quoted filter value must not split the path.
		{in: `emails[value eq "urn:weird:address"].value`, attr: "emails",
			sub: "value", hasFilter: true},
		{in: "  spaced  ", attr: "spaced"},
	}
	for _, tc := range cases {
		p, err := ParsePath(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if p.Attr != tc.attr || p.Sub != tc.sub {
			t.Errorf("%s: attr=%q sub=%q, want %q/%q", tc.in, p.Attr, p.Sub, tc.attr, tc.sub)
		}
		if (p.Filter != nil) != tc.hasFilter {
			t.Errorf("%s: filter presence = %v", tc.in, p.Filter != nil)
		}
		if tc.schemaPart != "" && p.Schema != tc.schemaPart {
			t.Errorf("%s: schema = %q, want %q", tc.in, p.Schema, tc.schemaPart)
		}
	}
}

func TestMalformedPathsAreRefused(t *testing.T) {
	for _, in := range []string{
		"", "   ",
		`emails[type eq "work"`,          // unclosed bracket
		`emails[type eq "work"] garbage`, // trailing text that is not a sub-attribute
		`[type eq "work"]`,               // filter with no attribute
		`emails[]`,                       // empty filter
		`emails[type]`,                   // attribute with no operator
		`emails[type zz "work"]`,         // unknown operator
		`emails[type eq]`,                // operator with no value
		`emails[(type eq "work"]`,        // unclosed paren
		`emails[type eq "unterminated]`,  // unterminated string
	} {
		if _, err := ParsePath(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

// §3.4.2.2's operators, evaluated against a value rather than matched as text.
func TestFilterEvaluation(t *testing.T) {
	obj := map[string]any{
		"type": "work", "value": "a@b.test", "primary": true, "rank": float64(3),
	}
	cases := map[string]bool{
		`type eq "work"`:                     true,
		`type eq "WORK"`:                     true, // caseExact:false in the core schema
		`type ne "home"`:                     true,
		`type co "or"`:                       true,
		`type sw "wo"`:                       true,
		`type ew "rk"`:                       true,
		`primary eq true`:                    true,
		`primary eq false`:                   false,
		`rank gt 2`:                          true,
		`rank lt 2`:                          false,
		`rank ge 3`:                          true,
		`value pr`:                           true,
		`missing pr`:                         false,
		`type eq "work" and primary eq true`: true,
		`type eq "home" and primary eq true`: false,
		`type eq "home" or primary eq true`:  true,
		`not (type eq "home")`:               true,
		`not (type eq "work")`:               false,
		`(type eq "home" or type eq "work") and primary eq true`: true,
	}
	for expr, want := range cases {
		f, err := parseFilter(expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := f.Matches(obj); got != want {
			t.Errorf("%s = %v, want %v", expr, got, want)
		}
	}
}

// A filter naming an attribute the element does not have is false, never true.
// Getting this backwards would make every filter match everything, which is the
// failure that silently widens a PATCH.
func TestAnAbsentAttributeNeverMatches(t *testing.T) {
	obj := map[string]any{"type": "work"}
	for _, expr := range []string{`nope eq "x"`, `nope ne "x"`, `nope co "x"`, `nope gt 1`} {
		f, err := parseFilter(expr)
		if err != nil {
			t.Fatal(err)
		}
		if f.Matches(obj) {
			t.Errorf("%s matched an element that has no such attribute", expr)
		}
	}
}
