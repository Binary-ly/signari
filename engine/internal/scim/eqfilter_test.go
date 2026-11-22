package scim

import (
	"strings"
	"testing"
)

// A list filter is RFC 7644 Figure 1's grammar. The value is JSON, so a trailing
// expression is an expression: it was folded into the value, and
// `userName eq "a" or userName eq "b"` searched for one person with an odd name,
// found nobody and invited a duplicate create (2.42).
func TestAListFilterIsTheGrammar(t *testing.T) {
	for in, want := range map[string]*Filter{
		`userName eq "bjensen"`:    {Op: "eq", Attr: "username", Value: "bjensen"},
		`USERNAME EQ "bjensen"`:    {Op: "eq", Attr: "username", Value: "bjensen"},
		`userName eq "say \"hi\""`: {Op: "eq", Attr: "username", Value: `say "hi"`},
		`userName eq  "spaced"  `:  {Op: "eq", Attr: "username", Value: "spaced"},
		`active eq true`:           {Op: "eq", Attr: "active", Value: true},
		`active eq null`:           {Op: "eq", Attr: "active"},
		`emails.value pr`:          {Op: "pr", Attr: "emails.value"},
	} {
		got, err := ParseListFilter(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.Op != want.Op || got.Attr != want.Attr || got.Value != want.Value {
			t.Errorf("%q read as %+v, want %+v", in, got, want)
		}
	}
	if f, err := ParseListFilter("  "); f != nil || err != nil {
		t.Errorf("no filter read as %+v, %v", f, err)
	}

	// \x5c is a backslash: JSON's escapes, and not only its quotes.
	if f, err := ParseListFilter("a eq \"\x5cu0041\x5cn\""); err != nil || f.Value != "A\n" {
		t.Errorf("read %+v, %v", f, err)
	}

	// `not` over `and` over `or`, as the RFC orders them.
	f, err := ParseListFilter(`a eq "1" or not (b eq "2") and c eq "3"`)
	if err != nil {
		t.Fatal(err)
	}
	if f.Op != "or" || f.Right.Op != "and" || f.Right.Left.Op != "not" {
		t.Errorf("read as %+v", f)
	}

	for _, in := range []string{
		`userName eq bjensen`,
		`userName eq "unterminated`,
		`userName regex "a"`,
		`"userName" eq "a"`,
		`userName "eq" "a"`,
		`userName eq "a" userName eq "b"`,
		`(userName eq "a"`,
		`userName eq "bad \q escape"`,
		`userName eq 0x10`,
		`userName eq`,
		`userName`,
		`and`,
		strings.Repeat(`(`, maxFilterTokens+1),
		strings.TrimSuffix(strings.Repeat(`a pr or `, maxFilterTokens), " or "),
	} {
		if got, err := ParseListFilter(in); err == nil {
			t.Errorf("%.40q was accepted as %+v", in, got)
		}
	}
}

// The value filter of a PATCH path keeps what upstreams send.
func TestAPathFilterStaysLenient(t *testing.T) {
	f, err := parseFilter(`type eq work`)
	if err != nil || f.Value != "work" {
		t.Errorf("read %+v, %v", f, err)
	}
}
