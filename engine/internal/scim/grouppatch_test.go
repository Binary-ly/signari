package scim

import (
	"encoding/json"
	"strings"
	"testing"
)


func parseOps(t *testing.T, body string) (*GroupPatch, error) {
	t.Helper()
	var req PatchRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	return ApplyGroupPatch(req)
}

func TestPathFilterMemberRemoval(t *testing.T) {
	p, err := parseOps(t, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"remove","path":"members[value eq \"abc-123\"]"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RemoveMembers) != 1 || p.RemoveMembers[0] != "abc-123" {
		t.Fatalf("RemoveMembers = %v, want [abc-123]", p.RemoveMembers)
	}
	if p.ReplaceMembers != nil {
		t.Error("a single removal was read as a whole-list replacement, which " +
			"would empty the group")
	}
}

func TestPathFilterRemovalWithTrailingAttribute(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"remove","path":"members[value eq \"abc-123\"].value"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RemoveMembers) != 1 || p.RemoveMembers[0] != "abc-123" {
		t.Fatalf("RemoveMembers = %v", p.RemoveMembers)
	}
}

// Entra names the member in the value and capitalises the verb.
func TestEntraStyleMemberRemoval(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"Remove","path":"members","value":[{"value":"abc-123"}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RemoveMembers) != 1 || p.RemoveMembers[0] != "abc-123" {
		t.Fatalf("RemoveMembers = %v", p.RemoveMembers)
	}
	if p.ReplaceMembers != nil {
		t.Error("naming one member to remove emptied the whole group")
	}
}

func TestMemberAddition(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"add","path":"members","value":[{"value":"a"},{"value":"b"}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AddMembers) != 2 {
		t.Fatalf("AddMembers = %v", p.AddMembers)
	}
	if p.ReplaceMembers != nil {
		t.Error("an add was read as a replacement, which removes everybody not named")
	}
}

// `replace` on the whole collection is NOT an add: everybody absent is removed.
// Reading it as an add leaves departed members in the group while the upstream
// reports the sync as complete.
func TestReplacingTheMemberListIsNotAnAddition(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"replace","path":"members","value":[{"value":"a"}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.ReplaceMembers == nil {
		t.Fatal("replace on members was not read as a whole-list replacement")
	}
	if len(*p.ReplaceMembers) != 1 || (*p.ReplaceMembers)[0] != "a" {
		t.Fatalf("ReplaceMembers = %v", *p.ReplaceMembers)
	}
	if len(p.AddMembers) != 0 {
		t.Error("the replacement was also recorded as an addition")
	}
}

// The no-path form, which Entra sends: the value's keys ARE the paths.
func TestEntraStyleRenameWithNoPath(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"replace","value":{"displayName":"Engineering EU"}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.DisplayName == nil || *p.DisplayName != "Engineering EU" {
		t.Fatalf("DisplayName = %v", p.DisplayName)
	}
}

// A fully qualified attribute path, permitted by §3.5.2 and sent by Entra.
// Unrecognised, it becomes an "unsupported path" -- answered 200 and never
// retried, so the membership change never happens.
func TestASchemaQualifiedMemberPathIsRecognised(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"add","path":"urn:ietf:params:scim:schemas:core:2.0:Group:members",
		 "value":[{"value":"a"}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AddMembers) != 1 {
		t.Fatalf("AddMembers = %v; a qualified path was not recognised as members",
			p.AddMembers)
	}
	if len(p.Unsupported) > 0 {
		t.Errorf("recorded as unsupported: %v", p.Unsupported)
	}
}

// THE failure this parser exists to prevent: a removal it cannot read must be an
// error, never a 200. A 200 tells the upstream the removal happened; it never
// sends it again, and the person keeps the group forever.
func TestAnUnreadableRemovalIsAnErrorNotASilentSuccess(t *testing.T) {
	_, err := parseOps(t, `{"Operations":[
		{"op":"remove","path":"members[displayName eq \"Alice\"]"}]}`)
	if err == nil {
		t.Fatal("a member removal naming an attribute we cannot resolve was " +
			"accepted; the upstream would record the removal as done")
	}
	if !strings.Contains(err.Error(), "member") {
		t.Errorf("the error does not say what could not be read: %v", err)
	}
}

// An unknown op is an error too, for the same reason.
func TestAnUnknownOperationIsRefused(t *testing.T) {
	if _, err := parseOps(t, `{"Operations":[{"op":"merge","path":"members"}]}`); err == nil {
		t.Error("an unknown op was accepted")
	}
	if _, err := parseOps(t, `{"Operations":[]}`); err == nil {
		t.Error("a PATCH with no operations was accepted")
	}
}

// `remove` on the whole collection with no value empties the group.
func TestRemovingTheWholeCollectionEmptiesTheGroup(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[{"op":"remove","path":"members"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.ReplaceMembers == nil || len(*p.ReplaceMembers) != 0 {
		t.Fatalf("ReplaceMembers = %v, want an empty list", p.ReplaceMembers)
	}
}

// A path we do not store is recorded rather than refused: the same operation may
// have changed something we DID apply, and failing the whole request blocks the
// sync over an attribute nobody uses.
func TestAnUnstoredPathIsRecordedNotRefused(t *testing.T) {
	p, err := parseOps(t, `{"Operations":[
		{"op":"replace","path":"externalIdSomething","value":"x"}]}`)
	if err != nil {
		t.Fatalf("an unstored non-member path was refused: %v", err)
	}
	if len(p.Unsupported) != 1 {
		t.Errorf("Unsupported = %v", p.Unsupported)
	}
}

// The name a token carries must satisfy core.groups' shape constraint, which
// upstream display names routinely do not.
func TestGroupNameDerivation(t *testing.T) {
	cases := map[string]string{
		"Engineering":           "Engineering",
		"Engineering Team":      "Engineering-Team",
		"Finance & Legal":       "Finance-Legal",
		"  Padded  ":            "Padded",
		"a/b\\c":                "a-b-c",
		"Ops (EU)":              "Ops-EU",
		strings.Repeat("x", 80): strings.Repeat("x", 64),
	}
	for in, want := range cases {
		got, err := GroupNameFrom(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("GroupNameFrom(%q) = %q, want %q", in, got, want)
		}
	}
	// A name with nothing usable in it is an error rather than an empty string,
	// which would violate the CHECK constraint at insert time with a message
	// naming a column the upstream has never heard of.
	if _, err := GroupNameFrom("日本語"); err == nil {
		t.Error("a display name with no usable characters produced a group name")
	}
}

// The filter operator matched case-insensitively. Being strict gains nothing
// and would turn a conformant client's removal into a 400.
func TestTheMemberFilterOperatorIsCaseInsensitive(t *testing.T) {
	for _, path := range []string{
		`members[value eq "abc"]`,
		`members[value EQ "abc"]`,
		`Members[Value Eq "abc"]`,
		`members[  value   eq   "abc"  ]`,
	} {
		p, err := parseOps(t, `{"Operations":[{"op":"remove","path":`+
			mustJSON(t, path)+`}]}`)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if len(p.RemoveMembers) != 1 || p.RemoveMembers[0] != "abc" {
			t.Errorf("%s: RemoveMembers = %v", path, p.RemoveMembers)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
