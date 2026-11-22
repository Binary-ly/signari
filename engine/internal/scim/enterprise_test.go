package scim

import (
	"encoding/json"
	"strings"
	"testing"
)

func patchOf(t *testing.T, ops string) *UserPatch {
	t.Helper()
	var req PatchRequest
	if err := json.Unmarshal([]byte(`{"Operations":`+ops+`}`), &req); err != nil {
		t.Fatal(err)
	}
	p, err := ApplyUserPatch(req)
	if err != nil {
		t.Fatalf("%s: %v", ops, err)
	}
	return p
}

func set(p *UserPatch, attribute string) string {
	if v := p.Enterprise[attribute]; v != nil {
		return *v
	}
	return ""
}

// Every way an upstream writes the extension. The URN has to survive to here:
// normalisePath takes it, and a path that is only `department` is not one this
// engine stores, so the value was dropped and the PATCH answered 200.
func TestAnEnterprisePatchIsReadInEveryShape(t *testing.T) {
	const ext = EnterpriseSchema
	for name, ops := range map[string]string{
		"by path":          `[{"op":"Add","path":"` + ext + `:department","value":"Eng"}]`,
		"replace":          `[{"op":"replace","path":"` + ext + `:department","value":"Eng"}]`,
		"another case":     `[{"op":"add","path":"` + strings.ToUpper(ext) + `:DEPARTMENT","value":"Eng"}]`,
		"flat, no path":    `[{"op":"Replace","value":{"` + ext + `:department":"Eng"}}]`,
		"nested, no path":  `[{"op":"Add","value":{"` + ext + `":{"department":"Eng"}}}]`,
		"the whole object": `[{"op":"replace","path":"` + ext + `","value":{"department":"Eng"}}]`,
	} {
		if got := set(patchOf(t, ops), "department"); got != "Eng" {
			t.Errorf("%s read %q", name, got)
		}
	}

	for name, value := range map[string]string{
		"a bare id":       `"m-1"`,
		"an object":       `{"value":"m-1"}`,
		"with its name":   `{"value":"m-1","displayName":"Ada"}`,
		"an array of one": `[{"value":"m-1"}]`,
	} {
		ops := `[{"op":"add","path":"` + ext + `:manager","value":` + value + `}]`
		if got := set(patchOf(t, ops), "manager"); got != "m-1" {
			t.Errorf("a manager as %s read %q", name, got)
		}
	}
	if got := set(patchOf(t, `[{"op":"replace","path":"`+ext+`:manager.value","value":"m-1"}]`), "manager"); got != "m-1" {
		t.Errorf("manager.value read %q", got)
	}

	// Names the user attributes hold them under, which are lower-case.
	p := patchOf(t, `[{"op":"add","path":"`+ext+`:employeeNumber","value":"7"},
		{"op":"add","path":"`+ext+`:costCenter","value":"42"}]`)
	if set(p, "employee_number") != "7" || set(p, "cost_center") != "42" {
		t.Errorf("read %+v", p.Enterprise)
	}

	// The core schema's are still the core schema's.
	p = patchOf(t, `[{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:active","value":false}]`)
	if p.Active == nil || *p.Active || p.Enterprise != nil {
		t.Errorf("read %+v", p)
	}
	// And `department` alone is not the extension's.
	if p := patchOf(t, `[{"op":"add","path":"department","value":"x"}]`); p.Enterprise != nil || len(p.Unsupported) != 1 {
		t.Errorf("read %+v", p)
	}
}

func TestAnEnterpriseValueIsCleared(t *testing.T) {
	const ext = EnterpriseSchema
	for name, ops := range map[string]string{
		"remove":           `[{"op":"remove","path":"` + ext + `:department"}]`,
		"null":             `[{"op":"replace","path":"` + ext + `:department","value":null}]`,
		"an empty string":  `[{"op":"replace","path":"` + ext + `:department","value":""}]`,
		"nested null":      `[{"op":"replace","value":{"` + ext + `":{"department":null}}}]`,
		"the whole object": `[{"op":"remove","path":"` + ext + `"}]`,
	} {
		p := patchOf(t, ops)
		v, mentioned := p.Enterprise["department"]
		if !mentioned || v != nil {
			t.Errorf("%s read %v, mentioned %v", name, v, mentioned)
		}
	}
	p := patchOf(t, `[{"op":"remove","path":"`+ext+`:manager.value"}]`)
	if v, mentioned := p.Enterprise["manager"]; !mentioned || v != nil {
		t.Errorf("manager.value read %v, mentioned %v", v, mentioned)
	}
}

func TestWhatTheExtensionDoesNotHaveIsRecordedNotStored(t *testing.T) {
	const ext = EnterpriseSchema
	p := patchOf(t, `[{"op":"add","path":"`+ext+`:shoeSize","value":"44"},
		{"op":"add","path":"`+ext+`:manager.displayName","value":"Ada"},
		{"op":"remove","path":"`+ext+`:shoeSize"}]`)
	if len(p.Enterprise) != 0 || len(p.Unsupported) != 3 {
		t.Errorf("read %+v", p)
	}
	// Not a prefix of the URN, whose next character says so.
	if _, ok := enterprisePath(ext + "Extra:department"); ok {
		t.Error("another schema was read as the extension")
	}
}

func TestABadEnterpriseValueIsRefused(t *testing.T) {
	const ext = EnterpriseSchema
	for _, ops := range []string{
		`[{"op":"add","path":"` + ext + `:department","value":5}]`,
		`[{"op":"add","path":"` + ext + `:department","value":{"value":"x"}}]`,
		`[{"op":"add","path":"` + ext + `:manager","value":[{"value":"a"},{"value":"b"}]}]`,
		`[{"op":"add","path":"` + ext + `:manager","value":5}]`,
		`[{"op":"add","path":"` + ext + `","value":"not an object"}]`,
	} {
		var req PatchRequest
		if err := json.Unmarshal([]byte(`{"Operations":`+ops+`}`), &req); err != nil {
			t.Fatal(err)
		}
		if p, err := ApplyUserPatch(req); err == nil {
			t.Errorf("%s was read as %+v", ops, p)
		}
	}
}

// PUT replaces what the extension covers, and only when it was sent: a client
// that does not send it may not understand it.
func TestAResourceSaysWhatItReplaces(t *testing.T) {
	var with, without User
	if err := json.Unmarshal([]byte(`{"userName":"a","`+EnterpriseSchema+`":{"department":"Eng"}}`), &with); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"userName":"a"}`), &without); err != nil {
		t.Fatal(err)
	}
	replacing, err := with.EnterpriseValues(true)
	if err != nil {
		t.Fatal(err)
	}
	if v := replacing["department"]; v == nil || *v != "Eng" {
		t.Errorf("read %v", v)
	}
	if v, mentioned := replacing["cost_center"]; !mentioned || v != nil {
		t.Errorf("an attribute left out of a replacing extension read %v, mentioned %v", v, mentioned)
	}
	merging, err := with.EnterpriseValues(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, mentioned := merging["cost_center"]; mentioned {
		t.Error("a create cleared what it did not mention")
	}
	if got, err := without.EnterpriseValues(true); got != nil || err != nil {
		t.Errorf("no extension read as %v, %v", got, err)
	}
}
