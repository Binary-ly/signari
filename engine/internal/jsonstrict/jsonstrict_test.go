package jsonstrict

import (
	"strings"
	"testing"
)

// A member named twice is refused wherever it is, and naming where; the same
// name in two different objects is not a duplicate; malformed input is left
// to the caller's decode, which says it better.
func TestADuplicateMemberIsRefusedAtAnyDepth(t *testing.T) {
	for _, c := range []struct {
		name, body, where string
	}{
		{"top level", `{"sub":"alice","sub":"admin"}`, "the document"},
		{"nested", `{"claims":{"role":"user","role":"admin"}}`, "claims"},
		{"in an array", `{"permissions":[{"scope":"read"},{"scope":"read","scope":"write"}]}`, "permissions"},
		{"deeper", `{"a":{"b":{"c":1,"c":2}}}`, "a.b"},
		// One name in two spellings is one name: Go decodes the escape, and a
		// parser that compared the raw bytes would read two members here.
		{"escaped", `{"aud":"rp","aud":"attacker"}`, "the document"},
	} {
		err := NoDuplicateKeys([]byte(c.body))
		if err == nil {
			t.Errorf("%s: %s was accepted", c.name, c.body)
			continue
		}
		if !strings.Contains(err.Error(), c.where) {
			t.Errorf("%s: the refusal %q does not say where (%s)", c.name, err, c.where)
		}
	}

	for _, ok := range []string{
		`{"a":1,"b":2}`,
		`[{"a":1},{"a":2}]`,         // the same name in sibling objects
		`{"x":{"a":1},"y":{"a":2}}`, // and in cousins
		`{"list":[1,2,2,3]}`,        // repeated values are not repeated names
		`"just a string"`, `42`, `null`, ``,
		`{"a":`, // malformed: the caller's decode reports it
	} {
		if err := NoDuplicateKeys([]byte(ok)); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}
