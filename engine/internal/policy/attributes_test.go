package policy

import (
	"strings"
	"testing"
)

const attributePolicy = `
version: 1
policies:
  - name: finance
    when: {client: ledger}
    require:
      user_attributes:
        cost_centre: ["4100", "4200"]
        employee_number: []
tests:
  - name: in a listed cost centre, with a number
    given: {client: ledger, attributes: {cost_centre: "4200", employee_number: "7"}}
    expect: allow
  - name: another cost centre
    given: {client: ledger, attributes: {cost_centre: "9999", employee_number: "7"}}
    expect: deny
  - name: no number at all
    given: {client: ledger, attributes: {cost_centre: "4100"}}
    expect: deny
  - name: nothing held
    given: {client: ledger}
    expect: deny
  - name: another application
    given: {client: wiki}
    expect: allow
`

// A rule asks about an attribute by value or by holding one, in the file's own tests with
// no directory behind them, and says which it reads so a decision reads nothing otherwise.
func TestARuleReadsAttributesByValueOrPresence(t *testing.T) {
	f, err := Parse([]byte(attributePolicy))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.AttributeNames(), ","); got != "cost_centre,employee_number" {
		t.Errorf("the rules read %q", got)
	}
	// Who somebody is holds at a refresh and on a grant nobody watched, where the
	// conditions on where they are cannot.
	for _, c := range []struct {
		name string
		req  Request
	}{
		{"a refresh", Request{Client: "ledger", Refresh: true}},
		{"a grant nobody watched", Request{Client: "ledger", Unobserved: true}},
	} {
		if d := f.Evaluate(c.req); d.Allowed {
			t.Errorf("%s with nothing held was allowed", c.name)
		}
	}
	if d := f.Evaluate(Request{Client: "ledger", Refresh: true,
		Attributes: map[string]string{"cost_centre": "4100", "employee_number": "7"}}); !d.Allowed {
		t.Errorf("a refresh meeting the rule was refused: %+v", d)
	}
	if _, err := Parse([]byte(strings.Replace(attributePolicy, "user_attributes:", "user_attribute:", 1))); err == nil {
		t.Error("a misspelt condition loaded, which would demand nothing")
	}
	// A rule with nothing but this is a rule, and cannot be mistaken for an empty one
	// that may also deny.
	bad := strings.Replace(attributePolicy, "    require:\n", "    deny: true\n    require:\n", 1)
	if _, err := Parse([]byte(bad)); err == nil {
		t.Error("a rule both denying and requiring an attribute loaded")
	}
}
