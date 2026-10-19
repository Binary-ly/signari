package authzen

import (
	"strings"
	"testing"
)

// No device posture and no risk score reach the decision point, so a model
// requiring one is refused at parse, naming where. device_managed would have
// refused everybody; max_risk refused nobody and looked like a control.
func TestARequirementOnAFactTheDecisionPointNeverHasIsRefused(t *testing.T) {
	for _, c := range []struct{ name, model, where string }{
		{"max_risk on a rule", `
types:
  doc:
    relations: {owner: []}
    permissions: {read: [owner]}
    require: {read: {max_risk: 30}}
`, "doc.read: max_risk"},
		{"device_managed on a rule", `
types:
  doc:
    relations: {owner: []}
    permissions: {read: [owner]}
    require: {read: {device_managed: true}}
`, "doc.read: device_managed"},
		{"device_compliant in a named policy", `
policies:
  healthy: {device_compliant: true}
types:
  doc:
    relations: {owner: []}
    permissions: {read: [owner]}
    require: {read: {policies: [healthy]}}
`, "policy healthy: device_compliant"},
	} {
		_, err := ParseModel([]byte(c.model))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.where) {
			t.Errorf("%s: refused without naming %q: %v", c.name, c.where, err)
		}
	}

	// The facts the decision point does have still load.
	if _, err := ParseModel([]byte(`
types:
  doc:
    relations: {owner: []}
    permissions: {read: [owner]}
    require: {read: {mfa: true, subject_active: true, email_verified: true, any_group: [staff]}}
`)); err != nil {
		t.Errorf("a model on facts the decision point has was refused: %v", err)
	}
}
