package authzen

import (
	"strings"
	"testing"
)

// Device posture and a risk score reach the decision point from the session (11.07), so a
// model may ask about them. What it asks of a request with no session is a refusal: no
// score is not a low one, and no device is not a managed one.
func TestAModelAsksWhatTheSessionShowed(t *testing.T) {
	m, err := ParseModel([]byte(`
policies:
  healthy: {device_compliant: true}
types:
  doc:
    relations: {owner: []}
    permissions: {read: [owner], edit: [owner], admin: [owner]}
    require:
      read: {max_risk: 10}
      edit: {device_managed: true}
      admin: {policies: [healthy]}
`))
	if err != nil {
		t.Fatalf("a model asking about the device and the risk was refused: %v", err)
	}
	for _, c := range []struct {
		name   string
		action string
		facts  Facts
		want   bool
		says   string
	}{
		{"a calm session", "read", Facts{FromSession: true, Risk: 0}, true, ""},
		{"at the cap", "read", Facts{FromSession: true, Risk: 10}, true, ""},
		{"above the cap", "read", Facts{FromSession: true, Risk: 50}, false, "(it is 50)"},
		{"no session named", "read", Facts{}, false, "session risk at most 10"},
		{"a managed device", "edit", Facts{FromSession: true, DeviceManaged: true}, true, ""},
		{"no device shown", "edit", Facts{FromSession: true}, false, "a managed device"},
		{"a compliant device, through a policy", "admin", Facts{FromSession: true, DeviceCompliant: true}, true, ""},
		{"a device not compliant", "admin", Facts{FromSession: true, DeviceManaged: true}, false, "healthy was not"},
	} {
		cond, has := m.ConditionFor("doc", c.action)
		if !has {
			t.Fatalf("%s: no condition on %s", c.name, c.action)
		}
		if got := cond.SatisfiedBy(c.facts); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if why := cond.Unmet(c.facts); !strings.Contains(why, c.says) || (c.want && why != "") {
			t.Errorf("%s: says %q, want %q", c.name, why, c.says)
		}
	}
}

// A test case in a model's file describes a session, so `max_risk` can be tested without one
// being named: it would otherwise refuse every case.
func TestAModelsOwnTestsAboutRiskRun(t *testing.T) {
	m, err := ParseModel([]byte(`
types:
  doc:
    relations: {owner: []}
    permissions: {read: [owner]}
    require:
      read: {max_risk: 10}
tests:
  - {name: calm, subject: 'user:ada', action: read, resource: 'doc:a', relations: [owner], risk: 5, allow: true}
  - {name: risky, subject: 'user:ada', action: read, resource: 'doc:a', relations: [owner], risk: 50, allow: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RunTests(); err != nil {
		t.Error(err)
	}
}
