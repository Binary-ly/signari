package policy

import "testing"

// A refresh asks again about who the person is, and not about where they are:
// the request comes from the application's server, which has the wrong address
// and no device certificate, and the where-from conditions were checked when
// the grant was issued.
func TestARefreshRechecksWhoNotWhere(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
policies:
  - name: staff from the office on a managed device
    when: {client: payroll}
    require:
      groups: [staff]
      mfa: true
      from_networks: ["10.0.0.0/8"]
      device_managed: true
      no_impossible_travel: true
  - name: closed
    when: {client: closed}
    deny: true
tests:
  - name: a refresh from the server's address passes
    given: {client: payroll, groups: [staff], mfa: true, ip: "192.0.2.1", refresh: true}
    expect: allow
  - name: the same request at sign-in does not
    given: {client: payroll, groups: [staff], mfa: true, ip: "192.0.2.1"}
    expect: deny
`))
	if err != nil {
		t.Fatalf("the file's own tests disagree with it: %v", err)
	}

	for _, c := range []struct {
		name string
		req  Request
		want bool
	}{
		{"where-from conditions are not re-asked",
			Request{Client: "payroll", Groups: []string{"staff"}, MFA: true, IP: "192.0.2.1",
				ImpossibleTravel: true, Refresh: true}, true},
		{"group membership is",
			Request{Client: "payroll", MFA: true, Refresh: true}, false},
		{"what the session proved is",
			Request{Client: "payroll", Groups: []string{"staff"}, Refresh: true}, false},
		{"a deny rule is",
			Request{Client: "closed", Refresh: true}, false},
	} {
		if got := f.Evaluate(c.req).Allowed; got != c.want {
			t.Errorf("%s: allowed = %v, want %v", c.name, got, c.want)
		}
	}
}

// A grant nobody watched arrive is a refresh in who it checks and the opposite
// in where: no sign-in to this client checked the network, device or travel
// conditions earlier, so they are not met. Each condition alone refuses, and a
// rule with none of them is decided by who the person is, as for a refresh.
func TestAnUnobservedGrantDoesNotMeetWhereFromConditions(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
policies:
  - name: office
    when: {client: office}
    require: {from_networks: ["10.0.0.0/8"]}
  - name: managed
    when: {client: managed}
    require: {device_managed: true}
  - name: compliant
    when: {client: compliant}
    require: {device_compliant: true}
  - name: travel
    when: {client: travel}
    require: {no_impossible_travel: true}
  - name: staff
    when: {client: staff}
    require: {groups: [staff]}
tests:
  - name: a grant for the office application is refused
    given: {client: office, ip: "10.1.2.3", unobserved: true}
    expect: deny
  - name: the same address at sign-in is not
    given: {client: office, ip: "10.1.2.3"}
    expect: allow
`))
	if err != nil {
		t.Fatalf("the file's own tests disagree with it: %v", err)
	}
	for _, c := range []struct {
		req  Request
		want bool
	}{
		// Whatever the caller's address or posture: it is the server's.
		{Request{Client: "office", IP: "10.1.2.3", Unobserved: true}, false},
		{Request{Client: "managed", DeviceManaged: true, Unobserved: true}, false},
		{Request{Client: "compliant", DeviceManaged: true, DeviceCompliant: true, Unobserved: true}, false},
		{Request{Client: "travel", Unobserved: true}, false},
		{Request{Client: "staff", Groups: []string{"staff"}, Unobserved: true}, true},
		{Request{Client: "staff", Unobserved: true}, false},
		// A refresh still inherits its sign-in's check.
		{Request{Client: "office", IP: "192.0.2.1", Refresh: true}, true},
	} {
		if got := f.Evaluate(c.req).Allowed; got != c.want {
			t.Errorf("%+v: allowed = %v, want %v", c.req, got, c.want)
		}
	}
}
