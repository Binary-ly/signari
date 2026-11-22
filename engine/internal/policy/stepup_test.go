package policy

import "testing"

const stepUpPolicy = `
version: 1
policies:
  - name: two-factors
    when: {client: reports}
    require: {mfa: true}
  - name: a-device-bound-key
    when: {client: payroll}
    require: {phishing_resistant: true}
  - name: an-app-or-a-key
    when: {client: wiki}
    require: {factors_any_of: [otp, hwk]}
  - name: finance-with-two-factors
    when: {client: ledger}
    require: {groups: [finance], mfa: true}
  - name: never
    when: {client: vault}
    deny: true
tests:
  - name: two factors reach the reports
    given: {client: reports, mfa: true}
    expect: allow
  - name: a hardware key reaches payroll
    given: {client: payroll, amr: [hwk]}
    expect: allow
  - name: a code reaches the wiki
    given: {client: wiki, amr: [otp]}
    expect: allow
  - name: finance with two factors reaches the ledger
    given: {client: ledger, groups: [finance], mfa: true}
    expect: allow
`

// A refusal says it can be cured by signing in again only when the rule asked for
// nothing else (9.09), and names the acr that would cure it when one value can. A
// rule that also asks for a group the person lacks, or denies outright, is not one a
// stronger sign-in changes, and saying it was would send a client round in a loop.
func TestARefusalSaysWhenAStrongerSignInWouldPassIt(t *testing.T) {
	f, err := Parse([]byte(stepUpPolicy))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		req    Request
		stepUp bool
		acr    string
	}{
		"one factor at the reports":     {Request{Client: "reports", AMR: []string{"pwd"}}, true, "2"},
		"a code at payroll":             {Request{Client: "payroll", MFA: true, AMR: []string{"pwd", "otp"}}, true, "4"},
		"a password at the wiki":        {Request{Client: "wiki", AMR: []string{"pwd"}}, true, ""},
		"finance with one factor":       {Request{Client: "ledger", Groups: []string{"finance"}}, true, "2"},
		"not finance, with one factor":  {Request{Client: "ledger"}, false, ""},
		"not finance, with two factors": {Request{Client: "ledger", MFA: true}, false, ""},
		"anybody at the vault":          {Request{Client: "vault", MFA: true, AMR: []string{"hwk"}}, false, ""},
	} {
		d := f.Evaluate(tc.req)
		if d.Allowed {
			t.Errorf("%s: allowed", name)
			continue
		}
		if d.StepUp != tc.stepUp || d.ACR != tc.acr {
			t.Errorf("%s: step-up %v with acr %q, want %v with %q", name, d.StepUp, d.ACR, tc.stepUp, tc.acr)
		}
	}
}
