package flow

import (
	"fmt"
	"strings"
	"testing"
)

// guarded builds a flow of designation on whose prompt stage runs only when
// cond holds, valid in every other respect.
func guarded(on Designation, cond string) string {
	var stages, expect string
	switch on {
	case Authentication:
		stages, expect = "[password, {stage: prompt, when: COND}, session]", "[password, PROMPTsession]"
	case Enrolment:
		stages, expect = "[{stage: prompt, when: COND}, create_user, done]", "[PROMPTcreate_user, done]"
	case Recovery:
		stages, expect = "[identify, email_otp, {stage: prompt, when: COND}, password_change, done]",
			"[identify, email_otp, PROMPTpassword_change, done]"
	case Unenrolment:
		stages, expect = "[password, {stage: prompt, when: COND}, done]", "[password, PROMPTdone]"
	}
	// Nothing is given, so the condition is false and only its negation runs
	// the prompt.
	prompt := ""
	if strings.HasPrefix(cond, "not ") {
		prompt = "prompt, "
	}
	return fmt.Sprintf(`
version: 1
flows:
  - name: f
    on: %s
    stages: %s
    tests: [{name: t, given: {}, expect: %s}]
`, on, strings.ReplaceAll(stages, "COND", cond), strings.ReplaceAll(expect, "PROMPT", prompt))
}

// Every condition a flow can branch on is either evaluated by the journey the
// flow is for, or refused when the file is parsed. A condition the journey
// cannot evaluate reads false every time, and `{stage: deny, when:
// risk_elevated}` parsed, passed its own tests and never refused anybody.
func TestEveryConditionIsAnsweredOrRefused(t *testing.T) {
	for _, on := range []Designation{Authentication, Enrolment, Recovery} {
		ok := map[Condition]bool{}
		for _, c := range Answered(on) {
			ok[c] = true
		}
		for _, c := range allConditions {
			for _, expr := range []string{string(c), "not " + string(c)} {
				_, err := Parse([]byte(guarded(on, expr)))
				switch {
				case ok[c] && err != nil:
					t.Errorf("on %s, `when: %s` is evaluated and was refused: %v", on, expr, err)
				case !ok[c] && err == nil:
					t.Errorf("on %s, `when: %s` is not evaluated and was accepted, so the "+
						"stage it guards would never run", on, expr)
				case !ok[c] && !strings.Contains(err.Error(), string(c)):
					t.Errorf("on %s, `when: %s` was refused without naming it: %v", on, expr, err)
				}
			}
		}
	}

	// Nothing walks an unenrolment flow, and flow test and flow apply say so
	// about the whole of it, so its conditions are not judged one by one.
	if _, err := Parse([]byte(guarded(Unenrolment, "risk_elevated"))); err != nil {
		t.Errorf("an unenrolment flow was refused over a condition: %v", err)
	}
}

// The deny this row was written about.
func TestADenyOnRiskIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - one_of:
          - {stage: mfa, when: risk_elevated}
          - {stage: prompt}
      - session
    tests:
      - {name: risky, given: {risk_elevated: true}, expect: [password, mfa, session]}
      - {name: calm, given: {}, expect: [password, prompt, session]}
`, "cannot evaluate risk_elevated yet")
}

// A sign-in settles the captcha at the form, so the walk reads
// captcha_required false: it may guard the captcha stage, which the form has
// already run, and nothing else.
func TestCaptchaRequiredGuardsOnlyTheCaptchaInASignIn(t *testing.T) {
	mustParse(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages: [{stage: captcha, when: captcha_required}, password, session]
    tests: [{name: t, given: {}, expect: [password, session]}]
`)
	parseErr(t, guarded(Authentication, "captcha_required"), "may guard only the captcha stage")
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - one_of:
          - {stage: mfa, when: not captcha_required}
          - {stage: prompt}
      - session
    tests: [{name: t, given: {}, expect: [password, mfa, session]}]
`, "may guard only the captcha stage")
}
