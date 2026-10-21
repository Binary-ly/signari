package flow

import (
	"fmt"
	"strings"
	"testing"
)

// guarded builds a flow of designation on with one stage its journey runs
// (prompt, or captcha in recovery, which runs no prompt) guarded by cond,
// valid in every other respect.
func guarded(on Designation, cond string) string {
	var stages, expect string
	guardedStage := "prompt"
	switch on {
	case Authentication:
		stages, expect = "[password, {stage: prompt, when: COND}, session]", "[password, PROMPTsession]"
	case Enrolment:
		stages, expect = "[{stage: prompt, when: COND}, create_user, done]", "[PROMPTcreate_user, done]"
	case Recovery:
		guardedStage = "captcha"
		stages, expect = "[{stage: captcha, when: COND}, identify, email_otp, password_change, done]",
			"[PROMPTidentify, email_otp, password_change, done]"
	case Unenrolment:
		// The proof is the one thing an unenrolment chooses between, so the
		// condition guards a branch of it.
		guardedStage = "passkey"
		stages, expect = "[{one_of: [{stage: passkey, when: COND}, {stage: password}]}, done]", "[password, done]"
	}
	// Nothing is given, so the condition is false and only its negation runs
	// the guarded stage.
	prompt := ""
	if strings.HasPrefix(cond, "not ") {
		prompt = guardedStage + ", "
		if on == Unenrolment {
			expect = "[passkey, done]"
		}
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
	for _, on := range []Designation{Authentication, Enrolment, Recovery, Unenrolment} {
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
}

// The step-up this row was written about parses now that a sign-in answers
// risk_elevated (4.10); one on a condition it still does not answer is
// refused the same way.
func TestAStepUpOnRiskParsesAndOneOnAnUnansweredConditionIsRefused(t *testing.T) {
	const doc = `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - one_of:
          - {stage: mfa, when: %s}
          - {stage: prompt}
      - session
    tests:
      - {name: risky, given: {%s: true}, expect: [password, mfa, session]}
      - {name: calm, given: {}, expect: [password, prompt, session]}
`
	mustParse(t, fmt.Sprintf(doc, "risk_elevated", "risk_elevated"))
	parseErr(t, fmt.Sprintf(doc, "device_managed", "device_managed"), "cannot evaluate device_managed yet")
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
