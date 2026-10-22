package flow

import "testing"

// The invitation and redirect stages, and the rules they are held to (5.24).

func enrolment(stages, tests string) string {
	return `
version: 1
flows:
  - name: sign-up
    on: enrolment
    stages:
` + stages + `
    tests:
` + tests
}

func TestARedirectIsHeldToWhereItMaySend(t *testing.T) {
	ok := map[string]string{
		"https":      `{stage: redirect, to: "https://welcome.example.com/start"}`,
		"local path": `{stage: redirect, to: "/account"}`,
	}
	for name, step := range ok {
		f := mustParse(t, enrolment("      - create_user\n      - "+step,
			"      - {name: made, given: {}, expect: [create_user, redirect]}"))
		if target := f.Flows[0].RedirectTarget(); target == "" {
			t.Errorf("%s: no redirect target read", name)
		}
	}

	refused := map[string]struct{ step, want string }{
		"no to":            {`redirect`, "needs `to`"},
		"http":             {`{stage: redirect, to: "http://welcome.example.com"}`, "must be an https URL"},
		"another host":     {`{stage: redirect, to: "//elsewhere.example"}`, "would leave this server"},
		"backslash":        {`{stage: redirect, to: "/\\elsewhere.example"}`, "would leave this server"},
		"user information": {`{stage: redirect, to: "https://bank.example@elsewhere.example/"}`, "no user information"},
		"no host":          {`{stage: redirect, to: "https:///path"}`, "must be an https URL"},
		"a script":         {`{stage: redirect, to: "javascript:alert(1)"}`, "must be an https URL"},
	}
	for name, c := range refused {
		parseErr(t, enrolment("      - create_user\n      - "+c.step,
			"      - {name: made, given: {}, expect: [create_user, redirect]}"), c.want)
		_ = name
	}

	// Only a redirect takes `to`.
	parseErr(t, enrolment("      - create_user\n      - {stage: done, to: \"https://welcome.example.com\"}",
		"      - {name: made, given: {}, expect: [create_user, done]}"), "`to` is for a redirect stage")
}

// A redirect is a terminal of enrolment and recovery only: a sign-in ends in a
// session that the parked request resumes from, and an unenrolment ends where
// the account is erased.
func TestARedirectEndsOnlyAnEnrolmentOrARecovery(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages: [password, {stage: redirect, to: "/account"}]
    tests: [{name: t, given: {}, expect: [password, redirect]}]
`, "redirect")
	parseErr(t, `
version: 1
flows:
  - name: deletion
    on: unenrolment
    stages: [password, {stage: redirect, to: "/goodbye"}]
    tests: [{name: t, given: {}, expect: [password, redirect]}]
`, "redirect")
	parseErr(t, enrolment("      - {stage: redirect, to: \"/welcome\"}\n      - create_user\n      - done",
		"      - {name: t, given: {}, expect: [redirect, create_user, done]}"), "ends a flow")
	mustParse(t, `
version: 1
flows:
  - name: reset
    on: recovery
    stages: [identify, email_otp, password_change, {stage: redirect, to: "https://app.example.com/"}]
    tests: [{name: t, given: {}, expect: [identify, email_otp, password_change, redirect]}]
`)
}

// The invitation stage is an enrolment's, and so is the condition it reads.
func TestInvitationOnlySignUpIsAnEnrolmentsAlone(t *testing.T) {
	mustParse(t, enrolment("      - invitation\n      - create_user\n      - done",
		"      - {name: invited, given: {}, expect: [invitation, create_user, done]}"))
	mustParse(t, enrolment("      - {stage: captcha, when: not invited}\n      - create_user\n      - done",
		"      - {name: invited, given: {invited: true}, expect: [create_user, done]}\n"+
			"      - {name: anybody, given: {}, expect: [captcha, create_user, done]}"))
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages: [invitation, password, session]
    tests: [{name: t, given: {}, expect: [invitation, password, session]}]
`, "invitation")
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages: [{stage: mfa, when: invited}, password, session]
    tests: [{name: t, given: {}, expect: [password, session]}]
`, "invited")
}
