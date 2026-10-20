package flow

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func oneFlow(on Designation, stages string) string {
	return fmt.Sprintf(`
version: 1
flows:
  - name: f
    on: %s
    stages: %s
    tests: [{name: t, given: {}, expect: %s}]
`, on, stages, stages)
}

// A stage the journey cannot run is refused when the file is parsed, naming
// it. A sign-in used to walk past it, so `password, kerberos, session` asked
// for a password and nothing more, and a sign-up or recovery stopped at it with
// a 501 in front of whoever tried first.
func TestAStageTheJourneyCannotRunIsRefused(t *testing.T) {
	for _, c := range []struct {
		on     Designation
		stages string
		names  string
	}{
		{Authentication, "[delegated, session]", "delegated"},
		{Authentication, "[certificate, session]", "certificate"},
		{Authentication, "[email_otp, session]", "email_otp"},
		{Authentication, "[sms_otp, session]", "sms_otp"},
		{Enrolment, "[enrol_mfa, create_user, done]", "enrol_mfa"},
		{Enrolment, "[identify, create_user, done]", "identify"},
		{Recovery, "[identify, email_otp, mfa, password_change, done]", "mfa"},
		{Recovery, "[identify, sms_otp, password_change, done]", "sms_otp"},
		{Recovery, "[identify, email_otp, password_change, session]", "session"},
	} {
		_, err := Parse([]byte(oneFlow(c.on, c.stages)))
		if err == nil {
			t.Errorf("on %s, %s was accepted; %s would be skipped or stop the journey",
				c.on, c.stages, c.names)
			continue
		}
		if !strings.Contains(err.Error(), "is "+c.names+", which this engine does not run") {
			t.Errorf("on %s, %s was refused without naming %s: %v", c.on, c.stages, c.names, err)
		}
	}
}

// A sign-in presents one proof, so a journey asking for two of them could only
// refuse whoever walks it, and is refused when the file is parsed, naming both
// (2.49). `password, kerberos, session` was once a password sign-in that
// walked past kerberos; then, with the proof matched, it would have refused
// everybody. Alternatives are what one_of is for, and an impossible
// combination -- two proved_by conditions at once -- is not a journey.
func TestAJourneyAskingForTwoSignInProofsIsRefused(t *testing.T) {
	// The test case's expect is the journey with nothing true.
	flowOf := func(stages, expect string) string {
		return fmt.Sprintf(`
version: 1
flows:
  - name: f
    on: authentication
    stages: %s
    tests: [{name: t, given: {}, expect: %s}]
`, stages, expect)
	}
	for _, c := range [][2]string{
		{"[password, kerberos, session]", "[password, kerberos, session]"},
		{"[passkey, password, mfa, session]", "[passkey, password, mfa, session]"},
		{"[{stage: federated, when: proved_by_federated}, password, session]", "[password, session]"},
	} {
		_, err := Parse([]byte(flowOf(c[0], c[1])))
		if err == nil || !strings.Contains(err.Error(), "a sign-in presents one of them") {
			t.Errorf("%s was not refused for asking for two proofs: %v", c[0], err)
		}
	}
	for _, c := range [][2]string{
		{"[{one_of: [{stage: kerberos, when: proved_by_kerberos}, {stage: password}]}, session]", "[password, session]"},
		// Asks for two proofs only when proved_by_password and proved_by_kerberos
		// both hold, which no sign-in can make true.
		{"[{one_of: [{stage: kerberos, when: proved_by_kerberos}, {stage: password}]}, " +
			"{stage: password, when: proved_by_password}, session]", "[password, session]"},
	} {
		if _, err := Parse([]byte(flowOf(c[0], c[1]))); err != nil {
			t.Errorf("%s was refused: %v", c[0], err)
		}
	}
}

// Which ways in a flow admits, for doctor to name the ones it refuses that an
// organisation uses (2.49).
func TestAFlowSaysWhichSignInProofsItAdmits(t *testing.T) {
	builtin, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	all := []StageName{StagePassword, StagePasskey, StageKerberos, StageFederated}
	for _, s := range all {
		if !builtin.Flows[0].AdmitsProof(s) {
			t.Errorf("the built-in sign-in does not admit %s", s)
		}
	}
	for stages, admits := range map[string][]StageName{
		"[passkey, session]":           {StagePasskey},
		"[password, mfa, session]":     {StagePassword},
		"[mfa, session]":               all,
		"[password, deny]":             nil,
		"[federated, prompt, session]": {StageFederated},
	} {
		f, err := Parse([]byte(oneFlow(Authentication, stages)))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range all {
			if got, want := f.Flows[0].AdmitsProof(s), slices.Contains(admits, s); got != want {
				t.Errorf("%s admits %s: %v, want %v", stages, s, got, want)
			}
		}
	}
}

// Every stage a journey runs is accepted there, and nothing walks an
// unenrolment flow, so its stages are not judged.
func TestAStageTheJourneyRunsIsAccepted(t *testing.T) {
	for _, c := range []struct {
		on     Designation
		stages string
	}{
		{Authentication, "[identify, captcha, password, mfa, prompt, password_change, consent, session]"},
		{Authentication, "[passkey, done]"},
		{Authentication, "[password, deny]"},
		{Authentication, "[kerberos, mfa, session]"},
		{Authentication, "[federated, session]"},
		{Enrolment, "[captcha, prompt, create_user, done]"},
		{Enrolment, "[deny]"},
		{Recovery, "[captcha, identify, email_otp, password_change, done]"},
		{Recovery, "[deny]"},
		{Unenrolment, "[kerberos, done]"},
	} {
		if _, err := Parse([]byte(oneFlow(c.on, c.stages))); err != nil {
			t.Errorf("on %s, %s was refused: %v", c.on, c.stages, err)
		}
	}
}
