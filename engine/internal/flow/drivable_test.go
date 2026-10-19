package flow

import (
	"fmt"
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
		{Authentication, "[password, kerberos, session]", "kerberos"},
		{Authentication, "[federated, session]", "federated"},
		{Authentication, "[delegated, session]", "delegated"},
		{Authentication, "[certificate, session]", "certificate"},
		{Authentication, "[email_otp, session]", "email_otp"},
		{Authentication, "[sms_otp, session]", "sms_otp"},
		{Authentication, "[password, enrol_mfa, session]", "enrol_mfa"},
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
