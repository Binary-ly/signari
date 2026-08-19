package flow

import (
	"strings"
	"testing"
)

// A flow that is correct in every way, used as the base for tests that change
// one thing. Written in the terse spelling on purpose: if the scalar form ever
// stops parsing, most of this file fails at once rather than one test that
// somebody might mark as flaky.
const goodFlow = `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - {stage: captcha, when: captcha_required}
      - identify
      - password
      - {stage: mfa, when: user_has_second_factor}
      - {stage: prompt, when: prompts_pending}
      - session
    tests:
      - name: plain
        given: {}
        expect: [identify, password, session]
      - name: with a challenge and a factor
        given: {captcha_required: true, user_has_second_factor: true}
        expect: [captcha, identify, password, mfa, session]
`

func mustParse(t *testing.T, doc string) *File {
	t.Helper()
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("expected this to parse: %v", err)
	}
	return f
}

func parseErr(t *testing.T, doc, wantSubstring string) {
	t.Helper()
	_, err := Parse([]byte(doc))
	if err == nil {
		t.Fatalf("expected a refusal mentioning %q; it parsed", wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("refused, but not for the stated reason.\nwant substring: %q\ngot: %v",
			wantSubstring, err)
	}
}

func TestAWellFormedFlowParses(t *testing.T) {
	f := mustParse(t, goodFlow)
	fl, ok := f.Flow("sign-in")
	if !ok {
		t.Fatal("the flow is not findable by name")
	}
	if got := joinStages(fl.Plan(State{})); got != "identify -> password -> session" {
		t.Fatalf("plan for the empty state: %s", got)
	}
	if _, ok := f.For(Authentication); !ok {
		t.Fatal("not findable by designation")
	}
}

// TestABareStageNameIsAStage covers the scalar spelling, which is what makes a
// flow file readable and is the one piece of custom unmarshalling here.
func TestABareStageNameIsAStage(t *testing.T) {
	f := mustParse(t, `
version: 1
flows:
  - name: terse
    on: authentication
    stages: [password, session]
    tests:
      - name: only way through
        given: {}
        expect: [password, session]
`)
	fl, _ := f.Flow("terse")
	if fl.Stages[0].Stage != StagePassword || fl.Stages[0].When != "" {
		t.Fatalf("a bare name did not become an unconditional stage: %+v", fl.Stages[0])
	}
}

// TestTheFilesOwnTestsAreRun is the property the whole design rests on.
func TestTheFilesOwnTestsAreRun(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_second_factor}
      - session
    tests:
      - name: claims mfa always runs
        given: {}
        expect: [password, mfa, session]
`, "do not do what their tests say")
}

// TestATestExpectingTheWrongOrderFails -- the expectation is an exact sequence,
// not a set. A flow that runs the right stages in the wrong order is a different
// flow.
func TestATestExpectingTheWrongOrderFails(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages: [identify, password, session]
    tests:
      - name: wrong order
        given: {}
        expect: [password, identify, session]
`, "do not do what their tests say")
}

func TestAFlowWithNoTestsIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: untested
    on: authentication
    stages: [password, session]
`, "has no tests")
}

// TestAnUnknownFieldIsRefused -- the misspelling that matters is `when`, because
// a `when` that does not bind becomes an unconditional stage: a condition that
// appears to restrict and does not.
func TestAnUnknownFieldIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: typo
    on: authentication
    stages:
      - password
      - {stage: mfa, whn: user_has_second_factor}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, mfa, session]
`, "did not parse")
}

// TestAnUnknownFieldInsideAOneOfBranchIsRefused covers the same hole one level
// down. A branch is decoded by its own unmarshaller, so it loses the decoder's
// strictness for exactly the same reason a step does.
func TestAnUnknownFieldInsideAOneOfBranchIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: typo
    on: authentication
    stages:
      - one_of:
          - {stage: passkey, whn: user_has_passkey}
          - {stage: password}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "is not a field here")
}

func TestAnUnknownStageIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages: [password, totp, session]
    tests:
      - name: x
        given: {}
        expect: [password, totp, session]
`, "is not a stage")
}

func TestAnUnknownConditionIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_totp}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "is not a condition")
}

// TestAnUnknownConditionInATestIsRefused catches the case where the flow is
// right and the test sets a fact nothing reads -- so the case passes for the
// wrong reason and covers nothing.
func TestAnUnknownConditionInATestIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_second_factor}
      - session
    tests:
      - name: typo in the given
        given: {user_has_2fa: true}
        expect: [password, session]
`, "is not a condition")
}

func TestAConditionWithTwoTermsIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - password
      - {stage: mfa, when: user_has_second_factor and risk_elevated}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "is one condition")
}

func TestNegationWorks(t *testing.T) {
	f := mustParse(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - {stage: mfa, when: not network_trusted}
      - session
    tests:
      - name: off the office network
        given: {}
        expect: [password, mfa, session]
      - name: on it
        given: {network_trusted: true}
        expect: [password, session]
`)
	if _, ok := f.Flow("sign-in"); !ok {
		t.Fatal("missing")
	}
}

func TestAStageAfterATerminalIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages: [password, session, prompt]
    tests:
      - name: x
        given: {}
        expect: [password, session, prompt]
`, "which ends a flow, but 1 step(s) follow it")
}

func TestAFlowNotEndingInATerminalIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages: [password, prompt]
    tests:
      - name: x
        given: {}
        expect: [password, prompt]
`, "is not a terminal stage")
}

// TestAConditionalTerminalIsRefused -- a last step that can be skipped leaves
// paths that end in nothing, and "nothing" is not an outcome the caller can act
// on.
func TestAConditionalTerminalIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - password
      - {stage: session, when: not risk_elevated}
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "is conditional")
}

func TestTwoFlowsWithTheSameNameAreRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: dup
    on: authentication
    stages: [password, session]
    tests: [{name: a, given: {}, expect: [password, session]}]
  - name: dup
    on: recovery
    stages: [email_otp, session]
    tests: [{name: b, given: {}, expect: [email_otp, session]}]
`, "two flows are named")
}

func TestAnUnknownDesignationIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: login
    stages: [password, session]
    tests: [{name: a, given: {}, expect: [password, session]}]
`, "is not a designation")
}

func TestAnUnsupportedVersionIsRefused(t *testing.T) {
	parseErr(t, `
version: 2
flows:
  - name: x
    on: authentication
    stages: [password, session]
    tests: [{name: a, given: {}, expect: [password, session]}]
`, "is not supported")
}

// --- one_of ----------------------------------------------------------------

func TestAOneOfWithoutADefaultBranchIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - one_of:
          - {stage: passkey, when: user_has_passkey}
          - {stage: password, when: not user_has_passkey}
      - session
    tests:
      - name: x
        given: {user_has_passkey: true}
        expect: [passkey, session]
`, "making it the default")
}

func TestAOneOfWithADefaultBeforeTheEndIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - one_of:
          - {stage: password}
          - {stage: passkey, when: user_has_passkey}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "can never run")
}

func TestAOneOfWithOneBranchIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - one_of:
          - {stage: password}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "is not a choice")
}

func TestATerminalInsideAOneOfIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - one_of:
          - {stage: deny, when: risk_elevated}
          - {stage: password}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "cannot be one arm of a choice")
}

func TestAStepSettingBothStageAndOneOfIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: bad
    on: authentication
    stages:
      - stage: password
        one_of:
          - {stage: passkey, when: user_has_passkey}
          - {stage: password}
      - session
    tests:
      - name: x
        given: {}
        expect: [password, session]
`, "one or the other")
}

// TestTheFirstMatchingBranchWins pins the selection rule, which decides which
// factor somebody is asked for.
func TestTheFirstMatchingBranchWins(t *testing.T) {
	f := mustParse(t, `
version: 1
flows:
  - name: pick
    on: authentication
    stages:
      - one_of:
          - {stage: certificate, when: device_managed}
          - {stage: passkey, when: user_has_passkey}
          - {stage: password}
      - session
    tests:
      - name: managed device, also has a passkey
        given: {device_managed: true, user_has_passkey: true}
        expect: [certificate, session]
      - name: passkey only
        given: {user_has_passkey: true}
        expect: [passkey, session]
      - name: neither
        given: {}
        expect: [password, session]
`)
	if _, ok := f.Flow("pick"); !ok {
		t.Fatal("missing")
	}
}

// --- the walker ------------------------------------------------------------

// TestTheCursorReEvaluatesAsItGoes is the difference between Plan and Cursor,
// and it is not cosmetic: whether a password change is required is not knowable
// until the password has been checked.
//
// Plan is given a fixed state and cannot see the change. The cursor is handed
// the state as it is now at each step, so it does.
func TestTheCursorReEvaluatesAsItGoes(t *testing.T) {
	f := mustParse(t, `
version: 1
flows:
  - name: sign-in
    on: authentication
    stages:
      - password
      - {stage: password_change, when: password_change_required}
      - session
    tests:
      - name: nothing flagged at the start
        given: {}
        expect: [password, session]
`)
	fl, _ := f.Flow("sign-in")

	// The snapshot: at the start, nothing is known to be flagged.
	if got := joinStages(fl.Plan(State{})); got != "password -> session" {
		t.Fatalf("snapshot plan: %s", got)
	}

	// The live walk: the password stage runs, and checking it reveals the
	// credential is flagged. The state the cursor is handed next reflects that.
	st := State{}
	c := fl.Cursor()
	var ran []StageName
	for {
		name, ok := c.Next(st)
		if !ok {
			break
		}
		ran = append(ran, name)
		if name == StagePassword {
			st[string(CondPasswordChangeRequired)] = true
		}
	}
	if got := joinStages(ran); got != "password -> password_change -> session" {
		t.Fatalf("the cursor did not see the state change made by an earlier stage: %s", got)
	}
}

// TestACursorResumesWhereItStopped -- a flow spans several requests, so the
// position has to survive between them.
func TestACursorResumesWhereItStopped(t *testing.T) {
	f := mustParse(t, goodFlow)
	fl, _ := f.Flow("sign-in")

	st := State{string(CondHasSecondFactor): true}
	c := fl.Cursor()
	if name, _ := c.Next(st); name != StageIdentify {
		t.Fatalf("first stage: %s", name)
	}
	if name, _ := c.Next(st); name != StagePassword {
		t.Fatalf("second stage: %s", name)
	}
	saved := c.At()

	// A new request, a fresh cursor built from the stored position.
	resumed := fl.Resume(saved)
	if name, _ := resumed.Next(st); name != StageMFA {
		t.Fatalf("after resuming, expected mfa, got %s", name)
	}
}

// TestResumingPastTheEndOfAnEditedFlowEndsIt is the case where an operator
// changes the file while somebody is halfway through.
//
// The stored index can now point anywhere. Ending the journey is recoverable --
// the caller restarts it. Running whatever stage now sits at that index is not,
// because that stage could be the session.
func TestResumingPastTheEndOfAnEditedFlowEndsIt(t *testing.T) {
	f := mustParse(t, goodFlow)
	fl, _ := f.Flow("sign-in")

	if name, ok := fl.Resume(999).Next(State{}); ok {
		t.Fatalf("a position past the end produced a stage: %s", name)
	}
	// Negative clamps forward rather than wrapping.
	if name, ok := fl.Resume(-5).Next(State{}); !ok || name != StageIdentify {
		t.Fatalf("a negative position should start at the beginning, got %s (%v)", name, ok)
	}
}

func TestATestWithNoNameIsRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: x
    on: authentication
    stages: [password, session]
    tests:
      - given: {}
        expect: [password, session]
`, "test with no name")
}

func TestTwoTestsWithTheSameNameAreRefused(t *testing.T) {
	parseErr(t, `
version: 1
flows:
  - name: x
    on: authentication
    stages: [password, session]
    tests:
      - {name: same, given: {}, expect: [password, session]}
      - {name: same, given: {}, expect: [password, session]}
`, "two tests named")
}

func TestAnEmptyFileIsRefused(t *testing.T) {
	parseErr(t, "version: 1\nflows: []\n", "defines no flows")
}
