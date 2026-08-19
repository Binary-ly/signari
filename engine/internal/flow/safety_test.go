package flow

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// The analysis in safety.go is a static argument about every path through a
// flow. These tests check it against the thing it is an argument about: the
// walker in walk.go, run over every condition assignment there is.
//
// An example-based test of a static analysis proves the examples. What has to be
// true is a quantified statement -- no accepted flow has an unsafe path -- and
// for flows this small that statement is checkable by exhaustion rather than
// argument.

// paths enumerates every stage sequence a flow can produce, by running the
// walker under all 2^n assignments of the conditions the flow mentions.
//
// Uses the real Cursor, deliberately. A reimplementation of the traversal here
// would let the analysis and the test agree with each other while both disagree
// with what the server does.
func paths(fl *Flow) [][]StageName {
	var conds []string
	seen := map[string]bool{}
	note := func(expr string) {
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expr), "not "))
		if name != "" && !seen[name] {
			seen[name] = true
			conds = append(conds, name)
		}
	}
	for _, st := range fl.Stages {
		note(st.When)
		for _, b := range st.OneOf {
			note(b.When)
		}
	}
	if len(conds) > 16 {
		panic("too many conditions to enumerate")
	}

	var out [][]StageName
	for mask := 0; mask < 1<<len(conds); mask++ {
		st := State{}
		for i, c := range conds {
			st[c] = mask&(1<<i) != 0
		}
		out = append(out, fl.Plan(st))
	}
	return out
}

// The oracles below restate the package's specification directly, rather than
// consulting the analysis. That is the point: if they were written in terms of
// guaranteedProver they would agree with safety.go by construction and prove
// nothing about it.
//
// The specification is designation-dependent, and stating it once here is what
// makes the property tests meaningful:
//
//	enrolment                            -- may not reach a session; nothing else
//	authentication, recovery, unenrolment -- proof rule, then order rule
//
// Enrolment is exempt from proof and order BECAUSE it cannot reach a session.
// An oracle that applied all three rules to every designation would fail the
// analysis for being correct.

// unsafePath returns a path that reaches a session having proved nothing.
func unsafePath(fl *Flow, d Designation) ([]StageName, bool) {
	for _, p := range paths(fl) {
		reached, proved := false, false
		for _, s := range p {
			// Enrolment has no notion of proving, so any session it reaches is
			// unsafe by definition -- which is exactly the rule it pays for its
			// exemption with.
			if d != Enrolment && s.proves(d) {
				proved = true
			}
			if s == StageSession {
				reached = true
			}
		}
		if reached && !proved {
			return p, true
		}
	}
	return nil, false
}

// disorderedPath returns a path that changes a credential before proving anyone.
//
// Not applicable to enrolment: creating an account and setting its first
// credential is the entire job, and there is nobody to have proved.
func disorderedPath(fl *Flow, d Designation) ([]StageName, bool) {
	if d == Enrolment {
		return nil, false
	}
	for _, p := range paths(fl) {
		proved := false
		for _, s := range p {
			if mutatingStages[s] && !proved {
				return p, true
			}
			if s.proves(d) {
				proved = true
			}
		}
	}
	return nil, false
}

// TestTheAnalysisNeverAdmitsAnUnsafeFlow is the soundness property.
//
// Random flows, every one of them walked under every condition assignment. Any
// flow the analysis accepts must have no unsafe path -- not for these inputs
// because they were chosen, but because the generator makes flows the author of
// the analysis did not have in mind.
func TestTheAnalysisNeverAdmitsAnUnsafeFlow(t *testing.T) {
	rng := rand.New(rand.NewSource(20260819))

	accepted, rejected := 0, 0
	for n := 0; n < 20000; n++ {
		fl := randomFlow(rng)
		if err := fl.checkSafety(); err != nil {
			rejected++
			continue
		}
		accepted++

		if p, bad := unsafePath(fl, fl.On); bad {
			t.Fatalf("the analysis accepted a flow with a path to a session that proves nothing.\n"+
				"flow: %s\npath: %s", show(fl), joinStages(p))
		}
		if p, bad := disorderedPath(fl, fl.On); bad {
			t.Fatalf("the analysis accepted a flow that changes a credential before proving anyone.\n"+
				"flow: %s\npath: %s", show(fl), joinStages(p))
		}
	}

	// A generator that produced nothing acceptable would make the assertions
	// above vacuous, and this test would pass forever having checked nothing.
	if accepted < 500 {
		t.Fatalf("only %d of %d generated flows were accepted; the property above is "+
			"barely being exercised", accepted, accepted+rejected)
	}
	t.Logf("accepted %d, rejected %d", accepted, rejected)
}

// TestTheAnalysisRejectsOnlyForAReason is the other half.
//
// Soundness alone is satisfiable by refusing everything. Every rejection must
// correspond to a real unsafe path, OR to the one incompleteness the package
// documents: conditions the author knows are exhaustive and the analysis does
// not. Anything else is a bug in the analysis -- a flow refused for no reason
// anybody can point at.
func TestTheAnalysisRejectsOnlyForAReason(t *testing.T) {
	rng := rand.New(rand.NewSource(4172026))

	documented := 0
	for n := 0; n < 20000; n++ {
		fl := randomFlow(rng)
		if err := fl.checkSafety(); err == nil {
			continue
		}
		_, unsafe := unsafePath(fl, fl.On)
		_, disordered := disorderedPath(fl, fl.On)
		if unsafe || disordered {
			continue
		}
		// No unsafe path exists under any assignment, yet it was refused. That is
		// only acceptable if some proving stage is conditional -- the documented
		// incompleteness, whose remedy is one_of.
		if fl.hasConditionalProver() {
			documented++
			continue
		}
		// create_user outside enrolment is refused by rule, not by path analysis.
		if fl.On != Enrolment && mentions(fl, StageCreateUser) {
			continue
		}
		t.Fatalf("a flow with no unsafe path was refused, and not for a documented reason.\n"+
			"flow: %s\nerror: %v", show(fl), fl.checkSafety())
	}
	t.Logf("%d refusals attributable to the documented incompleteness", documented)
}

func TestTheNestedStageFlowIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: identify-then-in
    on: authentication
    stages:
      - identify
      - session
    tests:
      - name: signs in
        given: {}
        expect: [identify, session]
`))
	if err == nil {
		t.Fatal("a flow of identify -> session loaded; that flow signs in anybody who can " +
			"type a username that exists")
	}
	if !strings.Contains(err.Error(), "without proving who the subject is") {
		t.Fatalf("refused, but not for the right reason: %v", err)
	}
	// The message has to name the trap, or the author adds a captcha and tries
	// again.
	if !strings.Contains(err.Error(), "knowing a username is not") {
		t.Fatalf("the error does not explain why identify is not enough: %v", err)
	}
}

// TestEnrollingAFactorBeforeProvingAnyoneIsRefused is the subtler bypass.
//
// It reads like two factors and is one: the enrolled authenticator is the
// attacker's, so the stage that checks it passes for the attacker.
func TestEnrollingAFactorBeforeProvingAnyoneIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: enrol-then-check
    on: authentication
    stages:
      - identify
      - enrol_mfa
      - mfa
      - session
    tests:
      - name: enrols and checks
        given: {}
        expect: [identify, enrol_mfa, mfa, session]
`))
	if err == nil {
		t.Fatal("a flow that enrols a second factor and then demands it loaded; whoever " +
			"reaches it attaches their own authenticator to somebody else's account")
	}
	if !strings.Contains(err.Error(), "changes the subject's credentials") {
		t.Fatalf("refused, but not as an ordering problem: %v", err)
	}
}

// TestPasswordChangeBeforeProofIsRefused is the same rule, older bug.
func TestPasswordChangeBeforeProofIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: reset-first
    on: authentication
    stages:
      - identify
      - password_change
      - password
      - session
    tests:
      - name: resets then checks
        given: {}
        expect: [identify, password_change, password, session]
`))
	if err == nil {
		t.Fatal("a flow that sets a password before checking one loaded")
	}
	if !strings.Contains(err.Error(), "sets the password on the named account") {
		t.Fatalf("the error does not say what an attacker gets: %v", err)
	}
}

// TestAConditionalProverIsNotEnough covers the case an author will hit, and
// checks they are told what to do about it rather than only that it is wrong.
func TestAConditionalProverIsNotEnough(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: exhaustive-by-eye
    on: authentication
    stages:
      - identify
      - {stage: passkey, when: user_has_passkey}
      - {stage: password, when: not user_has_passkey}
      - session
    tests:
      - name: with a passkey
        given: {user_has_passkey: true}
        expect: [identify, passkey, session]
`))
	if err == nil {
		t.Fatal("two conditional provers were accepted as covering every case; the analysis " +
			"cannot know the conditions are exhaustive")
	}
	if !strings.Contains(err.Error(), "one_of") {
		t.Fatalf("the author is not told about the construct that fixes this: %v", err)
	}
}

// TestAOneOfOfProversIsAccepted is the remedy actually working.
func TestAOneOfOfProversIsAccepted(t *testing.T) {
	f, err := Parse([]byte(`
version: 1
flows:
  - name: passkey-or-password
    on: authentication
    stages:
      - identify
      - one_of:
          - {stage: passkey, when: user_has_passkey}
          - {stage: password}
      - {stage: mfa, when: user_has_second_factor}
      - session
    tests:
      - name: passkey holder
        given: {user_has_passkey: true}
        expect: [identify, passkey, session]
      - name: password, no second factor
        given: {}
        expect: [identify, password, session]
      - name: password and a second factor
        given: {user_has_second_factor: true}
        expect: [identify, password, mfa, session]
`))
	if err != nil {
		t.Fatalf("a sound flow was refused: %v", err)
	}
	fl, _ := f.Flow("passkey-or-password")
	if _, bad := unsafePath(fl, Authentication); bad {
		t.Fatal("accepted, and it does have an unsafe path")
	}
}

// TestAOneOfWithOneWeakBranchIsRefused checks the group is judged by its worst
// branch. A choice between proving and not proving is not a proof.
func TestAOneOfWithOneWeakBranchIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: sometimes
    on: authentication
    stages:
      - one_of:
          - {stage: password, when: not user_is_new}
          - {stage: captcha}
      - session
    tests:
      - name: known user
        given: {}
        expect: [password, session]
`))
	if err == nil {
		t.Fatal("a one_of with a branch that proves nothing was accepted; taking that " +
			"branch reaches the session unauthenticated")
	}
}

// TestARecoveryFlowMayNotAcceptTheFactorItReplaces.
func TestARecoveryFlowMayNotAcceptTheFactorItReplaces(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: recover
    on: recovery
    stages:
      - identify
      - password
      - password_change
      - session
    tests:
      - name: recovers
        given: {}
        expect: [identify, password, password_change, session]
`))
	if err == nil {
		t.Fatal("a recovery flow that authenticates with a password was accepted; the " +
			"password is the thing being recovered")
	}
	// Refused by the ORDER rule, which reaches password_change first. What matters
	// is that its remedy names the narrowed set: the general list includes
	// password, and following it would earn a second refusal from the proof rule.
	if !strings.Contains(err.Error(), "narrower here than elsewhere") {
		t.Fatalf("refused, but the remedy does not tell the author that recovery "+
			"counts fewer factors: %v", err)
	}
	if strings.Contains(err.Error(), "(password,") {
		t.Fatalf("the remedy offers password, which this flow may not use: %v", err)
	}
}

// TestARecoveryFlowThatOnlyAuthenticatesWeaklyIsRefused reaches the proof rule
// rather than the order rule, by leaving out the stage that changes anything.
//
// Both rules can refuse a recovery flow and they say different things; a test
// that only ever exercised whichever fires first would leave the other's message
// unexercised, which is how an error nobody has read ships.
func TestARecoveryFlowThatOnlyAuthenticatesWeaklyIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: recover
    on: recovery
    stages:
      - identify
      - password
      - session
    tests:
      - name: recovers
        given: {}
        expect: [identify, password, session]
`))
	if err == nil {
		t.Fatal("a recovery flow whose only proof is a password was accepted")
	}
	if !strings.Contains(err.Error(), "does not count in a recovery flow") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestARecoveryFlowWithAnOutOfBandFactorIsAccepted is the other side of it.
func TestARecoveryFlowWithAnOutOfBandFactorIsAccepted(t *testing.T) {
	if _, err := Parse([]byte(`
version: 1
flows:
  - name: recover
    on: recovery
    stages:
      - identify
      - email_otp
      - password_change
      - session
    tests:
      - name: recovers by email
        given: {}
        expect: [identify, email_otp, password_change, session]
`)); err != nil {
		t.Fatalf("a sound recovery flow was refused: %v", err)
	}
}

// TestAnEnrolmentFlowMayNotReachASession.
func TestAnEnrolmentFlowMayNotReachASession(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: sign-up
    on: enrolment
    stages:
      - prompt
      - create_user
      - session
    tests:
      - name: signs up and in
        given: {}
        expect: [prompt, create_user, session]
`))
	if err == nil {
		t.Fatal("an enrolment flow issued a session; sign-up decides who exists, not who " +
			"is signed in")
	}
}

// TestCreateUserOutsideEnrolmentIsRefused.
func TestCreateUserOutsideEnrolmentIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
flows:
  - name: login
    on: authentication
    stages:
      - identify
      - {stage: create_user, when: user_is_new}
      - password
      - session
    tests:
      - name: existing user
        given: {}
        expect: [identify, password, session]
`))
	if err == nil {
		t.Fatal("an authentication flow that can create accounts was accepted")
	}
	if !strings.Contains(err.Error(), "belongs to an enrolment flow") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestADenyingFlowNeedsNoProof -- nothing is handed out, so there is nothing to
// prove. Included because a rule that fires on flows it has no business
// refusing is a rule people learn to work around.
func TestADenyingFlowNeedsNoProof(t *testing.T) {
	if _, err := Parse([]byte(`
version: 1
flows:
  - name: closed
    on: authentication
    stages:
      - identify
      - deny
    tests:
      - name: always refused
        given: {}
        expect: [identify, deny]
`)); err != nil {
		t.Fatalf("a flow that refuses everybody was itself refused: %v", err)
	}
}

// --- generator -------------------------------------------------------------

// randomFlow builds a small flow from the real inventory.
//
// Weighted towards the shapes that are hard: conditional stages, one_of groups,
// mutating stages in arbitrary positions. A generator that mostly produced
// `password -> session` would confirm the easy case twenty thousand times.
func randomFlow(rng *rand.Rand) *Flow {
	pool := []StageName{
		StageIdentify, StageCaptcha, StagePassword, StagePasskey, StageMFA,
		StageEmailOTP, StageCertificate, StageFederated, StageConsent,
		StagePrompt, StagePasswordChange, StageEnrolMFA, StageCreateUser,
	}
	conds := []string{
		string(CondHasPasskey), string(CondHasSecondFactor), string(CondUserIsNew),
		"not " + string(CondHasPasskey), "not " + string(CondUserIsNew),
	}

	designations := []Designation{Authentication, Recovery, Unenrolment, Enrolment}
	fl := &Flow{
		Name: "generated",
		On:   designations[rng.Intn(len(designations))],
	}

	n := 1 + rng.Intn(5)
	for i := 0; i < n; i++ {
		switch {
		case rng.Intn(5) == 0:
			// A one_of, always with the default branch validateGroup requires.
			g := []Branch{
				{Stage: pool[rng.Intn(len(pool))], When: conds[rng.Intn(len(conds))]},
				{Stage: pool[rng.Intn(len(pool))]},
			}
			fl.Stages = append(fl.Stages, Step{OneOf: g})
		case rng.Intn(2) == 0:
			fl.Stages = append(fl.Stages, Step{
				Stage: pool[rng.Intn(len(pool))],
				When:  conds[rng.Intn(len(conds))],
			})
		default:
			fl.Stages = append(fl.Stages, Step{Stage: pool[rng.Intn(len(pool))]})
		}
	}
	// Terminal, unconditional, as validate() requires.
	if rng.Intn(4) == 0 {
		fl.Stages = append(fl.Stages, Step{Stage: StageDeny})
	} else {
		fl.Stages = append(fl.Stages, Step{Stage: StageSession})
	}
	return fl
}

func mentions(fl *Flow, want StageName) bool {
	for _, st := range fl.Stages {
		for _, n := range st.stageNames() {
			if n == want {
				return true
			}
		}
	}
	return false
}

func show(fl *Flow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "on=%s", fl.On)
	for _, st := range fl.Stages {
		if len(st.OneOf) > 0 {
			var arms []string
			for _, br := range st.OneOf {
				if br.When == "" {
					arms = append(arms, string(br.Stage))
				} else {
					arms = append(arms, fmt.Sprintf("%s if %s", br.Stage, br.When))
				}
			}
			fmt.Fprintf(&b, " | one_of(%s)", strings.Join(arms, " / "))
			continue
		}
		if st.When == "" {
			fmt.Fprintf(&b, " | %s", st.Stage)
		} else {
			fmt.Fprintf(&b, " | %s if %s", st.Stage, st.When)
		}
	}
	return b.String()
}
