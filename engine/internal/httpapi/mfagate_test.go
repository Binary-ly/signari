package httpapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The `mfa` stage must bind every way in, not one of them.
//
// # The bug this exists to stop coming back
//
// `completeSignIn` has ten callers. For a long time exactly one of them -- the
// password path -- asked whether the flow demanded a second factor. Passkey,
// Kerberos, Duo, the federated sources and the second password path all reached
// a session without consulting it. An operator who wrote an unconditional `mfa`
// stage and enrolled passkeys believed the deployment had MFA and did not.
//
// That arrangement was deliberate and documented, so reverting it is a plausible
// future edit rather than an unthinkable one. The sequencer is now the single
// place the stage is acted on; these tests fail if it stops acting.
//
// This is a SOURCE-level guard, and that is a real limitation worth stating: it
// proves the sequencer still acts on the stage and that session creation still
// funnels through it. It does not drive ten sign-ins. The behavioural half
// belongs in an end-to-end run against a live engine.

func flowdriveSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("flowdrive.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// mfaStageBlock extracts the body of `case flow.StageMFA:` up to the next case.
func mfaStageBlock(t *testing.T, src string) string {
	t.Helper()
	start := strings.Index(src, "case flow.StageMFA:")
	if start < 0 {
		t.Fatal("`case flow.StageMFA:` is gone from the sequencer. If the stage was " +
			"renamed, update this test; if the case was deleted, the mfa stage is " +
			"silently inert again and every sign-in path skips it")
	}
	rest := src[start+len("case flow.StageMFA:"):]
	if end := strings.Index(rest, "\n\t\tcase "); end >= 0 {
		rest = rest[:end]
	}
	if def := strings.Index(rest, "\n\t\tdefault:"); def >= 0 {
		rest = rest[:def]
	}
	return rest
}

// The stage must actually challenge, not fall through.
func TestTheMFAStageIsActedOnBySequencer(t *testing.T) {
	block := mfaStageBlock(t, flowdriveSource(t))

	if !strings.Contains(block, "beginMFAChallenge") {
		t.Fatal("the mfa stage no longer starts a challenge. Whatever it does now, a " +
			"flow that demands a second factor is not getting one, and every caller " +
			"of completeSignIn reaches a session on one factor")
	}
	if !strings.Contains(block, "decisionHandled") {
		t.Error("the mfa stage does not return decisionHandled, so the walker carries " +
			"on to the session after starting a challenge")
	}
	// The pre-change body was exactly one `continue` and a long comment. A block
	// whose only statement is `continue` is that state restored.
	stripped := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(block, "")
	stripped = strings.TrimSpace(stripped)
	if stripped == "continue" {
		t.Fatal("the mfa stage is a bare `continue` again -- the exact state in which " +
			"an unconditional mfa stage bound the password path alone")
	}
}

// Refusing when nothing is enrolled must survive too.
//
// Waving these accounts through would mean the control holds for every account
// except the ones it was written to catch.
func TestTheMFAStageRefusesWhenNothingIsEnrolled(t *testing.T) {
	block := mfaStageBlock(t, flowdriveSource(t))
	if !strings.Contains(block, "CondHasSecondFactor") {
		t.Error("the mfa stage no longer checks whether anything is enrolled, so an " +
			"account with no factor is either waved through or sent to a challenge " +
			"it cannot answer")
	}
	if !strings.Contains(block, "mfa_required_but_not_enrolled") {
		t.Error("the refusal is no longer audited; an account blocked at sign-in " +
			"leaves no record of why")
	}
}

// A sign-in that has already proved two factors must not be challenged again.
//
// Without this the passkey path loops: a passkey without user verification
// reports ["user","hwk"], the challenge adds ["otp"], and both are possession,
// so a naive derivation still answers single-factor and demands the code again.
func TestAlreadyMultiFactorSignInsAreNotChallenged(t *testing.T) {
	block := mfaStageBlock(t, flowdriveSource(t))
	if !strings.Contains(block, "hasSecondFactorAMR") {
		t.Fatal("the mfa stage no longer short-circuits on what has already been " +
			"proved. Every path that completes a second factor re-enters here, so " +
			"without this check the challenge repeats forever")
	}

	// And the challenge path must assert AMRMFA, or the short-circuit above
	// cannot see that a second factor happened when both factors are possession.
	b, err := os.ReadFile("mfachallenge.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "oauth.AMRMFA") {
		t.Fatal("mfachallenge.go no longer records AMRMFA after a proven second " +
			"factor. ACRFromAMR groups otp and hwk both as possession, so a passkey " +
			"plus a TOTP code derives to single-factor and the sequencer challenges " +
			"again -- an infinite loop that locks out exactly the users who complied")
	}
}

// Session creation must stay funnelled through the sequencer, or a new sign-in
// method can bypass the gate by minting a session itself.
func TestSessionCreationGoesThroughTheSequencer(t *testing.T) {
	b, err := os.ReadFile("flow.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "s.advanceSignIn(") {
		t.Fatal("completeSignIn no longer calls advanceSignIn. The mfa stage, the " +
			"prompts and the password-change stage are all enforced there, so every " +
			"one of them is now optional")
	}
}
