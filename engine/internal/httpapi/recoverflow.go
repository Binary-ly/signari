package httpapi

import (
	"context"
	"net/http"

	"signari.dev/engine/internal/flow"
)

// Driving the recovery flow (9q option 3).
//
// # What was wrong
//
// `/recover` was a fixed sequence of Go. An operator could write a recovery
// flow, watch Parse accept it, watch the safety rules written specifically for
// recovery run against it -- `recoveryProving` exists only for this designation
// -- watch its own test cases pass, install it with `signari flow apply`, and
// have it govern nothing at all. That is worse than not offering the feature,
// because the operator stops looking.
//
// # The seam this driver sits on
//
// Recovery is two requests separated by an email, so the flow is consulted
// twice and each half can only execute the stages that belong to it:
//
//	POST /recover        captcha, identify        -> a request is created, mail sent
//	POST /recover/reset  email_otp, password_change, terminal
//
// Splitting the walk is not a shortcut. `captcha` has to run before the work it
// exists to protect -- creating a row and sending mail -- and `password_change`
// cannot run until the token proves the mailbox. No stage is evaluated in both
// halves, so the two walks cannot disagree.
//
// # Which organisation's flow
//
// The request half looks the flow up under the DEFAULT organisation, and that is
// a security requirement rather than a convenience. `/recover` must answer
// identically whether or not the account exists (see recovery.go). Reading the
// flow of the account's own organisation would make the journey vary by account
// -- one organisation demanding a challenge and another not -- which is an
// enumeration oracle wearing a configuration setting.
//
// The reset half knows the account, because the token named it, so it reads that
// organisation's flow.
//
// # Unsupported stages fail the journey closed
//
// The same rule the enrolment driver applies, for the same reason. Skipping a
// stage the operator put there on purpose is the bug this file exists to fix,
// re-introduced one level down. For recovery the realistic case is `mfa` -- an
// operator demanding a second factor before a reset -- and silently skipping it
// would reset the password having proved strictly less than the file requires.

// recoveryDrivableStages is every stage the recovery driver can execute, across
// BOTH halves.
//
// Support is a property of the driver as a whole, not of the half that happens
// to be running. The first version of this file checked each half against only
// its own stages, so the request half refused `password_change` -- a stage it is
// not supposed to run, because the reset half runs it -- and every ordinary
// recovery flow was rejected at the first request. Splitting the walk must not
// split the question of what is supported.
//
//   - captcha         request half
//   - identify        request half; the form collects an identifier, which is the
//     stage. Knowing a username proves nothing, which is why it
//     is in no proving set.
//   - email_otp       reset half, as a pass rather than a fresh challenge:
//     possession of the mailbox is what the tokenised link already
//     proved, and asking again would be a second challenge for the
//     same factor. Listed so a flow naming it -- as the shipped
//     default does -- is recognised rather than refused.
//   - password_change reset half; the reset itself
//   - done            reset half; the terminal
//
// `deny` is executable by both halves -- refusing is always something this engine
// can do -- so it is handled separately rather than listed here.
//
// Everything absent is refused, and the absences are the point. `mfa` before a
// reset, `sms_otp` as the proving channel, `passkey` recovery: each is a
// coherent thing to write and none of them runs, so each stops the journey
// rather than being skipped.
var recoveryDrivableStages = map[flow.StageName]bool{
	flow.StageCaptcha:        true,
	flow.StageIdentify:       true,
	flow.StageEmailOTP:       true,
	flow.StagePasswordChange: true,
	flow.StageDone:           true,
}

// recoveryPlan returns the stages in force, and whether every one of them can be
// executed by the half that is asking.
//
// A single pass over the plan answers both questions, and the refusal names the
// first stage that cannot run rather than reporting "something is unsupported".
func (s *Server) recoveryPlan(ctx context.Context, orgID string, st flow.State,
	fallback []flow.StageName) (plan []flow.StageName, unsupported flow.StageName, name string) {

	fl := s.flowFor(ctx, orgID, flow.Recovery)
	plan = fallback
	if fl != nil {
		plan = fl.Plan(st)
	}
	for _, stage := range plan {
		if stage == flow.StageDeny || recoveryDrivableStages[stage] {
			continue
		}
		return plan, stage, flowNameOf(fl)
	}
	return plan, "", flowNameOf(fl)
}

// refuseRecoveryStage reports a stage the driver cannot run, identically for both
// halves.
//
// 501 rather than 500: the request was well formed and the deployment is
// misconfigured, which is a different thing from a fault. The body says nothing
// about the account, because this is reachable from the request half where the
// account's existence is not the caller's business.
func (s *Server) refuseRecoveryStage(w http.ResponseWriter, r *http.Request, stage flow.StageName, flowName string) {
	s.log.Error("the recovery flow requires a stage this engine does not drive",
		"stage", stage, "flow", flowName, "correlation_id", correlationID(r.Context()))
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"account recovery is unavailable: the configured recovery flow uses a step "+
			"this engine cannot yet run")
}

// recoverCaptcha runs the captcha stage of a recovery flow: it verifies the
// challenge and, on failure, re-renders the form with a fresh one and reports
// false so the caller stops.
//
// The failure is recorded so adaptive mode escalates, exactly as at sign-in and
// sign-up. Without it a stream of blank submissions holds the counter still,
// which is the shape that makes an adaptive challenge decorative.
//
// The re-rendered form carries no identifier back. Every other form in this
// codebase repopulates what was typed, and this one must not: the value is an
// account identifier, and echoing it into a page served to whoever submitted it
// is the one place that convenience helps an enumerator more than a user.
func (s *Server) recoverCaptcha(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	if cerr := s.captcha.Verify(ctx, captchaResponse(r), r.RemoteAddr); cerr != nil {
		s.captcha.RecordFailure(ctx, r.RemoteAddr)
		s.log.Info("captcha refused at recovery", "err", cerr,
			"correlation_id", correlationID(ctx))
		csrf, _ := s.csrfToken(w, r)
		// captchaWidget, not captchaFields: reaching here means the FLOW put a
		// captcha stage in the plan, so the challenge must appear on the form
		// whatever the adaptive counter thinks. See captchaWidget for the dead end
		// this avoids.
		s.renderPage(w, r, "recover", s.captchaWidget(map[string]any{
			"Error": s.tr(r).T("error.captcha.incomplete"),
			"CSRF":  csrf, "CSRFField": csrfFormField,
		}))
		return false
	}
	return true
}

// planHasStage reports whether a stage appears in a plan.
func planHasStage(plan []flow.StageName, want flow.StageName) bool {
	for _, stage := range plan {
		if stage == want {
			return true
		}
	}
	return false
}

// recoveryDenied reports whether the operator's flow refuses recovery outright.
//
// A flow whose plan reaches `deny` has closed the journey. Answering it here,
// rather than at the point each half would otherwise act, keeps the two halves
// agreeing about a decision that is not about the account at all.
func recoveryDenied(plan []flow.StageName) bool {
	for _, stage := range plan {
		switch stage {
		case flow.StageDeny:
			return true
		case flow.StageDone, flow.StageSession:
			// A terminal was reached first, so the deny belongs to a branch this
			// walk did not take.
			return false
		}
	}
	return false
}
