package flow

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// StageName identifies a stage.
//
// A CLOSED set, checked at parse. The alternative -- letting a flow name any
// stage and resolving it at run time -- means a typo is a stage that silently
// does not exist, and the first person to find out is the one whose sign-in
// skipped it.
type StageName string

const (
	StageIdentify StageName = "identify"

	// StageCaptcha demands a challenge be solved. Proves nobody is who they say;
	// only that somebody is present.
	StageCaptcha StageName = "captcha"

	// StagePassword verifies a password. Proving.
	StagePassword StageName = "password"

	// StagePasskey runs a WebAuthn assertion. Proving, and phishing-resistant.
	StagePasskey StageName = "passkey"

	// StageMFA verifies an enrolled second factor: TOTP, a security key, Duo, a
	// recovery code. Proving on its own -- it is a proof of possession bound to
	// one account -- which is what makes `one_of: [passkey, password]` followed
	// by mfa a sound flow rather than a lucky one.
	StageMFA StageName = "mfa"

	// StageEmailOTP sends a code to a registered address. Proving: control of
	// the mailbox on file. Weak on its own, which is a policy question, not a
	// structural one.
	StageEmailOTP StageName = "email_otp"

	// StageSMSOTP sends a code to a registered number. Proving, and the weakest
	// thing in this list; NIST SP 800-63B has restricted it for years.
	StageSMSOTP StageName = "sms_otp"

	// StageCertificate authenticates with a client certificate (mTLS, EAP-TLS).
	// Proving.
	StageCertificate StageName = "certificate"

	// StageKerberos authenticates with a Kerberos ticket. Proving.
	StageKerberos StageName = "kerberos"

	// StageFederated hands off to an upstream source (SAML, OIDC, social) and
	// consumes the assertion. Proving -- the upstream did the proving.
	StageFederated StageName = "federated"

	// StageDelegated verifies the credential against the identity provider being
	// migrated away from. Proving: it is a password check, just not ours.
	StageDelegated StageName = "delegated"

	// StageConsent asks the person to approve what a client is requesting.
	StageConsent StageName = "consent"

	// StagePrompt asks a question -- terms, a missing field, a notice.
	StagePrompt StageName = "prompt"

	// StagePasswordChange forces a new password before continuing.
	//
	// NOT proving, though it takes a password: it sets a credential rather than
	// checking one. A flow that reached here without proving anything would be
	// letting a stranger choose somebody's new password.
	StagePasswordChange StageName = "password_change"

	// StageEnrolMFA enrols a second factor. Not proving: enrolling a factor
	// proves you hold the factor you just created, which is nothing.
	StageEnrolMFA StageName = "enrol_mfa"

	// StageVerifyEmail holds a sign-in until a code sent to the account's
	// address comes back, for an address self-sign-up has not yet seen proved.
	// Not proving who is signing in -- they proved that already -- but what
	// they claimed: that the address is theirs.
	StageVerifyEmail StageName = "verify_email"

	// StageCreateUser writes a new account. Enrolment only.
	StageCreateUser StageName = "create_user"

	// StageSession issues the session. Terminal.
	StageSession StageName = "session"

	// StageDeny refuses. Terminal.
	StageDeny StageName = "deny"

	// StageDone ends a flow that succeeded without issuing a session.
	//
	// Distinct from deny, and the distinction is not pedantry: an enrolment flow
	// may not reach a session (safety.go), so without this its successful ending
	// would have to be spelled `deny` -- a file that says the opposite of what
	// happened, in the one place an operator looks to find out what happened.
	StageDone StageName = "done"
)

// allStages is the inventory, in the order a reader should meet them.
var allStages = []StageName{
	StageIdentify, StageCaptcha,
	StagePassword, StagePasskey, StageMFA, StageEmailOTP, StageSMSOTP,
	StageCertificate, StageKerberos, StageFederated, StageDelegated,
	StageConsent, StagePrompt, StagePasswordChange, StageEnrolMFA, StageVerifyEmail, StageCreateUser,
	StageSession, StageDeny, StageDone,
}

// provingStages establish an authenticated subject.
//
// Membership here is the load-bearing judgement in this package: safety.go
// refuses any authentication flow that can reach a session without passing
// through one of these. Adding a stage to this map is therefore a security
// change, whatever else it looks like.
//
// The test for membership is: does passing this stage require the person to
// demonstrate possession of something bound to the account, that they could not
// demonstrate by knowing only public facts about it? identify fails that test.
// captcha fails it. enrol_mfa fails it -- it creates the secret it then checks.
var provingStages = map[StageName]bool{
	StagePassword:    true,
	StagePasskey:     true,
	StageMFA:         true,
	StageEmailOTP:    true,
	StageSMSOTP:      true,
	StageCertificate: true,
	StageKerberos:    true,
	StageFederated:   true,
	StageDelegated:   true,
}

// recoveryProving is the narrower set that counts in a RECOVERY flow.
//
// A recovery flow exists because a factor is lost, and it must not accept the
// class of factor it is replacing -- "reset your password by entering your
// password" is not a recovery flow, and "reset your password with the second
// factor that was on the phone you lost" is a support ticket rather than a
// recovery. What remains is possession of a channel the account registered out
// of band, or a credential held somewhere else entirely.
var recoveryProving = map[StageName]bool{
	StageEmailOTP:    true,
	StageSMSOTP:      true,
	StageCertificate: true,
	StagePasskey:     true,
	StageFederated:   true,
	StageKerberos:    true,
}

func (s StageName) known() bool {
	for _, n := range allStages {
		if n == s {
			return true
		}
	}
	return false
}

func (s StageName) terminal() bool {
	return s == StageSession || s == StageDeny || s == StageDone
}

// proves reports whether this stage establishes a subject for a given flow.
func (s StageName) proves(d Designation) bool {
	if d == Recovery {
		return recoveryProving[s]
	}
	return provingStages[s]
}

func knownStages() string {
	parts := make([]string, len(allStages))
	for i, n := range allStages {
		parts[i] = string(n)
	}
	return strings.Join(parts, ", ")
}

// Condition is a named fact about the request, the subject or the client.
//
// Also a closed set, for the same reason as StageName and one more: these are
// the only things a flow can branch on, so the list is a complete account of
// what the sequencer can see. A flow language with arbitrary expressions cannot
// make that statement, and cannot be analysed the way safety.go analyses this
// one.
type Condition string

const (
	// CondHasSecondFactor -- the subject has an enrolled second factor.
	CondHasSecondFactor Condition = "user_has_second_factor"
	// CondHasPasskey -- the subject has at least one WebAuthn credential.
	CondHasPasskey Condition = "user_has_passkey"
	// CondUserIsNew -- no account matched the identifier.
	CondUserIsNew Condition = "user_is_new"
	// CondPasswordChangeRequired -- the credential is flagged: expired, breached,
	// or set by an administrator.
	CondPasswordChangeRequired Condition = "password_change_required"
	// CondPromptsPending -- an unanswered prompt applies to this subject.
	CondPromptsPending Condition = "prompts_pending"
	// CondConsentRequired -- the client is asking for scopes not yet granted.
	CondConsentRequired Condition = "consent_required"
	// CondCaptchaRequired -- the adaptive counter has escalated for this address.
	CondCaptchaRequired Condition = "captcha_required"
	// CondRiskElevated -- a risk signal fired: impossible travel, a new country,
	// a known-bad address.
	CondRiskElevated Condition = "risk_elevated"
	// CondDeviceManaged -- the request carries evidence of a managed device.
	CondDeviceManaged Condition = "device_managed"
	// CondDeviceCompliant -- managed AND reported healthy.
	CondDeviceCompliant Condition = "device_compliant"
	// CondNetworkTrusted -- the request came from a network the operator named.
	CondNetworkTrusted Condition = "network_trusted"
	// CondClientRequiresMFA -- the authorization request asked for multi-factor
	// through acr_values. Not its registration: nothing on a client stores it.
	CondClientRequiresMFA Condition = "client_requires_mfa"
	// CondKerberosAvailable -- the request carried a Negotiate header.
	CondKerberosAvailable Condition = "kerberos_available"
	// CondMigrationPending -- the subject was imported and has not yet
	// authenticated against us.
	CondMigrationPending Condition = "migration_pending"
	// CondFederatedSource -- the request arrived by way of an upstream source.
	CondFederatedSource Condition = "federated_source"
	// CondEmailVerificationPending -- the subject's address is still to be
	// proved: self-sign-up made the account under a rule that requires it, and
	// no code has come back.
	CondEmailVerificationPending Condition = "email_verification_pending"

	// The proved_by family says which proof the person presented to reach this
	// walk (2.49). A sign-in's proving stage must be the one proved: a
	// `passkey, session` flow refuses a password, and a flow that admits
	// several ways in says which with these, in a one_of whose branches are
	// all proving stages.
	CondProvedByPassword  Condition = "proved_by_password"
	CondProvedByPasskey   Condition = "proved_by_passkey"
	CondProvedByKerberos  Condition = "proved_by_kerberos"
	CondProvedByFederated Condition = "proved_by_federated"
)

var allConditions = []Condition{
	CondHasSecondFactor, CondHasPasskey, CondUserIsNew,
	CondPasswordChangeRequired, CondPromptsPending, CondConsentRequired,
	CondCaptchaRequired, CondRiskElevated,
	CondDeviceManaged, CondDeviceCompliant, CondNetworkTrusted,
	CondClientRequiresMFA, CondKerberosAvailable, CondMigrationPending,
	CondFederatedSource, CondEmailVerificationPending,
	CondProvedByPassword, CondProvedByPasskey, CondProvedByKerberos, CondProvedByFederated,
}

// answered is which conditions each journey this engine drives can evaluate.
//
// The language names fifteen and the sign-in path used to answer four. The rest
// read false every time, so `{stage: deny, when: risk_elevated}` parsed, passed
// the file's own tests (which set the condition true) and never refused
// anybody: a control looked at once and trusted thereafter. A driven flow that
// branches on a condition outside its journey's set is refused at parse, by
// name, and so by `flow test`, `flow apply` and the engine's load alike.
//
// Widen a set only in step with an evaluator. internal/httpapi's
// TestEveryConditionAFlowCanUseIsAnswered compares these with the evaluators
// in both directions.
//
// captcha_required is absent from the sign-in set on purpose: a sign-in
// decides the challenge at the form, before the flow is walked, so the walk
// reads it false. It may guard the captcha stage there (checkAnswered), which
// is the one place false is the truth.
var answered = map[Designation][]Condition{
	Authentication: {
		CondHasSecondFactor, CondHasPasskey, CondPasswordChangeRequired,
		CondPromptsPending, CondClientRequiresMFA, CondRiskElevated, CondEmailVerificationPending,
		CondProvedByPassword, CondProvedByPasskey, CondProvedByKerberos, CondProvedByFederated,
	},
	// No account exists yet, so nothing is pending for it: false is the
	// answer, not the absence of one.
	Enrolment: {CondCaptchaRequired, CondPromptsPending},
	Recovery:  {CondCaptchaRequired},
	// Which way the person signed in to reach the page, from the session.
	Unenrolment: {CondProvedByPassword, CondProvedByPasskey, CondProvedByKerberos, CondProvedByFederated},
}

// drivable is which stages each journey this engine drives can run.
//
// A stage outside its journey's set did nothing anyone could see coming: a
// sign-in walked past it, so `password, kerberos, session` asked for a password
// and nothing else, and an enrolment or recovery stopped at it with a 501 the
// first time somebody tried. A driven flow naming one is refused at parse, by
// name, like a condition no journey evaluates.
//
// The sign-in set has two kinds. The walker acts on mfa, enrol_mfa, prompt,
// password_change, verify_email and the terminals. identify, captcha, password, passkey,
// kerberos, federated and consent are settled before the walk, by the route
// that reached it -- the sign-in form, the passkey ceremony, the Negotiate
// exchange, a provider's callback -- and the walker requires a proving one
// among them to be the proof that route presented (2.49). The stages refused
// there wait for a driver: a source pinned per flow (delegated, certificate),
// a code as the first factor (email_otp, sms_otp).
//
// Widen a set only in step with a driver; internal/httpapi's
// TestEveryStageAFlowCanUseIsDriven reads the drivers and compares.
var drivable = map[Designation][]StageName{
	Authentication: {
		StageMFA, StagePrompt, StagePasswordChange, StageSession, StageDeny, StageDone,
		StageIdentify, StageCaptcha, StagePassword, StagePasskey, StageKerberos, StageFederated,
		StageConsent, StageEnrolMFA, StageVerifyEmail,
	},
	Enrolment: {StageCaptcha, StagePrompt, StageCreateUser, StageDeny, StageDone},
	Recovery: {
		StageCaptcha, StageIdentify, StageEmailOTP, StageMFA, StagePasswordChange,
		StageDeny, StageDone, StageSession,
	},
	// The proving stages are settled by the recent sign-in the page requires,
	// each only by its own proof, as at sign-in; done deletes the account.
	Unenrolment: {StagePassword, StagePasskey, StageKerberos, StageFederated, StageDeny, StageDone},
}

// signInProofs are the proving stages a sign-in settles from the route that
// reached it, each with the condition saying that route was taken. A sign-in
// presents exactly one of them (2.49).
var signInProofs = map[StageName]Condition{
	StagePassword:  CondProvedByPassword,
	StagePasskey:   CondProvedByPasskey,
	StageKerberos:  CondProvedByKerberos,
	StageFederated: CondProvedByFederated,
}

// ProofCondition is the proved_by condition for a proving stage a sign-in
// settles, and whether stage is one.
func ProofCondition(stage StageName) (Condition, bool) {
	c, ok := signInProofs[stage]
	return c, ok
}

// checkOneProof refuses an authentication flow with a journey asking for two
// of the proofs a sign-in settles. Somebody arrives by password, passkey,
// Kerberos or a provider, never by two, so that journey could only refuse
// them; before 2.49 the walker passed both and it was a sign-in by whichever
// proof was presented, whatever the file said.
//
// Enumerated here rather than through Paths, which keeps one assignment per
// distinct journey and could keep an impossible one -- two proved_by
// conditions true at once -- in place of a possible one.
func (fl *Flow) checkOneProof() error {
	if fl.On != Authentication {
		return nil
	}
	conds := fl.Conditions()
	if len(conds) > maxEnumeratedConditions {
		return nil // Paths says so wherever the journeys are asked for
	}
	isProvedBy := map[string]bool{}
	for _, c := range signInProofs {
		isProvedBy[string(c)] = true
	}
	for mask := 0; mask < 1<<len(conds); mask++ {
		st, provedBy := State{}, 0
		for i, c := range conds {
			st[c] = mask&(1<<i) != 0
			if st[c] && isProvedBy[c] {
				provedBy++
			}
		}
		if provedBy > 1 {
			continue
		}
		var asked []StageName
		for _, s := range fl.Plan(st) {
			if _, ok := signInProofs[s]; ok && !slices.Contains(asked, s) {
				asked = append(asked, s)
			}
		}
		if len(asked) > 1 {
			return fmt.Errorf("a journey through this flow asks for %s and %s, but a sign-in presents "+
				"one of them: somebody arrives by password, passkey, Kerberos or a provider, never "+
				"by two, so that journey could only refuse them. Offer them as alternatives with "+
				"one_of, or ask for a second factor with mfa", asked[0], asked[1])
		}
	}
	return nil
}

// AdmitsProof reports whether an authentication flow signs in somebody who
// arrived by stage's proof: some journey with that route's proved_by true and
// no other, ending in a session, asks for no other sign-in proof. doctor uses
// it to say when an applied flow refuses a way in the organisation uses.
// A flow with too many conditions to enumerate is taken to admit it, so the
// answer only ever warns about what is certain.
func (fl *Flow) AdmitsProof(stage StageName) bool {
	want, ok := signInProofs[stage]
	if !ok || fl.On != Authentication {
		return false
	}
	conds := fl.Conditions()
	if len(conds) > maxEnumeratedConditions {
		return true
	}
	other := map[string]bool{}
	for _, c := range signInProofs {
		if c != want {
			other[string(c)] = true
		}
	}
	for mask := 0; mask < 1<<len(conds); mask++ {
		st, impossible := State{string(want): true}, false
		for i, c := range conds {
			if c == string(want) {
				continue
			}
			st[c] = mask&(1<<i) != 0
			impossible = impossible || (st[c] && other[c])
		}
		if impossible {
			continue
		}
		plan := fl.Plan(st)
		if len(plan) == 0 || plan[len(plan)-1] != StageSession {
			continue
		}
		admitted := true
		for _, s := range plan {
			if _, proof := signInProofs[s]; proof && s != stage {
				admitted = false
			}
		}
		if admitted {
			return true
		}
	}
	return false
}

// Drivable lists the stages a journey of designation d runs.
func Drivable(d Designation) []StageName {
	return append([]StageName(nil), drivable[d]...)
}

// checkDriven refuses a stage the journey a flow is for cannot run. Undriven
// designations are exempt, as for conditions.
func (fl *Flow) checkDriven() error {
	if !fl.On.Driven() {
		return nil
	}
	ok := map[StageName]bool{}
	names := make([]string, 0, len(drivable[fl.On]))
	for _, s := range drivable[fl.On] {
		ok[s] = true
		names = append(names, string(s))
	}
	sort.Strings(names)
	for i, st := range fl.Stages {
		for _, name := range st.stageNames() {
			if !ok[name] {
				return fmt.Errorf("step %d is %s, which this engine does not run in a flow "+
					"`on: %s` yet, so the journey could not do what this file says. Remove "+
					"it; what `on: %s` runs: %s", i+1, name, fl.On, fl.On, strings.Join(names, ", "))
			}
		}
	}
	return nil
}

// Answered lists the conditions a journey of designation d evaluates.
func Answered(d Designation) []Condition {
	return append([]Condition(nil), answered[d]...)
}

// conditionName is a `when:` expression without its `not`.
func conditionName(expr string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expr), "not "))
}

// checkAnswered refuses a condition the journey a flow is for cannot evaluate.
// An undriven designation is exempt: nothing walks it, and flow test and flow
// apply already say so about the whole flow.
func checkAnswered(on Designation, stage StageName, expr string) error {
	if expr == "" || !on.Driven() {
		return nil
	}
	name := conditionName(expr)
	if on == Authentication && Condition(name) == CondCaptchaRequired {
		if stage == StageCaptcha {
			return nil
		}
		return fmt.Errorf("`when: %s` guards %s, but a sign-in settles the captcha at the "+
			"form before this flow is walked, so here it always reads false. In an "+
			"authentication flow it may guard only the captcha stage", expr, stage)
	}
	for _, c := range answered[on] {
		if string(c) == name {
			return nil
		}
	}
	names := make([]string, 0, len(answered[on]))
	for _, c := range answered[on] {
		names = append(names, string(c))
	}
	sort.Strings(names)
	return fmt.Errorf("`when: %s`: a flow `on: %s` cannot evaluate %s yet, so it would "+
		"always read false and %s would never run (or, negated, always run). Remove it; "+
		"what `on: %s` evaluates: %s", expr, on, name, stage, on, strings.Join(names, ", "))
}

func isCondition(s string) bool {
	for _, c := range allConditions {
		if string(c) == s {
			return true
		}
	}
	return false
}

func knownConditions() string {
	parts := make([]string, len(allConditions))
	for i, c := range allConditions {
		parts[i] = string(c)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// checkCondition validates a `when:` expression.
//
// The grammar is one condition, optionally negated. Deliberately not an
// expression language: `and`/`or` would make the reachability analysis in
// safety.go a satisfiability problem, and the honest options at that point are
// to solve it or to stop claiming the guarantee. A flow needing two facts writes
// two steps, which also reads better.
func checkCondition(expr string) error {
	if expr == "" {
		return nil
	}
	name := strings.TrimSpace(expr)
	if rest, ok := strings.CutPrefix(name, "not "); ok {
		name = strings.TrimSpace(rest)
		if name == "" {
			return fmt.Errorf("`when: not` negates nothing")
		}
	}
	if strings.ContainsAny(name, " \t") {
		return fmt.Errorf("`when: %s` is not a single condition. A `when` is one condition, "+
			"optionally negated with `not`; two facts are two steps", expr)
	}
	if !isCondition(name) {
		return fmt.Errorf("%q is not a condition (%s)", name, knownConditions())
	}
	return nil
}

// Evaluator answers whether a named condition holds.
//
// An interface rather than a map, because the server answers these by querying
// the database and the walker only ever asks about conditions on the path it is
// actually taking. Handing it a fully-populated map means evaluating every
// condition the file mentions, including the ones guarding stages the journey
// never reaches -- which on the sign-in path is measured in round trips per
// login.
//
// State is the map implementation, used by the file's own test cases and by
// Plan, where a fixed situation is exactly what is being described.
type Evaluator interface {
	// Holds reports whether the named condition is true. A condition the
	// implementation cannot answer must return false: every condition in this
	// language guards an ADDITIONAL stage, so false never invents a stage that
	// did not run, and safety.go never counts a conditional stage as proving
	// anything.
	Holds(name string) bool
}

// State is the set of conditions that hold. A condition absent from the map is
// false, so a caller that cannot evaluate something gets the conservative
// answer rather than a panic.
type State map[string]bool

// Holds makes a State an Evaluator.
func (st State) Holds(name string) bool { return st[name] }

// holds evaluates a `when` against an evaluator. An empty expression always
// holds, which is what makes an unconditional stage cost no evaluation at all.
func holds(ev Evaluator, expr string) bool {
	if expr == "" {
		return true
	}
	name := strings.TrimSpace(expr)
	if rest, ok := strings.CutPrefix(name, "not "); ok {
		return !ev.Holds(strings.TrimSpace(rest))
	}
	return ev.Holds(name)
}
