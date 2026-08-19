package flow

import (
	"fmt"
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

	// StageCreateUser writes a new account. Enrolment only.
	StageCreateUser StageName = "create_user"

	// StageSession issues the session. Terminal.
	StageSession StageName = "session"

	// StageDeny refuses. Terminal, and the only other way a flow can end.
	StageDeny StageName = "deny"
)

// allStages is the inventory, in the order a reader should meet them.
var allStages = []StageName{
	StageIdentify, StageCaptcha,
	StagePassword, StagePasskey, StageMFA, StageEmailOTP, StageSMSOTP,
	StageCertificate, StageKerberos, StageFederated, StageDelegated,
	StageConsent, StagePrompt, StagePasswordChange, StageEnrolMFA, StageCreateUser,
	StageSession, StageDeny,
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

func (s StageName) terminal() bool { return s == StageSession || s == StageDeny }

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
	// CondClientRequiresMFA -- the client asked for multi-factor, through
	// acr_values or its registration.
	CondClientRequiresMFA Condition = "client_requires_mfa"
	// CondKerberosAvailable -- the request carried a Negotiate header.
	CondKerberosAvailable Condition = "kerberos_available"
	// CondMigrationPending -- the subject was imported and has not yet
	// authenticated against us.
	CondMigrationPending Condition = "migration_pending"
	// CondFederatedSource -- the request arrived by way of an upstream source.
	CondFederatedSource Condition = "federated_source"
)

var allConditions = []Condition{
	CondHasSecondFactor, CondHasPasskey, CondUserIsNew,
	CondPasswordChangeRequired, CondPromptsPending, CondConsentRequired,
	CondCaptchaRequired, CondRiskElevated,
	CondDeviceManaged, CondDeviceCompliant, CondNetworkTrusted,
	CondClientRequiresMFA, CondKerberosAvailable, CondMigrationPending,
	CondFederatedSource,
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

// State is the set of conditions that hold. A condition absent from the map is
// false, so a caller that cannot evaluate something gets the conservative
// answer rather than a panic.
type State map[string]bool

// holds evaluates a `when` against a state. An empty expression always holds.
func (st State) holds(expr string) bool {
	if expr == "" {
		return true
	}
	name := strings.TrimSpace(expr)
	if rest, ok := strings.CutPrefix(name, "not "); ok {
		return !st[strings.TrimSpace(rest)]
	}
	return st[name]
}
