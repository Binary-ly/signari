package oauth

import (
	"strings"
	"time"
)

// Authentication context: what actually happened at sign-in, and whether it is
// enough for what a client is asking for now.
//
// This is the file that decides whether a bank's "step up before a transfer"
// request means anything. The failure it exists to prevent is subtle and common:
//
//	the session says "authenticated", the client asks for MFA, and nobody
//	rechecks HOW the user authenticated -- so a password-only session silently
//	satisfies a multi-factor requirement, forever.
//
// That is a real bypass, not a theoretical one. It happens because acr is
// treated as a property frozen at login rather than a question re-answered per
// authorization request.

// ACR values. Deliberately the two everyone actually uses, plus the PAPE URN
// that shows up in the wild from older relying parties.
const (
	// ACRSingleFactor is one factor -- a password, or a passkey used alone.
	ACRSingleFactor = "1"
	// ACRMultiFactor is two independent factors.
	ACRMultiFactor = "2"
	// ACRPapeMultiFactor is the OpenID PAPE URN. Accepted as a synonym for "2"
	// because several older libraries emit it and rejecting it would fail a
	// legitimate step-up request for a spelling difference.
	ACRPapeMultiFactor = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
	// ACRPhishingResistant is multi-factor that includes a WebAuthn assertion
	// (4.15): a passkey that verified its user, or a key after a password. The
	// assertion is bound to this server's origin, so a page that relays the
	// sign-in cannot obtain one. This engine's rung, not a registered value.
	ACRPhishingResistant = "3"
	// ACRPhishingResistantHardware is ACRPhishingResistant with a device-bound
	// key (amr `hwk`): one that is not synced, so it exists on one device only.
	ACRPhishingResistantHardware = "4"
)

// rung orders the values: higher satisfies lower. Zero is a value this engine
// does not implement.
func rung(acr string) int {
	switch acr {
	case ACRSingleFactor:
		return 1
	case ACRMultiFactor, ACRPapeMultiFactor:
		return 2
	case ACRPhishingResistant:
		return 3
	case ACRPhishingResistantHardware:
		return 4
	}
	return 0
}

// Assurance is the highest rung a session's factors reach. ACRFromAMR stops
// at "2", and is what a session records and an ID token carries unless the
// client asked for more, so a relying party that was told "2" for a passkey
// sign-in is told "2" still.
//
// The two upper rungs are read from `hwk` and `swk`, which only a WebAuthn
// assertion here produces: a hardware OTP token reports `otp`.
func Assurance(amr []string) string {
	if ACRFromAMR(amr) != ACRMultiFactor {
		return ACRSingleFactor
	}
	for _, m := range amr {
		if m == AMRHardwareKey {
			return ACRPhishingResistantHardware
		}
	}
	for _, m := range amr {
		if m == AMRSoftwareKey {
			return ACRPhishingResistant
		}
	}
	return ACRMultiFactor
}

// Meets reports whether a session's factors reach a floor ("1" to "4"). An
// empty floor is no floor; one this engine does not implement is not met.
func Meets(amr []string, floor string) bool {
	if floor == "" {
		return true
	}
	need := rung(floor)
	return need > 0 && rung(Assurance(amr)) >= need
}

// SatisfiedACR is the value an ID token reports for a request: the first of
// acrValues the session's factors satisfy, when that is a rung above what the
// session records, and "" otherwise, leaving the session's own.
func SatisfiedACR(amr []string, acrValues string) string {
	for _, want := range ParseACRValues(acrValues) {
		if satisfies(Assurance(amr), want) {
			if rung(want) > rung(ACRFromAMR(amr)) {
				return want
			}
			return ""
		}
	}
	return ""
}

// RequiredRung is what an authorization needs: the lowest of the requested
// values, since any one satisfies, and the client's floor, whichever is higher.
// Zero is nothing required.
func RequiredRung(acrValues, floor string) int {
	need := 0
	for _, want := range ParseACRValues(acrValues) {
		if r := rung(want); r > 0 && (need == 0 || r < need) {
			need = r
		}
	}
	if f := rung(floor); f > need {
		need = f
	}
	return need
}

// AMR values (RFC 8176). Only the ones this server can honestly assert.
const (
	AMRPassword     = "pwd"
	AMROTP          = "otp"
	AMRHardwareKey  = "hwk"
	AMRSoftwareKey  = "swk" // a synced passkey, not bound to one device
	AMRUserPresence = "user"
	AMRPIN          = "pin"
	AMRMFA          = "mfa"
	// AMRSMS is reported for a code delivered by text, and is deliberately not
	// AMROTP.
	//
	// RFC 8176 defines both, and the difference is the point. SIM swap defeats
	// this factor with no technical exploit at all -- somebody persuades a
	// mobile operator to move a number. Recording it as "otp" would make it
	// indistinguishable from an authenticator app in every token, every audit
	// record and every policy decision: documenting the weakness in prose and
	// then erasing it from the one field machines actually read.
	AMRSMS = "sms"
)

// ParseACRValues splits the space-separated acr_values parameter.
//
// Order is significant and preserved: OIDC Core defines it as most-preferred
// first, so a server offering a choice should honour the earliest it can satisfy.
func ParseACRValues(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}

// ACRFromAMR derives the authentication context from the factors ACTUALLY used.
//
// Derived, never stored and trusted. If acr were written at login and read back
// later, then anything that could set it once -- a bug, a migration, an importer
// bringing users from another IdP -- could assert multi-factor for a session
// that never had a second factor. Computing it from amr means the claim can only
// be as strong as the evidence.
func ACRFromAMR(amr []string) string {
	distinct := map[string]bool{}
	for _, m := range amr {
		switch m {
		case AMRPassword, AMRPIN:
			distinct["knowledge"] = true
		case AMROTP, AMRHardwareKey, AMRSMS:
			// SMS IS a possession factor -- it proves control of a phone number,
			// which is worth strictly more than a password alone. It counts
			// towards multi-factor here for that reason.
			//
			// What it must not do is satisfy a request for a phishing-resistant
			// or hardware-backed factor. That distinction lives in the policy
			// language, where a rule can name amr values directly, rather than
			// being collapsed away here.
			distinct["possession"] = true
		case AMRUserPresence:
			// Presence alone is not a factor. A passkey that reports `user`
			// without a hardware key or PIN proves someone touched a device, not
			// which someone.
		case AMRMFA:
			// An explicit assertion that multiple factors were used.
			distinct["knowledge"] = true
			distinct["possession"] = true
		}
	}
	if len(distinct) >= 2 {
		return ACRMultiFactor
	}
	return ACRSingleFactor
}

// IsMultiFactor reports whether a session's authentication methods add up to
// multi-factor authentication.
//
// The ONE predicate every decision uses -- the access policy, the AuthZEN PDP,
// the SAML authentication context, the session list. There were four, and they
// disagreed: the PDP counted `user` or `pin` alone as MFA, the access policy and
// SAML counted a single possession factor, and the session list called a
// password session multi-factor. So a passkey used without user verification
// passed an MFA requirement in three places and failed it in the fourth.
// TestThereIsOneMultiFactorPredicate fails the build if a fifth appears.
func IsMultiFactor(amr []string) bool { return ACRFromAMR(amr) == ACRMultiFactor }

// satisfies reports whether an achieved context meets a requested one: a
// higher rung meets a lower, since refusing would force a pointless
// re-authentication on the stronger session. An acr we do not implement is
// refused rather than pretended: telling a client its requirement was met
// when we do not know what it means is the worst available answer.
func satisfies(achieved, requested string) bool {
	want := rung(requested)
	return want > 0 && rung(achieved) >= want
}

// StepUpReason says why an existing session is not sufficient. Empty means it is.
type StepUpReason string

const (
	StepUpNone         StepUpReason = ""
	StepUpNeedStronger StepUpReason = "acr"
	StepUpTooOld       StepUpReason = "max_age"
	StepUpForced       StepUpReason = "prompt"
)

// SessionSufficient decides whether a live session may be reused for this
// authorization request, or whether the user must authenticate again.
//
// Three independent reasons to re-authenticate, all of which are ways a client
// says "I do not trust what you already have":
//
//   - acr_values asks for a context this session does not have.
//   - max_age says the authentication is too old. Note this is measured from
//     auth_time, NOT from session creation or last activity: a session kept
//     alive by ordinary browsing is not freshly authenticated, and treating it
//     as such defeats the entire parameter.
//   - prompt=login demands it unconditionally.
func SessionSufficient(sessionAMR []string, authTime time.Time, now time.Time,
	acrValues string, maxAge *int, prompt string) (StepUpReason, string) {

	// select_account arrives here only when the browser holds no account to
	// choose in the client's organisation: httpapi's picker answers it first,
	// and consumes it. With nothing to choose, a sign-in is the choice.
	if HasPrompt(prompt, PromptLogin) || HasPrompt(prompt, PromptSelectAccount) {
		return StepUpForced, "the client requested re-authentication"
	}

	if maxAge != nil {
		// max_age=0 means "authenticate now, whatever just happened". Honoured
		// literally, because a client sending it has a reason.
		if authTime.IsZero() || now.Sub(authTime) > time.Duration(*maxAge)*time.Second {
			return StepUpTooOld, "the existing authentication is older than max_age"
		}
	}

	requested := ParseACRValues(acrValues)
	if len(requested) == 0 {
		return StepUpNone, ""
	}

	// Derived from what actually happened, not from anything stored.
	achieved := Assurance(sessionAMR)
	for _, want := range requested {
		if satisfies(achieved, want) {
			return StepUpNone, ""
		}
	}
	return StepUpNeedStronger, "the session does not meet the requested acr_values"
}

// RequiredFactor maps an unsatisfied acr_values request to what the user must
// now do. Returning the requirement rather than a bare failure is what makes
// step-up a flow instead of an error.
func RequiredFactor(acrValues string) string {
	for _, want := range ParseACRValues(acrValues) {
		switch want {
		case ACRPhishingResistant, ACRPhishingResistantHardware:
			return "passkey"
		case ACRMultiFactor, ACRPapeMultiFactor:
			return "mfa"
		case ACRSingleFactor:
			return "password"
		}
	}
	return ""
}
