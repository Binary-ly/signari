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
)

// AMR values (RFC 8176). Only the ones this server can honestly assert.
const (
	AMRPassword     = "pwd"
	AMROTP          = "otp"
	AMRHardwareKey  = "hwk"
	AMRUserPresence = "user"
	AMRPIN          = "pin"
	AMRMFA          = "mfa"
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
		case AMROTP, AMRHardwareKey:
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

// satisfies reports whether an achieved context meets a requested one.
func satisfies(achieved, requested string) bool {
	switch requested {
	case ACRMultiFactor, ACRPapeMultiFactor:
		return achieved == ACRMultiFactor
	case ACRSingleFactor:
		// Multi-factor satisfies a single-factor request. Refusing would force a
		// pointless re-authentication on the stronger session.
		return achieved == ACRSingleFactor || achieved == ACRMultiFactor
	default:
		// An acr we do not implement. Refuse rather than pretend: telling a
		// client its requirement was met when we do not know what it means is
		// the worst available answer.
		return false
	}
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

	if prompt == "login" || prompt == "select_account" {
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
	achieved := ACRFromAMR(sessionAMR)
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
		case ACRMultiFactor, ACRPapeMultiFactor:
			return "mfa"
		case ACRSingleFactor:
			return "password"
		}
	}
	return ""
}
