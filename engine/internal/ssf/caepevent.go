package ssf

import "time"

// RevocationEvent builds the CAEP session-revoked event for a subject.
//
// Shared by both delivery paths -- push (the outbox worker) and poll (the poll
// handler) -- so a receiver gets the same event whichever way it reaches them.
// Before this existed the push worker built the event inline; poll would have
// been a second, drifting copy of the same shape.
//
// eventTime is when the session was actually revoked, which is NOT when the SET
// is minted. For push the two are moments apart; for poll they can be hours
// apart, so the caller passes the revoke time (the queue row's timestamp) rather
// than "now" -- a receiver orders events by when they happened.
func RevocationEvent(issuer, subject, reason string, eventTime time.Time) Event {
	return Event{
		Type:             EventSessionRevoked,
		Subject:          Subject{Format: "iss_sub", Issuer: issuer, Sub: subject},
		EventTime:        eventTime,
		ReasonAdmin:      "The session was revoked: " + reason,
		ReasonUser:       "You were signed out.",
		InitiatingEntity: InitiatingEntityFor(reason),
	}
}

// InitiatingEntityFor maps a session-termination reason to the CAEP initiating
// entity vocabulary (CAEP §3.1: policy, user, admin, or system).
//
// Reported honestly: a receiver may treat an administrator revoking a session
// differently from a user signing themselves out, and collapsing them into
// "system" throws away the distinction it would act on.
func InitiatingEntityFor(reason string) string {
	switch reason {
	case "logout", "user_revoke":
		// The user ended it -- signed out, or revoked one of their own sessions
		// from the account console.
		return "user"
	case "admin_revoke", "user_deactivated", "user_deleted":
		return "admin"
	case "password_change", "mfa_reset":
		return "user"
	case "reuse_detected":
		return "policy"
	default:
		return "system"
	}
}
