// Package ssf implements the Shared Signals Framework and CAEP events.
//
// # The argument
//
// An access token is valid until it expires. That is the whole security model of
// a bearer token, and it means a relying party keeps honouring one for its full
// lifetime after the session behind it was revoked, the password was changed, or
// the account was disabled. Short lifetimes narrow the window; they do not close
// it, and shortening them costs a token request per few minutes per user.
//
// Continuous Access Evaluation closes it by telling the relying party. When a
// session is revoked here, every receiver that has seen that subject learns
// within seconds, and can stop honouring what it holds.
//
// This project has made the same argument about logout from the beginning --
// that a logout nobody can prove happened is not a logout. CAEP is that argument
// applied continuously instead of once.
//
// # Security Event Tokens
//
// Events are SETs (RFC 8417): signed JWTs with a fixed shape. Signed, because a
// receiver acts on them -- an unsigned "this session is revoked" is a denial of
// service anybody can send, and an unsigned "this device is compliant" is worse.
package ssf

import (
	"fmt"
	"time"
)

// Event types. CAEP 1.0 defines these URIs; a receiver subscribes by naming
// them, so the exact strings matter.
const (
	EventSessionRevoked    = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCredentialChange  = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventAssuranceChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"

	// TypSET is the media type a SET carries (RFC 8417 §2.3). Checked by
	// receivers, and set here so a SET cannot be confused with an ID token by
	// anything that inspects `typ`.
	TypSET = "secevent+jwt"
)

// SupportedEvents is what this engine can actually emit.
//
// Advertised, and deliberately short. A receiver subscribing to an event we
// never send waits forever for a signal that will not come, and would have been
// better off knowing that when it subscribed.
func SupportedEvents() []string {
	return []string{EventSessionRevoked, EventCredentialChange}
}

// Subject identifies who an event is about.
//
// The "iss_sub" format: the issuer plus the subject identifier we gave that
// receiver. NOT an email address -- a receiver that matched on email would be
// vulnerable to the same account-confusion the federation code refuses, and the
// subject we issued is the only identifier both sides agree on.
type Subject struct {
	Format string `json:"format"`
	Issuer string `json:"iss"`
	Sub    string `json:"sub"`
}

// Event is one CAEP event.
type Event struct {
	Type string
	// Subject is who it is about.
	Subject Subject
	// EventTime is when the thing happened, which is NOT when the token was
	// minted -- a receiver replaying its queue after an outage needs to order
	// events by when they occurred.
	EventTime time.Time
	// ReasonAdmin is shown to an administrator; ReasonUser to the person.
	// Separate because the useful phrasing differs, and because the admin reason
	// may name internal detail the user should not see.
	ReasonAdmin string
	ReasonUser  string
	// InitiatingEntity: policy, user, admin, or system (CAEP §3.1).
	InitiatingEntity string
}

// setClaims is the wire shape of a Security Event Token.
type setClaims struct {
	Issuer   string   `json:"iss"`
	JTI      string   `json:"jti"`
	IssuedAt int64    `json:"iat"`
	Audience []string `json:"aud"`
	// Expiry is NOT RECOMMENDED in a SET (RFC 8417 §2.2): a security event has
	// already happened and is historical, so an expiry rarely makes sense. But
	// when a transmitter does send one, the claim means "the time after which
	// the JWT MUST NOT be accepted for processing", and honouring it is not
	// optional. Omitted by us when minting; enforced when receiving.
	Expiry int64                     `json:"exp,omitempty"`
	Events map[string]map[string]any `json:"events"`
}

// Signer mints SETs.
type Signer interface {
	SignJSON(claims any, typ string) (string, error)
}

// Mint builds a signed Security Event Token.
//
// The audience is the RECEIVER, not the subject's client id in general -- a SET
// with no audience, or the wrong one, is a token a receiver can forward to
// another receiver, which is how one relying party ends another's sessions.
func Mint(s Signer, issuer, audience, jti string, e Event, now time.Time) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("refusing to mint a security event token with no audience: " +
			"it could be forwarded to any other receiver")
	}
	if e.Subject.Sub == "" {
		return "", fmt.Errorf("refusing to mint an event with no subject")
	}

	payload := map[string]any{
		"subject": map[string]any{
			"format": e.Subject.Format,
			"iss":    e.Subject.Issuer,
			"sub":    e.Subject.Sub,
		},
		// Seconds, per CAEP. Milliseconds here is a common and silent
		// interoperability bug: a receiver reads a timestamp forty thousand years
		// in the future and either rejects the event or orders it last forever.
		"event_timestamp": e.EventTime.Unix(),
	}
	if e.InitiatingEntity != "" {
		payload["initiating_entity"] = e.InitiatingEntity
	}
	if e.ReasonAdmin != "" || e.ReasonUser != "" {
		reason := map[string]any{}
		if e.ReasonAdmin != "" {
			reason["en"] = e.ReasonAdmin
		}
		payload["reason_admin"] = reason
		if e.ReasonUser != "" {
			payload["reason_user"] = map[string]any{"en": e.ReasonUser}
		}
	}

	return s.SignJSON(setClaims{
		Issuer:   issuer,
		JTI:      jti,
		IssuedAt: now.Unix(),
		Audience: []string{audience},
		Events:   map[string]map[string]any{e.Type: payload},
	}, TypSET)
}

// Wants reports whether a stream asked for an event type.
//
// An empty subscription means NOTHING, not everything. A receiver that
// registered without naming event types has not asked to be told about
// credential changes, and sending them anyway discloses more about the user
// than that receiver was given.
func Wants(requested []string, eventType string) bool {
	for _, r := range requested {
		if r == eventType {
			return true
		}
	}
	return false
}
