package uma

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Claims collection, UMA 2.0 §3.3.1, §3.3.2 and §3.3.6.
//
// # The two methods, and why only one of them is a protocol
//
// §1.2 names both: "The two methods available for UMA claims collection are
// claims pushing and interactive claims gathering."
//
// Claims PUSHING is a protocol: the client sends `claim_token` in a format it
// names, and this server verifies it. Interactive claims GATHERING is
// deliberately not one -- §3.3.3: "Interactive claims-gathering processes are
// outside the scope of this specification. The purpose of the interaction is for
// the authorization server to gather information for its own authorization
// assessment purposes."
//
// So the redirect in and the redirect out are specified to the letter and what
// happens between them is ours. What happens between them here is: the person
// signs in, and is shown what is being asked before anything is spent. See
// internal/httpapi/umaclaims.go.

// ClaimTokenFormatIDToken is the OIDC ID Token format.
//
// The identifier is the one §3.3.1's own example uses and is the only format
// this server accepts. It is a URL into the OIDC Core specification rather than
// a URN, which looks like a mistake and is not: that string is what deployed
// UMA clients send.
const ClaimTokenFormatIDToken = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"

// DecodeClaimToken returns the JWT carried by a `claim_token` parameter.
//
// # The encoding question
//
// §3.3.1: "It MUST be base64url encoded unless specified otherwise by the claim
// token format."
//
// The ID Token format specifies nothing about encoding, so read strictly the
// value is a base64url-encoded JWT. In practice clients send the raw compact
// serialisation, because a JWT already looks like something you do not encode
// again -- and an authorization server that accepts only one of the two spellings
// interoperates with half the field.
//
// Both are accepted, and they are DISTINGUISHABLE rather than guessed at: a
// compact JWS has exactly two dots, and base64url has no dot in its alphabet, so
// a value containing a dot cannot be a base64url encoding of anything. There is
// no input that is validly both, which is what makes accepting both safe --
// a permissive parser that tried one and fell back to the other on failure would
// be a different and worse thing.
func DecodeClaimToken(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("claim_token is empty")
	}
	if strings.Contains(v, ".") {
		return v, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return "", fmt.Errorf("claim_token contains no '.' so it is not a compact " +
			"JWT, and it does not decode as base64url either")
	}
	out := strings.TrimSpace(string(raw))
	if !strings.Contains(out, ".") {
		return "", fmt.Errorf("claim_token decoded from base64url but the result " +
			"is not a compact JWT")
	}
	return out, nil
}

// RequiredClaim is one element of §3.3.6's `required_claims`.
//
// Every member is OPTIONAL in the specification. They are populated here anyway,
// all of them, because the array exists to tell a client what to send and an
// entry naming nothing is an entry a client cannot act on.
type RequiredClaim struct {
	ClaimTokenFormat []string `json:"claim_token_format,omitempty"`
	ClaimType        string   `json:"claim_type,omitempty"`
	FriendlyName     string   `json:"friendly_name,omitempty"`
	Issuer           []string `json:"issuer,omitempty"`
	Name             string   `json:"name,omitempty"`
}

// SubjectClaim describes the one claim this server can act on.
//
// The requesting party's identity, as an ID token THIS server issued. That is
// the whole of what is accepted, and saying so precisely -- with the issuer
// named -- is the difference between a client that knows what to fetch and one
// that tries an assertion from somewhere else and is refused again.
//
// `claim_type` is the X.500 mail attribute's OID, which is what §3.3.6's own
// example uses for an email claim.
func SubjectClaim(issuer string) RequiredClaim {
	return RequiredClaim{
		ClaimTokenFormat: []string{ClaimTokenFormatIDToken},
		ClaimType:        "urn:oid:0.9.2342.19200300.100.1.3",
		FriendlyName:     "email",
		Issuer:           []string{issuer},
		Name:             "email",
	}
}

// NeedInfo is §3.3.6's need_info, 403.
//
//	"It MUST include a ticket parameter, and it MUST also include either the
//	required_claims parameter or the redirect_user parameter, or both, as hints
//	about the information it needs."
//
// Both are sent. A client with an end-user in front of it follows
// redirect_user; a headless one pushes the claim named in required_claims. The
// server cannot tell which kind of client it is talking to, and §3.3.6 itself
// notes that "if the requesting party is not an end-user, then no client action
// is possible on receiving the hint" -- so sending only the redirect would leave
// a whole class of client with nothing to do.
func NeedInfo(ticket, redirectUser string, required []RequiredClaim, desc string) *Error {
	return &Error{
		Code:           "need_info",
		Description:    desc,
		Status:         http.StatusForbidden,
		Ticket:         ticket,
		RedirectUser:   redirectUser,
		RequiredClaims: required,
	}
}

// Submitted is §3.3.6's request_submitted, 403.
//
//	"It MUST include a ticket parameter and MAY include an interval parameter."
//
// The ticket is a NEW one, per §3.3.6's "The value MUST NOT be the same as the
// one the client used to make its request" -- so each poll spends a ticket and
// receives the next. That reads like a contradiction of §3.3.1's single-use rule
// and is not: the ticket is still spent exactly once, and the chain of them is
// what makes polling possible without ever replaying one.
func Submitted(ticket string, intervalSeconds int, desc string) *Error {
	return &Error{
		Code:        "request_submitted",
		Description: desc,
		Status:      http.StatusForbidden,
		Ticket:      ticket,
		Interval:    intervalSeconds,
	}
}
