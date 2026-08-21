package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Client-Initiated Backchannel Authentication.
//
// OpenID Connect Client-Initiated Backchannel Authentication Flow -- Core 1.0,
// Final, 1 September 2021.
//
// The client asks us to authenticate somebody who is not in front of it, and
// polls until they approve on their own device. A call-centre agent confirming a
// transaction on the customer's phone; a point-of-sale terminal; a bank asking
// "did you just try to move £4,000".
//
// # The shape, and what it shares with the device flow
//
//	POST /oauth2/backchannel   (client authenticates)  -> auth_req_id
//	POST /oauth2/token          grant_type=urn:openid:params:grant-type:ciba
//	                            auth_req_id=...        -> authorization_pending
//	                                                   -> ... -> tokens
//
// The polling half is RFC 8628's, word for word -- §11 uses the same four error
// codes with the same meanings, including "the interval MUST be increased by at
// least 5 seconds". So it is not reimplemented here: the storage layer stores a
// CIBA request in the same table and polls it with the same function. See
// migration 0088 for why that is a correctness argument rather than a shortcut.
//
// What is genuinely different is the START of the flow, and that is what this
// file is.

// GrantTypeCIBA is CIBA §7.4's grant type.
const GrantTypeCIBA = "urn:openid:params:grant-type:ciba"

// GrantTypeUMATicket is UMA 2.0 §3.3.1's grant type.
//
// Declared beside CIBA's rather than in internal/uma, for the reason given above
// GrantTypePreAuthorizedCode: the allow-list decides which grants the token
// endpoint will consider at all, and that question should not require importing
// the package that implements each one.
const GrantTypeUMATicket = "urn:ietf:params:oauth:grant-type:uma-ticket"

// CIBADefaultExpiry is how long an auth_req_id lives when the client does not
// ask for something shorter.
//
// Long enough to reach somebody's phone, notice it, and act; short enough that
// an unapproved request is not a standing invitation. Somebody who does not
// respond within this has not seen the prompt, and a fresh one is better than a
// stale approval.
const CIBADefaultExpiry = 5 * time.Minute

// CIBAMaxExpiry bounds `requested_expiry`. §7.1 lets the client ask; it does not
// oblige us to agree, and an hour-long pending authorization is an hour in which
// a prompt somebody has forgotten about can still be approved.
const CIBAMaxExpiry = 15 * time.Minute

// CIBAMinPollInterval is what we tell clients, and enforce.
//
// §7.3: "interval -- OPTIONAL. A JSON number with a positive integer value
// indicating the minimum amount of time in seconds that the Client MUST wait
// between polling requests to the token endpoint. If no value is provided, the
// Client MUST use 5 as the default value."
//
// Sent explicitly rather than relying on that default, because a client that
// gets no value and misreads the specification polls as fast as it likes, and
// the first anybody knows is the load.
const CIBAMinPollInterval = 5

// maxBindingMessage bounds §7.1's binding_message.
//
// The specification gives no length, only that it "SHOULD be relatively short
// and use a limited set of plain text characters" because it has to render on a
// phone's notification. A limit is still needed: this string is displayed to a
// person as part of an approval decision, and an unbounded one is a way to push
// the actual question off the screen.
//
// Counted in CHARACTERS, not bytes. The constraint is how much room the message
// takes on a notification, and a byte limit makes that depend on the script --
// 140 bytes is 140 Latin characters but around 46 Arabic or Japanese ones, so
// the same sentence would fit in English and be refused in translation.
const maxBindingMessage = 140

// CIBARequest is a parsed backchannel authentication request.
type CIBARequest struct {
	ClientID string
	Scope    string
	// Hint is the single user hint, and HintKind says which parameter carried
	// it. Which one it was matters: they are resolved differently and trusted
	// differently.
	Hint     string
	HintKind string
	// BindingMessage is shown on both devices. May be empty.
	BindingMessage  string
	ACRValues       []string
	RequestedExpiry time.Duration
	// ClientNotificationToken belongs to ping and push mode, which we do not
	// implement. Parsed only so its presence can be refused rather than ignored.
	ClientNotificationToken string
	UserCode                string
}

// The three hint parameters, §7.1. Exactly one must be present.
const (
	HintLogin      = "login_hint"
	HintLoginToken = "login_hint_token"
	HintIDToken    = "id_token_hint"
)

// CIBAError is a backchannel authentication endpoint failure.
//
// Carries its own status because §13 assigns different ones: 400 for most, 401
// for invalid_client, 403 for access_denied. Returning 400 for all of them would
// be a client behaving correctly on a response it could not distinguish.
type CIBAError struct {
	Code        string
	Description string
	Status      int
}

func (e *CIBAError) Error() string { return e.Code + ": " + e.Description }

func cibaErr(status int, code, desc string) *CIBAError {
	return &CIBAError{Code: code, Description: desc, Status: status}
}

// ParseCIBARequest validates a backchannel authentication request.
//
// Everything §7.1 requires, and nothing that depends on knowing who the subject
// is -- resolving the hint needs a database and belongs to the caller.
func ParseCIBARequest(form url.Values, clientID, deliveryMode string) (*CIBARequest, *CIBAError) {
	// Duplicates first, as everywhere else. RFC 6749 §3.1 forbids a repeated
	// parameter, and §13 names it: invalid_request covers a request that
	// "includes any of the parameters more than once".
	for name, values := range form {
		if len(values) > 1 {
			return nil, cibaErr(400, "invalid_request",
				fmt.Sprintf("the parameter %q appears %d times; each may appear at most once",
					name, len(values)))
		}
	}

	// §7.1.1 signed authentication requests are not supported, and a `request`
	// parameter is REFUSED rather than ignored.
	//
	// §7.2 says "OpenID Providers MUST ignore unrecognized request parameters",
	// and `request` is not unrecognised -- it is recognised by the specification
	// and unimplemented here. The distinction decides the behaviour.
	//
	// Ignoring it fails two ways. A client that sends only `request` (which is
	// what §7.1.1 describes, with the parameters inside the JWT) reaches the hint
	// check below and is told "exactly one of login_hint, login_hint_token or
	// id_token_hint is required" -- a true statement that sends an integrator to
	// look at hints they did put in, inside the object we discarded.
	//
	// Worse is the client that sends BOTH, for compatibility with servers that
	// take either. Reading the form and dropping the JWT means the binding
	// message, scope and hint that were SIGNED are replaced by the plaintext
	// copies beside them, and the signature protects nothing. Anything that can
	// rewrite the form -- a proxy, a compromised SDK -- changes the transaction
	// the user is asked to approve.
	//
	// The metadata already says this: §4 makes
	// backchannel_authentication_request_signing_alg_values_supported OPTIONAL
	// and "If omitted, signed authentication requests are not supported by the
	// OP", and we omit it. This makes the endpoint agree with the document.
	for _, p := range []string{"request", "request_uri"} {
		if strings.TrimSpace(form.Get(p)) != "" {
			return nil, cibaErr(400, "invalid_request",
				"this server does not support signed backchannel authentication "+
					"requests, and refuses "+p+" rather than ignoring it: the "+
					"parameters inside a signed request object would otherwise be "+
					"silently replaced by the unsigned copies in this form. See "+
					"backchannel_authentication_request_signing_alg_values_supported "+
					"in the discovery document, which is absent")
		}
	}

	req := &CIBARequest{
		ClientID:                clientID,
		Scope:                   strings.TrimSpace(form.Get("scope")),
		BindingMessage:          strings.TrimSpace(form.Get("binding_message")),
		ClientNotificationToken: form.Get("client_notification_token"),
		UserCode:                form.Get("user_code"),
	}

	// §7.1: "scope -- REQUIRED. The scope of the access request ... CIBA
	// authentication requests MUST contain the openid scope value."
	if req.Scope == "" {
		return nil, cibaErr(400, "invalid_request", "scope is required")
	}
	if !containsScopeValue(req.Scope, "openid") {
		return nil, cibaErr(400, "invalid_scope",
			"a backchannel authentication request must include the openid scope")
	}

	// §7.1: exactly one hint. "It is REQUIRED that the Client provides one (and
	// only one) of the hints specified above in the authentication request".
	//
	// Both halves matter. None means we do not know who to ask; more than one
	// means two answers to that question, and choosing between them here would
	// be inventing a precedence the specification does not define.
	var present []string
	for _, k := range []string{HintLogin, HintLoginToken, HintIDToken} {
		if strings.TrimSpace(form.Get(k)) != "" {
			present = append(present, k)
		}
	}
	switch len(present) {
	case 0:
		return nil, cibaErr(400, "invalid_request",
			"exactly one of login_hint, login_hint_token or id_token_hint is required: "+
				"without one there is nobody to ask")
	case 1:
		req.HintKind = present[0]
		req.Hint = strings.TrimSpace(form.Get(present[0]))
	default:
		return nil, cibaErr(400, "invalid_request",
			"more than one hint was supplied ("+strings.Join(present, ", ")+"); "+
				"exactly one is permitted, and choosing between them is not defined")
	}

	// §7.1: "client_notification_token REQUIRED if the Client is registered to
	// use Ping or Push modes."
	//
	// Both directions are errors, and the second is the one implementations skip.
	// A poll client that sends one expects a callback that will never arrive; a
	// ping client that omits one leaves us with nowhere to authenticate the
	// callback to, so the notification could be delivered to the endpoint but not
	// proven to come from us.
	switch deliveryMode {
	case DeliveryPing:
		if req.ClientNotificationToken == "" {
			return nil, cibaErr(400, "invalid_request",
				"client_notification_token is required: this client is registered "+
					"for ping delivery, and section 7.1 makes the token the means by "+
					"which the notification is authenticated to the client")
		}
		if err := validClientNotificationToken(req.ClientNotificationToken); err != nil {
			return nil, cibaErr(400, "invalid_request", err.Error())
		}
	default:
		if req.ClientNotificationToken != "" {
			return nil, cibaErr(400, "invalid_request",
				"client_notification_token was supplied, which belongs to the ping and "+
					"push delivery modes; this client is registered for poll delivery, "+
					"so no notification will be sent and the token has no use")
		}
	}

	// §7.1: user_code is gated on the OP advertising support. We do not, so a
	// client sending one is working from a different understanding of this
	// server than the one discovery describes.
	if req.UserCode != "" {
		return nil, cibaErr(400, "invalid_request",
			"user_code was supplied, but this server does not advertise "+
				"backchannel_user_code_parameter_supported")
	}

	if req.BindingMessage != "" {
		if err := validBindingMessage(req.BindingMessage); err != nil {
			// §13 defines a dedicated code for this, and using invalid_request
			// instead would tell the client to look at the wrong parameter.
			return nil, cibaErr(400, "invalid_binding_message", err.Error())
		}
	}

	if v := strings.TrimSpace(form.Get("acr_values")); v != "" {
		req.ACRValues = ParseACRValues(v)
	}

	// §7.1: "requested_expiry -- OPTIONAL. A positive integer allowing the
	// client to request the expires_in value".
	if v := strings.TrimSpace(form.Get("requested_expiry")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, cibaErr(400, "invalid_request",
				"requested_expiry must be a positive integer number of seconds")
		}
		d := time.Duration(n) * time.Second
		// Honoured only downwards. A client asking for longer than our ceiling
		// gets the ceiling rather than an error: it asked for a lifetime, we are
		// permitted to choose, and the response says what it actually got.
		if d > CIBAMaxExpiry {
			d = CIBAMaxExpiry
		}
		req.RequestedExpiry = d
	}
	return req, nil
}

// Expiry is the lifetime this request will actually get.
func (r *CIBARequest) Expiry() time.Duration {
	if r.RequestedExpiry > 0 {
		return r.RequestedExpiry
	}
	return CIBADefaultExpiry
}

func validBindingMessage(s string) error {
	if n := utf8.RuneCountInString(s); n > maxBindingMessage {
		return fmt.Errorf("the binding message is %d characters, over the %d-character "+
			"limit; it has to render on a phone notification beside the approval prompt",
			n, maxBindingMessage)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("the binding message is not valid UTF-8")
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("the binding message contains the non-printing character "+
				"U+%04X; it is displayed beside an approval prompt, and invisible, "+
				"directional and line-separating characters can make it read as "+
				"something other than what it says", r)
		}
	}
	return nil
}

// NewAuthReqID mints an auth_req_id.
//
// §7.3, quoted correctly on the second attempt: the entropy floor is a **MUST**
// of "a minimum of 128 bits while 160 bits is recommended", over the character
// set "'A'-'Z', 'a'-'z', '0'-'9', '.', '-' and '_'".
//
// The first version of this comment wrote it as "It is RECOMMENDED that the
// value be ... at least 128 bits", which turns a MUST into advice and loses the
// 160-bit recommendation entirely. We comply either way — 32 bytes base64url is
// 256 bits from exactly that alphabet, past both numbers — so nothing was built
// wrong. The citation was, and it is the same shape as the two other misquotes
// this review found (NIST's "advises against" for a SHALL NOT, and RFC 8628's
// "20 bits" read off "base 20"): a real document, a plausible paraphrase, and a
// normative level quietly softened.
//
// The same width as an authorization code, because it is the same kind of thing:
// whoever holds it can collect the tokens once it is approved.
func NewAuthReqID() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating an auth_req_id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// containsScopeValue reports whether a space-delimited scope string contains a
// value, comparing whole values rather than substrings.
func containsScopeValue(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

const (
	DeliveryPoll = "poll"
	DeliveryPing = "ping"
)

// maxClientNotificationToken is §7.1's ceiling, exactly.
//
// "The length of the token MUST NOT exceed 1024 characters and it MUST conform to
// the syntax for Bearer credentials as defined in Section 2.1 of [RFC6750]."
const maxClientNotificationToken = 1024

// validClientNotificationToken enforces the two halves of §7.1 that are ours to
// enforce.
//
// The third -- "Clients MUST ensure that it contains sufficient entropy (a
// minimum of 128 bits while 160 bits is recommended)" -- is an obligation on the
// CLIENT, and deliberately not checked here: entropy is not a property of a
// string an OP can measure. A 128-bit random value and the word "password"
// padded to the same length are indistinguishable from this side. Refusing short
// tokens would be a proxy that rejects conformant clients using a compact
// encoding while still accepting a long guessable one.
func validClientNotificationToken(t string) error {
	if len(t) > maxClientNotificationToken {
		return fmt.Errorf("client_notification_token is %d characters; section 7.1 "+
			"permits at most %d", len(t), maxClientNotificationToken)
	}
	// RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
	trimmed := strings.TrimRight(t, "=")
	if trimmed == "" {
		return fmt.Errorf("client_notification_token is empty once padding is removed")
	}
	for _, r := range trimmed {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_', r == '~', r == '+', r == '/':
		default:
			return fmt.Errorf("client_notification_token contains %q, which RFC 6750 "+
				"section 2.1 does not permit in a bearer credential", r)
		}
	}
	return nil
}
