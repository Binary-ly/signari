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
func ParseCIBARequest(form url.Values, clientID string) (*CIBARequest, *CIBAError) {
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

	// Ping and push modes deliver the result to a client endpoint instead of
	// being polled, and require client_notification_token. We implement poll
	// mode only, so its presence means the client expects a callback that will
	// never arrive.
	//
	// Refused rather than ignored. A client that gets an auth_req_id back
	// reasonably concludes the mode it asked for was accepted, and would then
	// wait forever for a notification.
	if req.ClientNotificationToken != "" {
		return nil, cibaErr(400, "invalid_request",
			"client_notification_token was supplied, which belongs to the ping and "+
				"push delivery modes; this server implements poll mode only, and "+
				"advertises exactly that in backchannel_token_delivery_modes_supported")
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

// validBindingMessage applies §7.1's "relatively short ... limited set of plain
// text characters".
//
// Control characters are the ones that matter. This string is rendered on an
// approval screen next to the question "do you want to allow this", and a
// newline or a bidirectional override in it is a way to make the screen say
// something other than what it appears to say.
func validBindingMessage(s string) error {
	if len(s) > maxBindingMessage {
		return fmt.Errorf("the binding message is %d bytes, over the %d-byte limit; "+
			"it has to render on a phone notification beside the approval prompt",
			len(s), maxBindingMessage)
	}
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\t':
			return fmt.Errorf("the binding message contains a line break or tab; it is " +
				"displayed inline beside an approval prompt and must not be able to " +
				"restructure it")
		case r < 0x20, r == 0x7f:
			return fmt.Errorf("the binding message contains a control character")
		// Bidirectional overrides can reverse displayed text, so a message can
		// read as one thing and be another.
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return fmt.Errorf("the binding message contains a bidirectional control " +
				"character, which can make it display differently from what it says")
		}
	}
	return nil
}

// NewAuthReqID mints an auth_req_id.
//
// §7.3: "It is RECOMMENDED that the value be a cryptographically random string
// with at least 128 bits of entropy" and the value is restricted to
// "[A-Za-z0-9.\-_]". 32 bytes base64url gives 256 bits from that exact alphabet.
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
