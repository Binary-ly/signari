package oauth

import (
	"slices"
	"strconv"
	"strings"
)

// The prompt values OpenID Connect Core §3.1.2.1 defines, and `create` from
// Initiating User Registration via OpenID Connect 1.0
// (https://openid.net/specs/openid-connect-prompt-create-1_0.html §4).
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
	PromptCreate        = "create"
)

// SupportedPrompts is every prompt value this server acts on, advertised as
// prompt_values_supported. That spec's §4.2: an OP supporting `create` "MUST
// define this metadata element", and "must also specify all other prompt values
// which it supports"; §4.1: a value not declared there SHOULD be answered with
// `invalid_request`, which ValidatePrompt does. httpapi's
// TestEveryAdvertisedPromptDoesWhatItSays drives each one.
var SupportedPrompts = []string{PromptNone, PromptLogin, PromptConsent, PromptSelectAccount, PromptCreate}

// HasPrompt reports whether a prompt parameter contains a value.
//
// # Why this exists
//
// OIDC Core §3.1.2.1: "prompt: OPTIONAL. **Space delimited**, case sensitive
// list of ASCII string values that specifies whether the Authorization Server
// prompts the End-User for reauthentication and consent."
//
// Every site in this server compared the parameter with `==` against a single
// value — `req.Prompt == "none"`, `prompt == "login"`, `req.Prompt == "consent"`.
// That is correct for a request carrying exactly one value and silently wrong for
// every combination.
//
// `prompt=login consent` is the combination that matters, and it is not exotic:
// it is what a relying party sends before a high-value operation to say
// "re-authenticate this person AND ask them to consent again". Under the old
// comparison it matched neither branch, so the user was re-authenticated not at
// all and asked to consent not at all — and the relying party, having received
// an ID token, had no way to tell. An RP that gates a transfer on
// `prompt=login` believed the session had just been re-verified when it had not.
//
// Case sensitive, per the same sentence: `Login` is not `login` and is not a
// value this specification defines.
func HasPrompt(prompt, want string) bool {
	for _, v := range strings.Fields(prompt) {
		if v == want {
			return true
		}
	}
	return false
}

// ValidatePrompt applies §3.1.2.1's exclusivity rule.
//
//	"none: The Authorization Server MUST NOT display any authentication or
//	consent user interface pages... If this parameter contains none with any
//	other value, an error is returned."
//
// The rule exists because the combination is self-contradictory: `none` promises
// the user will not be interrupted and every other value demands an
// interruption. An implementation that silently drops one half picks a winner
// the client did not choose.
//
// Returning an error rather than resolving it is what the specification asks
// for, and it is also the only answer that cannot mislead: a client sending
// `prompt=none login` has a bug, and telling it so is more useful than guessing
// which half it meant.
//
// And it refuses a value this server does not act on. Core leaves that open (an
// OP "MAY return an error or MAY ignore" one); once prompt_values_supported is
// published, the prompt-create spec's §4.1 asks for `invalid_request`. Ignored,
// `prompt=Login` -- the parameter is case sensitive -- re-authenticated nobody
// and told the client nothing.
func ValidatePrompt(prompt string) error {
	values := strings.Fields(prompt)
	for _, v := range values {
		if !slices.Contains(SupportedPrompts, v) {
			return &unsupportedPromptError{value: v}
		}
	}
	if len(values) < 2 {
		return nil
	}
	for _, v := range values {
		if v == PromptNone {
			return errPromptNoneCombined
		}
	}
	return nil
}

type unsupportedPromptError struct{ value string }

func (e *unsupportedPromptError) Error() string {
	return "prompt value " + strconv.Quote(e.value) + " is not supported; prompt_values_supported " +
		"in the discovery document lists those this server acts on (prompt values are case sensitive)"
}

// errPromptNoneCombined is the §3.1.2.1 violation.
var errPromptNoneCombined = &promptError{}

type promptError struct{}

func (e *promptError) Error() string {
	return "prompt contains \"none\" together with another value; OpenID Connect " +
		"Core section 3.1.2.1 requires an error, because none promises the user " +
		"will not be interrupted and every other value demands an interruption"
}
