package txntoken

import (
	"fmt"
	"strings"
	"time"
)


// GrantType is RFC 8693's, because a Txn-Token request IS a token exchange.
const GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// TokenType identifies a Txn-Token in requested_token_type and
// issued_token_type.
const TokenType = "urn:ietf:params:oauth:token-type:txn_token"

// Subject token types, section 11.2.
//
// The specification says the type MAY be any RFC 8693 type EXCEPT
// refresh_token, or one of two URNs it defines, or a custom one agreed between
// requester and TTS.
const (
	SubjectAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	SubjectIDToken     = "urn:ietf:params:oauth:token-type:id_token"
	SubjectJWT         = "urn:ietf:params:oauth:token-type:jwt"
	SubjectTxnToken    = TokenType
	// SubjectRefreshToken is named so it can be REFUSED by name. Section 11.2
	// excludes it, and section 13.3 explains why: a refresh token is a
	// long-lived credential for obtaining access tokens, and turning one
	// directly into a transaction token skips every check that sits between.
	SubjectRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	// Defined by the specification but not implemented here. Named so the
	// refusal can say "not supported" rather than "invalid", which are
	// different problems for whoever is integrating.
	SubjectSelfSigned   = "urn:ietf:params:oauth:token-type:self_signed"
	SubjectUnsignedJSON = "urn:ietf:params:oauth:token-type:unsigned_json"
)

// ErrSubjectTokenType means the type is one we will not or cannot accept.
var ErrSubjectTokenType = fmt.Errorf("unsupported subject_token_type")

// CheckSubjectTokenType applies section 11.2.
//
// Enumerated rather than defaulted. The first version treated ANY unrecognised
// type as an access token, which meant a refresh token -- the one type the
// specification excludes -- was refused only by accident, because it happens
// not to parse as an access token JWT. An exclusion that holds by accident is
// one that stops holding when the accident changes.
func CheckSubjectTokenType(t string) error {
	switch t {
	case SubjectAccessToken, SubjectIDToken, SubjectJWT, SubjectTxnToken:
		return nil
	case SubjectRefreshToken:
		return fmt.Errorf("%w: section 11.2 excludes refresh tokens, and 13.3 "+
			"explains why -- a long-lived credential must not become a "+
			"transaction token directly", ErrSubjectTokenType)
	case SubjectSelfSigned, SubjectUnsignedJSON:
		return fmt.Errorf("%w: %s is defined by the specification but not "+
			"implemented here", ErrSubjectTokenType, t)
	case "":
		return fmt.Errorf("%w: subject_token_type is required", ErrSubjectTokenType)
	}
	return fmt.Errorf("%w: %q is not a type this deployment accepts",
		ErrSubjectTokenType, t)
}

// Typ is the JWT header `typ`.
//
// Distinct from at+jwt on purpose. A resource server that accepts both without
// checking would let a Txn-Token be presented as an access token, and the two
// carry different authority -- RFC 8725's explicit-typing rule exists for this.
const Typ = "txntoken+jwt"

// Header is how a Txn-Token travels between workloads.
//
// NOT Authorization. The specification is explicit: workloads use that header
// for their own purposes, and overloading it means a proxy that strips or
// rewrites Authorization silently destroys the transaction context.
const Header = "Txn-Token"

// DefaultTTL is how long one lives.
//
// Very short. A Txn-Token is minted for one transaction that is in flight; if
// it outlives the transaction it is a bearer credential lying around a network
// where every service can read it.
const DefaultTTL = 5 * time.Minute

// MaxTTL bounds what a deployment may configure.
const MaxTTL = 15 * time.Minute

// Claims is the Txn-Token body.
//
// Field order and names follow the draft exactly. A near-miss here is a token
// that every conforming consumer rejects for reasons nobody can see.
type Claims struct {
	// Issuer is OPTIONAL in the draft. We always set it: a token whose issuer
	// cannot be determined cannot have its key found, and "optional" in a spec
	// does not mean "helpful to omit".
	Issuer string `json:"iss,omitempty"`
	// IssuedAt and Expiry are REQUIRED.
	IssuedAt int64 `json:"iat"`
	Expiry   int64 `json:"exp"`
	// Audience is the TRUST DOMAIN, not a client. One value, not a list: a
	// Txn-Token that is valid in two trust domains is valid in the weaker one.
	Audience string `json:"aud"`
	// Transaction is the immutable id tying every hop together.
	Transaction string `json:"txn"`
	// Subject is who the transaction is on behalf of.
	Subject string `json:"sub"`
	// RequestingWorkload is who asked for the token. REQUIRED.
	RequestingWorkload string `json:"req_wl"`
	// CallChain is every workload that has requested this transaction's
	// tokens, oldest first, INCLUDING the current one.
	//
	// Section 13.15 says a TTS "MUST maintain the Call Chain of workloads that
	// requested the Txn-Token being replaced in the subsequently issued
	// Txn-Token", and leaves the mechanism out of scope. `req_wl` is singular
	// and is overwritten at each hop, so on its own the chain is destroyed at
	// the first replacement -- which is exactly the audit property this format
	// exists to provide.
	//
	// So the chain is carried in an additional claim, which section 9.2
	// explicitly permits ("A Txn-Token MAY contain additional claims").
	CallChain []string `json:"req_wl_chain,omitempty"`
	// Scope is the authorization intent, space-delimited. REQUIRED.
	Scope string `json:"scope"`

	// TransactionContext describes what is being done -- the action and its
	// parameters. RECOMMENDED.
	TransactionContext map[string]any `json:"tctx,omitempty"`
	// RequestContext describes the environment the request arrived in.
	// RECOMMENDED.
	RequestContext map[string]any `json:"rctx,omitempty"`
}

// Request is a parsed Txn-Token request.
type Request struct {
	Audience         string
	Scope            []string
	SubjectToken     string
	SubjectTokenType string
	RequestContext   map[string]any
	RequestDetails   map[string]any
}

// Response is what the TTS returns.
type Response struct {
	// TokenType is literally "N_A" per the draft. It is not a mistake: a
	// Txn-Token is not a bearer token for an HTTP Authorization header, and
	// saying "Bearer" would invite a workload to use it as one.
	TokenType       string `json:"token_type"`
	IssuedTokenType string `json:"issued_token_type"`
	// AccessToken carries the Txn-Token, because RFC 8693's response shape
	// names the field that way whatever was actually issued.
	AccessToken string `json:"access_token"`
}

// NewResponse wraps a minted token.
func NewResponse(jwt string) Response {
	return Response{
		TokenType:       "N_A",
		IssuedTokenType: TokenType,
		AccessToken:     jwt,
	}
}

// Replacement describes a request to replace a Txn-Token for the next hop.
type Replacement struct {
	// Previous is the verified token being replaced.
	Previous Claims
	// Workload is the authenticated identity of the caller asking for the
	// replacement -- taken from client authentication, never from the body.
	Workload string
	// Scope is what the caller is asking for. It may only narrow.
	Scope []string
	// RequestContext replaces the environmental context, which legitimately
	// differs per hop.
	RequestContext map[string]any
}

// ErrWiden is returned when a replacement asks for authority it was not given.
var ErrWiden = fmt.Errorf("a replacement token may not widen scope")

// Replace derives the next token in a chain.
//
// The immutable fields are copied rather than re-derived, so there is no path
// by which a caller's input reaches them. Copying is the mechanism, not a
// convention somebody could edit around.
func Replace(r Replacement, issuer string, now time.Time, ttl time.Duration) (Claims, error) {
	if r.Previous.Transaction == "" || r.Previous.Subject == "" {
		return Claims{}, fmt.Errorf("the previous token is missing txn or sub")
	}
	if ttl <= 0 || ttl > MaxTTL {
		ttl = DefaultTTL
	}

	had := splitScope(r.Previous.Scope)
	want := r.Scope
	if len(want) == 0 {
		// Asking for nothing means "carry what I have". Narrowing is a choice a
		// caller makes deliberately; silence should not silently drop authority
		// the next hop needs.
		want = had
	}
	for _, s := range want {
		if !contains(had, s) {
			return Claims{}, fmt.Errorf("%w: %q was not in the presented token", ErrWiden, s)
		}
	}

	// The replacement may NOT outlive the token it came from. Otherwise a chain
	// extends its own life one hop at a time, and a five-minute token becomes
	// permanent across enough services.
	exp := now.Add(ttl).Unix()
	if r.Previous.Expiry > 0 && exp > r.Previous.Expiry {
		exp = r.Previous.Expiry
	}
	if exp <= now.Unix() {
		return Claims{}, fmt.Errorf("the presented token has expired")
	}

	return Claims{
		Issuer:   issuer,
		IssuedAt: now.Unix(),
		Expiry:   exp,
		// Immutable. Copied from the verified previous token.
		Audience:    r.Previous.Audience,
		Transaction: r.Previous.Transaction,
		Subject:     r.Previous.Subject,
		// The one field that SHOULD change: each hop says who it is.
		RequestingWorkload: r.Workload,
		// And the chain grows rather than being overwritten -- section 13.15's
		// MUST. Built from the PREVIOUS token's chain, so a caller cannot
		// supply one: the history is ours, not theirs.
		CallChain: appendChain(r.Previous, r.Workload),
		Scope:     strings.Join(want, " "),
		// Transaction context is immutable too: what is being done does not
		// change because the request moved one service to the right.
		TransactionContext: r.Previous.TransactionContext,
		// Request context legitimately differs per hop.
		RequestContext: r.RequestContext,
	}, nil
}

// Validate checks a request can be answered.
func (r Request) Validate() error {
	var missing []string
	if r.Audience == "" {
		missing = append(missing, "audience (the trust domain)")
	}
	if len(r.Scope) == 0 {
		missing = append(missing, "scope")
	}
	if r.SubjectToken == "" {
		missing = append(missing, "subject_token")
	}
	if r.SubjectTokenType == "" {
		missing = append(missing, "subject_token_type")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the request is missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func splitScope(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// appendChain extends the call chain by one hop.
//
// Reads the previous token's chain and falls back to its req_wl, so a token
// minted before this claim existed still contributes its workload rather than
// vanishing from the history.
//
// Bounded. Section 13.15 also says a TTS SHOULD limit how many times a token is
// replaced; an unbounded chain is both a growing token and a hint that
// something is looping.
func appendChain(prev Claims, next string) []string {
	chain := prev.CallChain
	if len(chain) == 0 && prev.RequestingWorkload != "" {
		chain = []string{prev.RequestingWorkload}
	}
	// Copied rather than appended in place: append may share the backing array
	// with the caller's slice, and two replacements from one token would then
	// scribble over each other.
	out := make([]string, 0, len(chain)+1)
	out = append(out, chain...)
	if len(out) >= MaxCallChain {
		return out
	}
	return append(out, next)
}

// MaxCallChain bounds how long a chain may grow.
//
// A transaction crossing more than this many workloads is a loop or a design
// nobody intended to have. Reaching it does not fail the request -- refusing a
// live transaction because its history is long would be worse than truncating
// the history -- but the chain stops growing, which is visible.
const MaxCallChain = 32
