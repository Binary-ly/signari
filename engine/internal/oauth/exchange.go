package oauth

import (
	"fmt"
	"strings"
)

// RFC 8693 token exchange.
//
// The rules below are the difference between a delegation feature and an
// escalation path. Each one exists because its absence is exploitable, not
// because the RFC lists it.

// GrantTypeTokenExchange is the grant_type value.
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// Token type identifiers from RFC 8693 §3.
const (
	TokenTypeAccess  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefresh = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeID      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT     = "urn:ietf:params:oauth:token-type:jwt"
)

// ExchangeRequest is a parsed exchange.
type ExchangeRequest struct {
	SubjectToken     string
	SubjectTokenType string
	// ActorToken identifies WHO is doing the acting, when that differs from the
	// client. It is what makes an `act` chain meaningful rather than decorative.
	ActorToken     string
	ActorTokenType string

	Audience           []string
	Resource           []string
	Scope              []string
	RequestedTokenType string
}

// ParseExchange reads the exchange parameters from a token request form.
func ParseExchange(form map[string][]string) ExchangeRequest {
	first := func(k string) string {
		if v := form[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return ExchangeRequest{
		SubjectToken:       first("subject_token"),
		SubjectTokenType:   first("subject_token_type"),
		ActorToken:         first("actor_token"),
		ActorTokenType:     first("actor_token_type"),
		Audience:           form["audience"],
		Resource:           form["resource"],
		Scope:              splitScope(first("scope")),
		RequestedTokenType: first("requested_token_type"),
	}
}

func splitScope(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}

// ValidateExchange checks an exchange request against the subject token it
// presents.
//
// `subjectScopes` and `subjectAudience` come from the VERIFIED subject token --
// never from the request. Taking them from the request would let a caller
// describe its own token as anything it liked, which is the whole attack.
// ValidateExchange applies the exchange rules.
//
// It does NOT take the subject token's own client. That was a parameter here,
// threaded through from the call site and assigned to the blank identifier --
// which reads like a check that exists. It does not, and the omission is
// deliberate: RFC 8693's canonical flow is a resource server exchanging a token
// it was legitimately given, so the subject token having been issued to someone
// else is the normal case rather than a red flag.
//
// What bounds the exchange instead is stated in RFC 8693 §5: "The use of the
// `scope` claim (in addition to other typical constraints such as a limited
// token lifetime) is suggested to mitigate potential for such abuse." That is
// the scope ceiling below, plus the per-client audience allow-list.
//
// The specification's own mechanism for "who may act for whom" is the `may_act`
// claim (§4.4), which is a MAY: "can be used by the authorization server to
// determine whether the client ... is authorized to engage in the requested
// delegation". We gate per client rather than per subject token, which is
// coarser and always on. If may_act is implemented later it belongs beside the
// actor-token branch, not here.
func ValidateExchange(req ExchangeRequest, confidential, mayExchange bool,
	allowedAudiences []string, callerClientID string,
	subjectScopes []string) (granted []string, aud []string, e *TokenError) {

	if !confidential {
		return nil, nil, tokenErr("invalid_client",
			"token exchange requires a confidential client; a public client cannot "+
				"prove it is the client this permission was granted to, so anyone "+
				"holding the subject token could exchange it")
	}
	if !mayExchange {
		// Off by default. A client that was never granted exchange must not be
		// able to discover it by trying.
		return nil, nil, tokenErr("unauthorized_client",
			"this client is not permitted to exchange tokens")
	}
	if req.SubjectToken == "" {
		return nil, nil, tokenErr("invalid_request", "subject_token is required")
	}
	switch req.SubjectTokenType {
	case TokenTypeAccess, TokenTypeJWT:
	case "":
		return nil, nil, tokenErr("invalid_request", "subject_token_type is required")
	default:
		// Refusing an unimplemented type is not pedantry: silently treating an
		// ID token as an access token is how a token issued for authentication
		// becomes one for authorisation.
		return nil, nil, tokenErr("invalid_request",
			fmt.Sprintf("subject_token_type %q is not supported", req.SubjectTokenType))
	}
	if req.RequestedTokenType != "" &&
		req.RequestedTokenType != TokenTypeAccess && req.RequestedTokenType != TokenTypeJWT {
		return nil, nil, tokenErr("invalid_request",
			fmt.Sprintf("requested_token_type %q is not supported", req.RequestedTokenType))
	}

	// The actor token: RFC 8693 §4.1 delegation.
	//
	// §2.1 is a MUST on the server: "In processing the request, the authorization
	// server MUST perform the appropriate validation procedures for the indicated
	// token type and, if the actor token is present, also perform the appropriate
	// validation procedures for its indicated token type."
	//
	// These two parameters were once parsed and read by nothing, so a client
	// asserting "this specific party is doing the acting" received a token whose
	// `act` chain named only the calling client, with a 200 and no sign the
	// assertion had been dropped. That was fixed by REFUSING the parameter, which
	// is correct for something unimplemented but is not the same as supporting
	// delegation -- and it left `may_act.sub` with nothing to compare against.
	//
	// Now validated. The parameter shape is checked here; the token itself is
	// verified by the caller, which can reach the key set and the revocation
	// state, exactly as it does for the subject token.
	if req.ActorToken != "" && req.ActorTokenType == "" {
		// §2.1: actor_token_type "is REQUIRED when the actor_token parameter is
		// present in the request".
		return nil, nil, tokenErr("invalid_request",
			"actor_token_type is required when actor_token is present")
	}
	if req.ActorToken == "" && req.ActorTokenType != "" {
		// §2.1: actor_token_type "MUST NOT be included otherwise".
		return nil, nil, tokenErr("invalid_request",
			"actor_token_type must not be sent without actor_token")
	}
	if req.ActorToken != "" {
		switch req.ActorTokenType {
		case TokenTypeAccess, TokenTypeJWT:
		default:
			// Same reasoning as the subject token: silently accepting a type we do
			// not validate the way its specification requires is how a token issued
			// for one purpose becomes authority for another.
			return nil, nil, tokenErr("invalid_request",
				fmt.Sprintf("actor_token_type %q is not supported", req.ActorTokenType))
		}
	}

	// THE SCOPE CEILING.
	//
	// The exchanged token may narrow the subject's scopes and may never exceed
	// them. Without this, exchange is a privilege escalation: present a token
	// with `read`, ask for `admin`, receive `admin`. It is the single most
	// important rule in this file and the easiest to omit, because the happy
	// path works identically without it.
	if len(req.Scope) == 0 {
		granted = subjectScopes
	} else {
		have := make(map[string]bool, len(subjectScopes))
		for _, s := range subjectScopes {
			have[s] = true
		}
		for _, want := range req.Scope {
			if !have[want] {
				return nil, nil, tokenErr("invalid_scope",
					fmt.Sprintf("scope %q was not granted to the subject token; an exchange "+
						"may narrow scopes but never add them", want))
			}
			granted = append(granted, want)
		}
	}

	// The audience must be one this client was configured to exchange for. An
	// unrestricted exchanger can mint a token for any resource server in the
	// deployment, which is exactly the escalation the allow-list prevents.
	aud = append(append([]string{}, req.Audience...), req.Resource...)
	if err := validateResources(req.Resource); err != nil {
		return nil, nil, tokenErr("invalid_target", err.Error())
	}
	if len(aud) == 0 {
		// No audience requested: the token stays addressed to the caller, which
		// is the narrowest possible answer.
		aud = []string{callerClientID}
	} else {
		allowed := make(map[string]bool, len(allowedAudiences))
		for _, a := range allowedAudiences {
			allowed[a] = true
		}
		for _, a := range aud {
			if a == callerClientID {
				continue // always allowed to address itself
			}
			if !allowed[a] {
				return nil, nil, tokenErr("invalid_target",
					fmt.Sprintf("this client may not exchange tokens for audience %q", a))
			}
		}
	}

	return granted, aud, nil
}
