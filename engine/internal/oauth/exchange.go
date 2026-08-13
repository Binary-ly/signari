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
func ValidateExchange(req ExchangeRequest, mayExchange bool, allowedAudiences []string,
	subjectClientID, callerClientID string, subjectScopes []string) (granted []string, aud []string, e *TokenError) {

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

	_ = subjectClientID
	return granted, aud, nil
}
