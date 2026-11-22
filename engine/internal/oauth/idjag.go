package oauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Identity Assertion JWT Authorization Grant, draft-ietf-oauth-identity-assertion-authz-
// grant (specs/id-jag.txt): what a sign-in here is worth at another authorization server.
const (
	// TokenTypeIDJAG is §4.3's requested_token_type.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"
	// TokenTypeIDToken is the one subject_token_type taken for it.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	// GrantProfileIDJAG is §7.2's authorization_grant_profiles_supported value.
	GrantProfileIDJAG = "urn:ietf:params:oauth:grant-profile:id-jag"
	// TypIDJAG is §3's `typ`.
	TypIDJAG = "oauth-id-jag+jwt"
)

// IDJAGClaims is what §4.4.1 reads of a grant beyond RFC 7523's.
type IDJAGClaims struct {
	ClientID string `json:"client_id"`
	// Resource is a string or an array, §3.1, which Audience already reads.
	Resource Audience `json:"resource"`
	Scope    string   `json:"scope"`
	// Confirmation is only read for whether it is there: §4.4.1 has a key in it proved.
	Confirmation json.RawMessage `json:"cnf"`
}

// IsIDJAG says whether an assertion's header declares it one. Read before the signature
// is checked, so it only ever adds rules: dropping it from a signed grant fails the
// signature, and adding it to something else subjects that to more.
func IsIDJAG(assertion string) bool {
	header, _, found := strings.Cut(assertion, ".")
	if !found {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return false
	}
	var probe struct {
		Typ string `json:"typ"`
	}
	return json.Unmarshal(raw, &probe) == nil && strings.EqualFold(probe.Typ, TypIDJAG)
}
