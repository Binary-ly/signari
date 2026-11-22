package oauth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"signari.dev/engine/internal/clients"
)

// The `claims` request parameter. OpenID Connect Core is not among specs/, so this
// is the behaviour chosen and not a reading of its text: docs/oidc-parameters.md.
//
// It is read as a way of asking for things this server already decides, never as
// another way of being given them. Everything here releases by scope, and there is one
// consent screen, one release and one set of step-up rules: a request for a claim becomes
// a request for its scope, an essential `acr` becomes acr_values, and from there it is an
// ordinary request. So the parameter can release nothing the client is not registered
// for, and nothing the person did not consent to.
//
// What that costs is precision: asking for `email` in `userinfo` alone also puts it in the
// ID token, as the scope does. A client gets at most what its scopes would give it.

// claimAsk is one claim's request: null, or an object saying how much it matters.
type claimAsk struct {
	Essential bool     `json:"essential"`
	Value     any      `json:"value"`
	Values    []string `json:"values"`
}

// claimsRequest is the parameter's two members. Any other is ignored.
type claimsRequest struct {
	UserInfo map[string]*claimAsk `json:"userinfo"`
	IDToken  map[string]*claimAsk `json:"id_token"`
}

// claimScope is the scope each claim is released under. A claim not here is released
// to everybody or to nobody, and asking changes neither.
var claimScope = map[string]string{
	"email": "email", "email_verified": "email",
	"name": "profile", "given_name": "profile", "family_name": "profile", "preferred_username": "profile",
	"groups": "groups",
}

// CompileClaims rewrites a request's `claims` parameter into its scope and acr_values,
// and returns the subject it names, "" for none. It can be run on a request already
// compiled, which is how a parked one comes back. A claim whose scope the client is not
// registered for is dropped and not refused, essential or not: that the claim does not
// come back is the answer.
func CompileClaims(query url.Values, c *clients.Client) (subject string, err error) {
	raw := query.Get("claims")
	if raw == "" {
		return "", nil
	}
	var asked claimsRequest
	if err := json.Unmarshal([]byte(raw), &asked); err != nil {
		return "", fmt.Errorf("the claims parameter is not a JSON object of claims requests")
	}
	scopes := strings.Fields(query.Get("scope"))
	for _, member := range []map[string]*claimAsk{asked.UserInfo, asked.IDToken} {
		names := make([]string, 0, len(member))
		for name := range member {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if scope := claimScope[name]; scope != "" && !slices.Contains(scopes, scope) &&
				len(c.UnknownScopes([]string{scope})) == 0 {
				scopes = append(scopes, scope)
			}
			if ask := member[name]; name == "sub" && ask != nil {
				named, ok := ask.Value.(string)
				if !ok && ask.Value != nil {
					return "", fmt.Errorf("the claims parameter's sub value is not a string")
				}
				if subject != "" && named != "" && named != subject {
					return "", fmt.Errorf("the claims parameter names two subjects")
				}
				if named != "" {
					subject = named
				}
			}
		}
	}
	query.Set("scope", strings.Join(scopes, " "))
	if ask := asked.IDToken["acr"]; ask != nil && ask.Essential {
		values := strings.Fields(query.Get("acr_values"))
		wanted := ask.Values
		if value, ok := ask.Value.(string); ok && value != "" {
			wanted = append(wanted, value)
		}
		for _, value := range wanted {
			if !slices.Contains(values, value) {
				values = append(values, value)
			}
		}
		if len(values) > 0 {
			query.Set("acr_values", strings.Join(values, " "))
		}
	}
	return subject, nil
}
