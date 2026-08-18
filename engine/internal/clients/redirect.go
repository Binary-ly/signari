package clients

import (
	"fmt"
	"net/url"
	"strings"
)


var ForbiddenRedirectParams = map[string]bool{
	"code": true, "id_token": true, "access_token": true, "token_type": true,
	"expires_in": true, "state": true, "scope": true, "iss": true,
	"error": true, "error_description": true, "error_uri": true,
	"session_state": true,
}

// ValidateRedirectURI checks a URI before it is registered.
//
// ONE validator, called from every registration path: the CLI, the admin API,
// dynamic registration (RFC 7591) and the importer. Four sites each doing their
// own checking is three sites that eventually disagree, and the weakest is the
// one an attacker registers through -- dynamic registration being open to
// anybody is exactly the wrong place to have the lenient copy.
func ValidateRedirectURI(raw string) error {
	if raw == "" {
		return fmt.Errorf("a redirect URI is required")
	}
	if strings.Contains(raw, "*") {
		return fmt.Errorf("%q contains a wildcard; redirect URIs are compared by "+
			"exact string match (OAuth 2.1, RFC 9700 section 4.1.3), so register "+
			"each URI in full", raw)
	}
	// Absolute only. A relative URI has no origin, so "does this belong to the
	// client" has no answer.
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("that redirect URI does not parse: %w", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("%q must be an absolute URI", raw)
	}
	// http only on loopback, the documented native-app pattern (RFC 8252).
	// Anywhere else the authorization code crosses the network in the clear.
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("%q uses http on a non-loopback host; the "+
				"authorization code would cross the network in the clear", raw)
		}
	}
	// No user-info. `https://good.example@evil.example/cb` reads as good.example
	// to a person and resolves to evil.example -- and defeating the parse of
	// this component is precisely how CVE-2026-7504 worked.
	if u.User != nil {
		return fmt.Errorf("a redirect URI must not contain user information " +
			"before the host: it reads as one host and resolves to another")
	}

	for _, part := range []struct{ name, value string }{
		{"query", u.RawQuery},
		{"fragment", u.Fragment},
	} {
		if part.value == "" {
			continue
		}
		vals, perr := url.ParseQuery(part.value)
		if perr != nil {
			// A fragment that is not key=value is fine -- it is just a fragment.
			continue
		}
		for k := range vals {
			if ForbiddenRedirectParams[strings.ToLower(k)] {
				return fmt.Errorf("a redirect URI must not carry %q in its %s: "+
					"the authorization response appends that parameter, and a "+
					"relying party that reads the first occurrence would read "+
					"this one instead", k, part.name)
			}
		}
	}
	return nil
}
