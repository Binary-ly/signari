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
				"authorization code would cross the network in the clear. Use "+
				"https, or http on a loopback address for local development", raw)
		}
	}

	// An ALLOW-LIST of schemes: https, loopback http, or an RFC 8252 private-use
	// scheme, which is reverse-domain and therefore contains a dot.
	//
	// This rule already existed, in the dynamic-registration path, whose comment
	// said it "applies the same rules an operator-registered client gets". It did
	// not: there were two validators for one rule and they disagreed. This one --
	// the one the CLI and the admin API use -- rejected only http on a
	// non-loopback host, so `javascript:`, `data:`, `vbscript:` and `file:` were
	// all accepted as redirect URIs for an operator-registered client.
	//
	// The practical risk was small: it takes an operator to register one, and a
	// browser will not navigate to `javascript:` or `data:` from a Location
	// header. It is not nothing, though -- the authorization code is appended to
	// whatever is registered, so a `file:` or bespoke scheme hands the code to a
	// local handler, and an embedded webview is far less careful than a browser.
	//
	// One implementation now, so the two paths cannot drift again.
	switch {
	case u.Scheme == "https", u.Scheme == "http":
		// Covered above.
	case strings.Contains(u.Scheme, "."):
		// RFC 8252 §7.1: "com.example.app:/oauth2redirect/example-provider".
	default:
		return fmt.Errorf("%q uses the %q scheme; a redirect URI must be https, "+
			"http on a loopback address, or a private-use scheme in reverse-domain "+
			"form -- anything else hands the authorization code to whatever on the "+
			"device claims that scheme", raw, u.Scheme)
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
