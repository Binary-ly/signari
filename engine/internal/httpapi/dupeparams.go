package httpapi

import (
	"fmt"
	"net/url"
)

// Duplicate request parameters — RFC 6749 §3.1, and ASVS 5.0.0 V15.3.7.
//
//	"Request and response parameters MUST NOT be included more than once."
//
// The reasoning was already written down in this codebase, at the PAR endpoint:
//
//	"The tempting behaviour -- take the first, ignore the rest -- is parameter
//	pollution: whether the first or the last wins differs between servers,
//	proxies and libraries, so a request carrying two `redirect_uri` values can
//	be validated against one and acted on with the other."
//
// It was applied at PAR **and nowhere else**. The authorization endpoint and the
// token endpoint — the two that actually issue a code and a token, and the two a
// browser or a proxy sits in front of — had no such check. The endpoint where a
// duplicate `redirect_uri` matters most is the one that redirects.
//
// # Why this is not simply "refuse every duplicate"
//
// Two parameters are repeatable by specification and refusing them would break
// conformant clients:
//
//   - `resource`, RFC 8707 §2. This server already reads it as a list
//     (`q["resource"]`, capped at eight) precisely because a client may request
//     several audiences at once.
//   - `audience`, RFC 8693 §2.1, for the same reason at token exchange.
//
// So the rule is "at most once, unless a specification says otherwise", and the
// exceptions are named rather than inferred from whether the code happens to
// read a list.
var repeatableParams = map[string]bool{
	"resource": true, // RFC 8707 §2
	"audience": true, // RFC 8693 §2.1
}

// refuseDuplicateParams reports the first parameter that appears more than once
// and is not repeatable by specification.
func refuseDuplicateParams(values url.Values) error {
	for name, v := range values {
		if len(v) > 1 && !repeatableParams[name] {
			return fmt.Errorf("the parameter %q appears %d times; RFC 6749 section 3.1 "+
				"permits each at most once", name, len(v))
		}
	}
	return nil
}
