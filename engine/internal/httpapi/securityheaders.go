package httpapi

import (
	"net/http"
	"strings"
)

// Browser security response headers — OWASP ASVS 5.0.0 §V3.4.
//
// This chapter was skipped by the earlier ASVS sweeps on the reasoning, written
// into `security-review-asvs.md`, that the unswept chapters were "frontend
// rendering, file handling, WebRTC, configuration and general secure coding:
// relevant to the product, not specific to it".
//
// That was wrong about V3. An identity provider's login page is the most
// attacked page it serves, and V3.4 is the chapter about what the browser is
// told to do with it. Sweeping it found five headers absent entirely, two of
// them Level 1 — the baseline.
//
// V3.3 Cookie Setup, by contrast, was already met in full and needed nothing:
// every cookie carries the `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite`
// and no `Domain`.

// hstsMaxAge is one year in seconds.
//
// V3.4.1 requires "a maximum age of at least 1 year... and for L2 and up, the
// policy must apply to all subdomains as well".
const hstsMaxAge = "max-age=31536000; includeSubDomains"

// withSecurityHeaders sets the response headers that apply to every route.
//
// Set here rather than per handler because the requirement is "all responses",
// and a per-handler version is a list somebody has to remember to append to. The
// two headers this engine was missing at Level 1 are exactly the kind that get
// added to the HTML pages and forgotten on the JSON ones.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	// Decided once at wiring time rather than per request.
	secure := strings.HasPrefix(s.cfg.Issuer, "https://")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// V3.4.4 (L1): "all HTTP responses contain an 'X-Content-Type-Options:
		// nosniff' header field".
		//
		// The one that mattered most here. This server answers JSON on nearly
		// every endpoint, and several of those responses echo caller-supplied
		// values back inside an `error_description`. Without nosniff a browser
		// may decide a JSON body is HTML and render it, which turns an echoed
		// parameter into script execution on the issuer's own origin -- the
		// origin holding the session cookie.
		h.Set("X-Content-Type-Options", "nosniff")

		// V3.4.5 (L2): a referrer policy, "to prevent leakage of technically
		// sensitive data to third-party services via the 'Referer' request
		// header field... path and query data in the URL".
		//
		// `no-referrer` rather than a softer value because of what this server's
		// URLs contain. An authorization request carries `state`, `login_hint`
		// and `request_uri`; an authorization RESPONSE carries `code` in the
		// query string. Any resource loaded from a page holding one of those
		// would send it onward in a header, and the browser default
		// (`strict-origin-when-cross-origin`) still sends the full URL to the
		// same origin. There is no flow here that needs a Referer.
		h.Set("Referrer-Policy", "no-referrer")

		// V3.4.1 (L1/L2): HSTS with a maximum age of at least one year, applying
		// to subdomains at L2.
		//
		// Only when the issuer is https. A browser ignores HSTS received over
		// plaintext, so sending it always would be harmless in the common case --
		// but `AllowInsecureIssuer` exists so the OIDF conformance suite can
		// reach the engine by a plain-http service name, and a header that
		// silently does nothing is worse documentation than one that is absent
		// for a stated reason.
		if secure {
			h.Set("Strict-Transport-Security", hstsMaxAge)
		}

		next.ServeHTTP(w, r)
	})
}

// cspInvariants are the directives every policy this server sends must carry.
//
// V3.4.3 (L2) names two explicitly: "a global policy must be used which includes
// the directives object-src 'none' and base-uri 'none'".
//
// It names both because only one of them is covered by `default-src`.
// `object-src` falls back to `default-src`, so our `default-src 'none'` already
// blocked plugins. **`base-uri` has no fallback at all** -- it is one of the
// directives CSP deliberately leaves outside the `default-src` chain -- so every
// policy this server sent left `<base>` unrestricted, including the sign-in page,
// where `script-src` is relaxed to `'self'` and further still when a CAPTCHA
// provider is configured.
//
// An injected `<base href="...">` re-points every relative URL on the page. With
// `script-src 'self'` that cannot pull script from another origin, which is why
// this is a hardening gap rather than a live hole -- but it is one directive, the
// standard asks for it by name, and the protection it provides is exactly the
// protection that disappears the next time somebody widens a policy.
const cspInvariants = "base-uri 'none'; object-src 'none'"

// setCSP sends a Content-Security-Policy with the invariant directives appended.
//
// A helper rather than ten edited string literals. There were ten places
// building a policy by hand, and the failure mode of fixing them individually is
// that the eleventh page -- the one written next month -- starts from a copy of
// whichever one the author found first.
func setCSP(w http.ResponseWriter, policy string) {
	p := strings.TrimSpace(policy)
	p = strings.TrimSuffix(p, ";")
	w.Header().Set("Content-Security-Policy", p+"; "+cspInvariants)
}
