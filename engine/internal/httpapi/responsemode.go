package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Delivering an authorization response by query, fragment or form_post.
//
// # Why form_post exists here at all
//
// For the code flow it buys almost nothing: an authorization code in a query
// string is single-use, PKCE-bound and worthless to anyone who reads it out of
// a log. This was refused for exactly that reason, and the reasoning was right
// at the time.
//
// Hybrid changes it. An id_token is a signed assertion about who just signed
// in, it is not single-use, and a query string is written to the far end's
// access log, to every proxy in between, and to browser history. So the moment
// `code id_token` became possible, form_post stopped being decoration.
//
// # The auto-submitting form
//
// OIDC's form_post response mode is an HTML page that posts itself. That needs
// a script, and a script on this page needs a Content-Security-Policy that
// permits it. A nonce is used rather than 'unsafe-inline': the page carries a
// signed assertion, and 'unsafe-inline' would let anything injected into it run
// as well.
//
// The noscript fallback is a real button rather than an apology. A browser with
// script disabled still completes the sign-in, one click later.

// responseParams is what an authorization response carries.
type responseParams struct {
	Code    string
	IDToken string
	State   string
	Issuer  string
}

func (p responseParams) values() url.Values {
	v := url.Values{}
	if p.Code != "" {
		v.Set("code", p.Code)
	}
	if p.IDToken != "" {
		v.Set("id_token", p.IDToken)
	}
	if p.State != "" {
		v.Set("state", p.State)
	}
	// RFC 9207, on every mode: tell the client which issuer answered.
	if p.Issuer != "" {
		v.Set("iss", p.Issuer)
	}
	return v
}

// deliverAuthzResponse sends the response by the mode the client asked for.
//
// mode may be empty, in which case the default depends on what is being
// carried: `query` for a bare code, `fragment` for anything with an id_token,
// which is what OIDC specifies and what keeps assertions out of server logs.
func (s *Server) deliverAuthzResponse(w http.ResponseWriter, r *http.Request,
	redirectURI, mode string, p responseParams) {

	if mode == "" {
		mode = "query"
		if p.IDToken != "" {
			mode = "fragment"
		}
	}

	if mode == "form_post" {
		s.postAuthzResponse(w, r, redirectURI, p)
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusInternalServerError)
		return
	}
	switch mode {
	case "fragment":
		// Merged with any fragment already on the registered URI rather than
		// replacing it, because a client that registered one put it there.
		existing := strings.TrimPrefix(u.Fragment, "#")
		encoded := p.values().Encode()
		if existing != "" {
			encoded = existing + "&" + encoded
		}
		u.Fragment = encoded
	default:
		q := u.Query()
		for k, vs := range p.values() {
			for _, v := range vs {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}
	// 303, not 302, and never 307.
	//
	// FAPI 2.0 §5.3.2.2 states both halves: an authorization server "shall not
	// use the HTTP 307 status code when redirecting a request that contains user
	// credentials to avoid forwarding the credentials to a third party
	// accidentally", and "should use the HTTP 303 status code when redirecting
	// the user agent using status codes".
	//
	// 307 is the obvious hazard -- it preserves the method and body, so a POSTed
	// password is re-sent to wherever the redirect points. 302 is the quiet one:
	// RFC 7231 §6.4.3 says a user agent MAY change the method from POST to GET,
	// which means it may also keep it. The behaviour is the agent's choice, and
	// "usually GET" is not a security property.
	//
	// 303 removes the choice: §6.4.4 requires the method change. Every redirect
	// this server issues is "the result is at another URI, go and GET it", so the
	// whole codebase uses it rather than leaving one status code here and another
	// everywhere else for a reader to reason about.
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// postAuthzResponse renders the self-submitting form.
// r is carried only so the bridge's <noscript> text can be rendered in the
// language the request asked for. It is the one thing on the page a person ever
// reads, and only when scripting is off.
func (s *Server) postAuthzResponse(w http.ResponseWriter, r *http.Request,
	redirectURI string, p responseParams) {
	nonce, err := newCSPNonce()
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	type field struct{ Name, Value string }
	var fields []field
	for k, vs := range p.values() {
		for _, v := range vs {
			fields = append(fields, field{k, v})
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Never cached. The page contains a single-use code and, in a hybrid
	// response, a signed assertion about who just signed in.
	w.Header().Set("Cache-Control", "no-store")
	setCSP(w, "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
		"form-action "+formActionOrigin(redirectURI)+"; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	s.renderBare(w, r, "formpost", map[string]any{
		"Action": redirectURI, "Fields": fields, "Nonce": nonce,
	})
}

// formActionOrigin narrows form-action to where this form actually posts.
//
// Without it the policy would have to allow any target, which on a page that
// carries a code and an assertion is the one thing worth constraining.
func formActionOrigin(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "'self'"
	}
	return u.Scheme + "://" + u.Host
}

// newCSPNonce mints a per-response nonce for an inline script.
//
// Per response, never reused: a nonce that repeats is a nonce an attacker can
// predict, which makes it exactly as useful as 'unsafe-inline'.
func newCSPNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
