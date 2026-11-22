package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"time"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/tokens"
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
//
// # Signed responses
//
// A code in a query string says nothing about where it came from. JARM puts the whole
// response in a JWT this server signs, for the client to verify before it reads any of
// it, and the three encodings above carry that one `response` parameter instead.

// authzResponseLifetime is how long a signed response stays good. JARM §2.1: "A maximum
// JWT lifetime of 10 minutes is RECOMMENDED." It arrives in a moment, so what this
// leaves room for is a client whose clock disagrees.
const authzResponseLifetime = 5 * time.Minute

// responseParams is what an authorization response carries.
type responseParams struct {
	Code             string
	IDToken          string
	Error            string
	ErrorDescription string
	State            string
	Issuer           string
	// Response is JARM's one parameter, and everything above is inside it.
	Response string
}

func (p responseParams) values() url.Values {
	v := url.Values{}
	if p.Code != "" {
		v.Set("code", p.Code)
	}
	if p.IDToken != "" {
		v.Set("id_token", p.IDToken)
	}
	if p.Error != "" {
		v.Set("error", p.Error)
	}
	if p.ErrorDescription != "" {
		v.Set("error_description", oauth.ErrorText(p.ErrorDescription))
	}
	if p.State != "" {
		v.Set("state", p.State)
	}
	// RFC 9207, on every mode: tell the client which issuer answered.
	if p.Issuer != "" {
		v.Set("iss", p.Issuer)
	}
	if p.Response != "" {
		v.Set("response", p.Response)
	}
	return v
}

// signAuthzResponse is the response as a JARM JWT. §2.1: the JWT "MUST furthermore
// contain the authorization endpoint response parameters as defined for the particular
// response types, even in case of an error response", and that includes RFC 9207's
// `iss`, which FAPI 2.0 Message Signing §5.4.1 keeps inside it for the same reason.
func (s *Server) signAuthzResponse(c *clients.Client, p responseParams) (string, error) {
	// §3: "If unspecified, the default algorithm to use for signing authorization
	// responses is RS256."
	alg := keys.RS256
	if c.AuthorizationResponseAlg != "" {
		alg = keys.Algorithm(c.AuthorizationResponseAlg)
	}
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		return "", err
	}
	claims := map[string]any{"aud": c.ClientID, "exp": time.Now().Add(authzResponseLifetime).Unix()}
	for name, values := range p.values() {
		claims[name] = values[0]
	}
	signed, err := tokens.NewSigner(key).SignJSON(claims, "JWT")
	if err != nil || c.AuthorizationEncryption.Alg == "" {
		return signed, err
	}
	// §2.2: "the JSON document will be signed then encrypted".
	return tokens.EncryptTo([]byte(signed), true, c.EncryptionKeys, c.AuthorizationEncryption)
}

// deliverAuthzResponse sends a response, a code or an error, the way the request asked:
// oauth.AuthzRequest.ResponseEncoding says which, and what it defaults to.
func (s *Server) deliverAuthzResponse(w http.ResponseWriter, r *http.Request,
	req oauth.AuthzRequest, c *clients.Client, p responseParams) {

	mode, signed := req.ResponseEncoding()
	// A client held to signing gets nothing else, the refusal of a plain mode included.
	if signed || c.HeldToSignedResponses() {
		response, err := s.signAuthzResponse(c, p)
		if err != nil {
			// Never the same thing unsigned: the client asked for a signature so as
			// to refuse a response without one.
			s.log.ErrorContext(r.Context(), "signing an authorization response", "err", err, "client", c.ClientID)
			http.Error(w, "the authorization response could not be signed", http.StatusInternalServerError)
			return
		}
		p = responseParams{Response: response}
	}

	if mode == "form_post" {
		s.postAuthzResponse(w, r, req.RedirectURI, p)
		return
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusInternalServerError)
		return
	}
	switch mode {
	case "fragment":
		// RawFragment, the escaped form, because Encode has escaped it already. It went
		// in Fragment, which holds the decoded form, so String escaped it again, and a
		// client's script reading location.hash found `iss` still percent-encoded and
		// refused the response as a mix-up. Tests decoded twice and agreed with it; the
		// OIDF Hybrid plan, which decodes once as a browser does, did not. A registered
		// redirect URI has no fragment of its own (RFC 6749 §3.1.2) to keep.
		u.RawFragment = p.values().Encode()
		if u.Fragment, err = url.PathUnescape(u.RawFragment); err != nil {
			http.Error(w, "the authorization response could not be encoded", http.StatusInternalServerError)
			return
		}
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

	// Never cached: renderBare sees to that, and the page contains a single-use
	// code and, in a hybrid response, a signed assertion about who just signed in.
	//
	// No `form-action`, here or on the other bridges. It would have to name the
	// relying party's origin, and Chrome applies it to every redirect the form
	// starts: a callback that goes on to another origin of the relying party's own,
	// as a gateway in front of an application does, is stopped with the code already
	// delivered and the person stranded here. The fields are escaped and nothing but
	// the page's one script runs, so what the directive would add is small.
	s.renderBare(w, r, "formpost", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
		"frame-ancestors 'none'", map[string]any{
		"Action": redirectURI, "Fields": fields, "Nonce": nonce,
	})
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
