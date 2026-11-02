package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// parPerAddressLimit pushed requests are accepted from one address per
// parPerAddressWindow for a public client. Each authorization a person starts
// pushes one, so this is far above a browser's need and bounds a script.
//
// A confidential client is paced per client instead, once it has
// authenticated, at parPerClientLimit. Its pushes come from its own servers,
// often one egress address, and one per sign-in: sixty a minute per address
// capped a relying party at sixty sign-ins a minute, on the endpoint FAPI 2.0
// requires. The client ceiling still bounds what a leaked secret can make this
// server store (each row lives parLifetime).
const (
	parPerAddressLimit  = 60
	parPerAddressWindow = time.Minute
	parPerClientLimit   = 6000
)

// Pushed Authorization Requests (RFC 9126).
//
//	POST /oauth2/par   ->  {"request_uri": "...", "expires_in": 90}
//	GET  /oauth2/authorize?client_id=...&request_uri=...
//
// # The property it buys
//
// An ordinary authorization request is a URL, and a URL is visible: browser
// history, `Referer` headers to every resource the page loads, reverse-proxy
// access logs, the address bar. It is also EDITABLE -- nothing stops whoever
// controls the browser changing `scope` or `redirect_uri` before it arrives.
//
// PAR moves the parameters onto a back channel from an authenticated client.
// What the browser carries is an opaque handle that is single-use, short-lived
// and bound to the client that pushed it.

const (
	// requestURIPrefix is fixed by RFC 9126 §2.2. Clients match on it, and a
	// different prefix means a handle nothing recognises.
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"

	// parLifetime is how long a person has from the client's redirect to the code,
	// which is the whole sign-in, a second factor and a consent screen included,
	// because the handle is spent at the code and not at the first page. Longer is a
	// window in which a captured handle still works, though only for its client and
	// only by somebody who can then sign in. FAPI 2.0 §5.3.2.2 wants under 600.
	parLifetime = 5 * time.Minute

	maxPARBody = 64 << 10
)

// handlePAR accepts a pushed authorization request.
func (s *Server) handlePAR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	// A pushed request is a handful of parameters. Declared from the start and
	// applied to nothing, so a push parsed up to net/http's 10 MB form ceiling.
	r.Body = http.MaxBytesReader(w, r.Body, maxPARBody)
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "the pushed request is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Duplicate parameters are REFUSED, not resolved by taking the first.
	//
	// The rule and its reasoning now live in dupeparams.go, because this was the
	// only endpoint that had it -- and the two that issue a code and a token did
	// not. Moving it also fixed the other half: this loop refused EVERY repeat,
	// including `resource`, which RFC 8707 §2 explicitly permits more than once.
	//
	// Found while writing a test that accidentally sent two, and got a success
	// because the valid one happened to come first.
	if err := refuseDuplicateParams(r.PostForm); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// A `request_uri` in a PUSHED request would be a handle referring to another
	// handle. RFC 9126 §2.1 forbids it, and the reason is worth stating: chained
	// handles make the parameters that will actually be authorized depend on a
	// lookup chain, which is precisely the indirection this endpoint removes.
	if r.PostForm.Get("request_uri") != "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"a pushed request must not itself contain request_uri")
		return
	}

	// Credentials resolved exactly as at the token endpoint. RFC 9126 §2: "The
	// rules for client authentication as defined in [RFC6749] for token
	// endpoint requests, including the applicable authentication methods, apply
	// for the PAR endpoint as well."
	//
	// This read `client_secret` from the form and nothing else, so a client
	// registered for client_secret_basic could not use PAR at all -- while
	// discovery advertised that method, which the same section says covers this
	// endpoint too.
	creds, cerr := oauth.ParseClientCredentials(r.Header, r.PostForm)
	if cerr != nil {
		writeError(w, cerr.Status, cerr.Code, cerr.Description)
		return
	}
	clientID := creds.ClientID
	c, err := s.lookupClient(ctx, clientID)
	if err != nil || c == nil {
		// writeTokenError, not writeError.
		//
		// RFC 9126 §2: "The rules for client authentication as defined in
		// [RFC6749] for token endpoint requests... apply for the PAR endpoint as
		// well." That includes §5.2's requirement that a 401 for `invalid_client`
		// carry a WWW-Authenticate challenge, and RFC 9110 §11.6.1's broader rule
		// that any 401 must carry one at all.
		//
		// `writeTokenError` attaches it; `writeError` does not. The token endpoint
		// used the first and this endpoint used the second, so the same failure
		// answered a challenge in one place and a bare 401 in the other.
		writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
			Description: "unknown client", Status: http.StatusUnauthorized})
		return
	}

	// THE point of the endpoint: the client authenticates here. Without it,
	// anybody could push a request in a client's name and the integrity property
	// would be worth nothing -- the parameters would still be attacker-chosen,
	// just harder to see.
	if c.Type == "confidential" {
		if err := s.authenticateConfidentialClient(ctx, r, c, creds.ClientSecret); err != nil {
			s.log.InfoContext(ctx, "PAR client authentication failed", "client_id", clientID, "err", err,
				"correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
				Description: "client authentication failed", Status: http.StatusUnauthorized})
			return
		}
	}

	// Out of its profile, a client gets nothing to authorize.
	if problems := c.ProfileProblems(); len(problems) > 0 {
		s.log.ErrorContext(ctx, "a client out of its security profile was refused", "client_id", clientID,
			"problems", problems, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusBadRequest, "unauthorized_client", "this client does not meet its security profile")
		return
	}

	// Paced before anything is stored. Every pushed request is a row, and a
	// public client authenticates nothing here, so there was once no limit at
	// all on how many rows a stranger could have this server write: a public
	// client is paced per address. An authenticated confidential client is
	// paced as itself (parPerClientLimit). A failed authentication stores
	// nothing and is metered by the client-authentication budgets.
	why, rerr := s.pushPaced(ctx, r, c)
	if rerr != nil {
		s.log.ErrorContext(ctx, "checking the PAR rate limit", "err", rerr)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "please try again shortly")
		return
	}
	if why != "" {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "temporarily_unavailable", why)
		return
	}

	// A push may be a signed Request Object, whose parameters are then the only ones
	// there are: RFC 9101 §6.3, which is what the client signed.
	signed := false
	if object := r.PostForm.Get("request"); object != "" {
		params, perr := s.requestObjectParams(ctx, c, object)
		if perr != nil {
			s.log.InfoContext(ctx, "pushed request object refused", "client_id", clientID, "err", perr,
				"correlation_id", correlationID(ctx))
			writeError(w, http.StatusBadRequest, "invalid_request_object", perr.Error())
			return
		}
		r.PostForm, signed = params, true
	} else if c.RequireSignedRequest {
		writeError(w, http.StatusBadRequest, "invalid_request", "this client must sign its authorization requests")
		return
	}

	// Validated NOW, with the same rules the authorization endpoint applies.
	// Deferring validation to redemption would let a client push nonsense,
	// receive a handle, and discover the problem in a browser -- where the error
	// has to be rendered to a person instead of returned to the caller that can
	// act on it.
	req := oauth.ParseAuthz(r.PostForm)
	req.ClientID = clientID
	if aerr := oauth.ValidateAuthz(req, c, nil); aerr != nil {
		// Returned as a normal error response, NOT as a redirect. There is no
		// browser here, and redirecting a back-channel caller would be
		// meaningless -- worse, it would echo an unvalidated redirect_uri.
		writeError(w, http.StatusBadRequest, aerr.Code, aerr.Description)
		return
	}
	// As the authorization endpoint would, and here because the redeemed request is
	// all it will see.
	if _, cerr := oauth.CompileClaims(r.PostForm, c); cerr != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", cerr.Error())
		return
	}
	if err := s.checkResources(ctx, s.db, c, c.OrgID, req.Resources); err != nil {
		if refusedTarget(err) {
			writeError(w, http.StatusBadRequest, "invalid_target", err.Error())
			return
		}
		s.log.ErrorContext(ctx, "checking resource indicators", "err", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "please try again shortly")
		return
	}

	// RFC 9449 §10.1, and it is a MUST for us specifically:
	//
	//	"Both mechanisms MUST be supported by an authorization server that
	//	supports PAR and DPoP."
	//
	// The two mechanisms are `dpop_jkt` in the POST body, and a DPoP header on
	// the PAR request itself -- in which case the server "MUST further behave as
	// if the contained public key's thumbprint was provided using dpop_jkt".
	//
	// Supporting only the parameter would make a client that attaches its DPoP
	// header to every authorization-server request -- which §10.1 explicitly
	// exists to accommodate -- silently lose the binding.
	jkt := r.PostForm.Get("dpop_jkt")
	if proofJKT, derr := s.verifyDPoPForRequest(r, ""); errors.Is(derr, errDPoPNonce) {
		s.offerDPoPNonce(w)
		writeError(w, http.StatusBadRequest, "use_dpop_nonce", "this server requires a nonce in the DPoP proof")
		return
	} else if derr != nil {
		writeError(w, http.StatusBadRequest, "invalid_dpop_proof", derr.Error())
		return
	} else if proofJKT != "" {
		// "If both mechanisms are used at the same time, the authorization
		// server MUST reject the request if the JWK Thumbprint in dpop_jkt does
		// not match the public key in the DPoP header."
		if jkt != "" && jkt != proofJKT {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"dpop_jkt does not match the key in the DPoP proof on this request")
			return
		}
		jkt = proofJKT
	}

	// Everything the client sent, kept verbatim.
	//
	// Every VALUE, not the first of each: this was `map[string]string` taking
	// `v[0]`, which meant a repeatable parameter could not survive a push even in
	// principle. With the duplicate rule above now allowing `resource` more than
	// once, storing only the first would have turned an explicit refusal into a
	// silent loss of an audience restriction the client asked for -- strictly
	// worse than the refusal it replaced.
	params := map[string][]string{}
	for k, v := range r.PostForm {
		switch k {
		case "client_secret", "client_assertion", "client_assertion_type", signedRequestMark:
			// Never stored. These authenticate the push and have no business
			// surviving into the authorization, where they would sit in a jsonb
			// column being a credential nobody remembers is there. And the mark is
			// this server's to set: a client sending it would be saying it signed.
			continue
		}
		if len(v) > 0 {
			params[k] = v
		}
	}
	if signed {
		params[signedRequestMark] = []string{"1"}
	}

	handle, err := s.parkRequest(ctx, c, params, jkt)
	if err != nil {
		s.log.ErrorContext(ctx, "storing a pushed request", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSONBody(w, map[string]any{
		"request_uri": handle,
		"expires_in":  int(parLifetime.Seconds()),
	})
}

// signedRequestMark is how a parked request remembers it was a signed Request Object,
// among its parameters, so that a client held to signing is held at the redemption too.
const signedRequestMark = "signari_signed_request_object"

// pushPaced says why a request may not be parked now, empty when it may.
func (s *Server) pushPaced(ctx context.Context, r *http.Request, c *clients.Client) (string, error) {
	key, limit, why := "par:ip:"+budgetIP(clientIP(r)), parPerAddressLimit, "too many pushed requests from this address"
	if c.Type == "confidential" {
		key, limit, why = "par:client:"+c.ClientID, parPerClientLimit, "too many pushed requests from this client"
	}
	res, err := store.AllowRate(ctx, s.db, key, limit, parPerAddressWindow)
	if err != nil {
		return "", err
	}
	if !res.Allowed {
		return why, nil
	}
	return "", nil
}

// parkRequest stores a request's parameters behind a new handle.
func (s *Server) parkRequest(ctx context.Context, c *clients.Client, params map[string][]string, jkt string) (string, error) {
	handle, err := newRequestURI()
	if err != nil {
		return "", err
	}
	blob, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.pushed_requests
			(uri_hash, org_id, client_id, params, expires_at, dpop_jkt)
		VALUES ($1, $2::uuid, $3, $4, now() + $5::interval, NULLIF($6,''))`,
		pushedHash(handle), c.OrgID, c.ClientID, blob, parLifetime.String(), jkt); err != nil {
		return "", err
	}
	return handle, nil
}

// requestObjectParams verifies a client's signed Request Object.
func (s *Server) requestObjectParams(ctx context.Context, c *clients.Client, object string) (url.Values, error) {
	jwks, err := store.ClientJWKS(ctx, s.db, c.ClientID)
	if err != nil {
		return nil, fmt.Errorf("reading the client's keys: %w", err)
	}
	var rules clientauth.RequestObjectRules
	if c.MessageSigning() {
		rules = clientauth.RequestObjectRules{Dated: true, Algorithms: clients.FAPI2Algorithms}
	}
	return clientauth.VerifyRequestObject(object, c.ClientID, jwks, []string{s.cfg.Issuer}, time.Now(), rules)
}

// parkRequestObject verifies a Request Object sent by value and parks what it says,
// answering the handle, or the problem to tell the client. Paced as a push is: it is a
// row each time, and a captured URL can be sent again.
func (s *Server) parkRequestObject(r *http.Request, clientID, requestURI, object string) (handle, problem string) {
	ctx := r.Context()
	// §5: "'request_uri' MUST NOT be present" with `request`, and it would be a handle
	// beside an object, naming two requests.
	if requestURI != "" {
		return "", "send request or request_uri, not both"
	}
	c, err := s.lookupClient(ctx, clientID)
	if err != nil || c == nil {
		return "", "unknown client"
	}
	params, err := s.requestObjectParams(ctx, c, object)
	if err != nil {
		s.log.InfoContext(ctx, "request object refused", "client_id", clientID, "err", err,
			"correlation_id", correlationID(ctx))
		return "", err.Error()
	}
	why, err := s.pushPaced(ctx, r, c)
	if err != nil {
		s.log.ErrorContext(ctx, "checking the PAR rate limit", "err", err)
		return "", "please try again shortly"
	}
	if why != "" {
		return "", why
	}
	params.Del(signedRequestMark)
	stored := map[string][]string(params)
	stored[signedRequestMark] = []string{"1"}
	handle, err = s.parkRequest(ctx, c, stored, "")
	if err != nil {
		s.log.ErrorContext(ctx, "storing a request object", "err", err)
		return "", "please try again shortly"
	}
	return handle, ""
}

// errPushedRequestSpent is a handle that has given a code, or run out.
var errPushedRequestSpent = errors.New("this request_uri has already been used, or has expired")

// pushedHash is what a handle is stored and found by.
func pushedHash(requestURI string) []byte {
	sum := sha256.Sum256([]byte(requestURI))
	return sum[:]
}

// readPushedRequest answers the parameters behind a handle, and leaves it as it found it.
//
// A person arrives at this endpoint several times on one handle: for the sign-in page,
// back from it, back from a second factor, back from the consent screen. Software that
// fetches a link to see what is there arrives too. So the handle is not spent here but in
// the transaction that issues the code, which is the point FAPI 2.0 §5.3.2.2 NOTE 3 names:
// "at the point of authorization, not at the point of loading an authorization page".
func (s *Server) readPushedRequest(ctx context.Context, requestURI, clientID string) (url.Values, error) {
	if !strings.HasPrefix(requestURI, requestURIPrefix) {
		return nil, fmt.Errorf("request_uri is not a pushed request handle")
	}

	var blob []byte
	var storedClient string
	var storedJKT *string
	err := s.db.QueryRow(ctx, `
		SELECT params, client_id, dpop_jkt FROM core.pushed_requests
		WHERE uri_hash = $1 AND used_at IS NULL AND expires_at > now()`,
		pushedHash(requestURI)).Scan(&blob, &storedClient, &storedJKT)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errPushedRequestSpent
		}
		return nil, err
	}

	// Bound to the client that pushed it. Without this check a handle pushed by
	// one client could be redeemed by another -- which would let a client begin
	// an authorization carrying somebody else's registered redirect_uri.
	if storedClient != clientID {
		return nil, fmt.Errorf("this request_uri was issued to a different client")
	}

	var params map[string][]string
	if err := json.Unmarshal(blob, &params); err != nil {
		// A row written by an older build stored one string per name. Pushed
		// requests live 90 seconds, so this can only be seen during a deploy, and
		// refusing is right: the alternative is decoding a request whose shape we
		// are guessing at.
		return nil, fmt.Errorf("this request_uri was stored in an older format; push it again")
	}
	out := url.Values{}
	// The thumbprint from the column wins over any in the stored parameters.
	//
	// Both mechanisms of RFC 9449 §10.1 converge here: `dpop_jkt` sent in the
	// POST body lands in `params`, and a DPoP header on the push lands in the
	// column. The push already refused the case where both were present and
	// disagreed, so by this point they cannot conflict -- and reading the column
	// means a header-only client gets the binding it asked for rather than
	// silently losing it between the push and the authorization request.
	if storedJKT != nil && *storedJKT != "" {
		out.Set("dpop_jkt", *storedJKT)
	}
	for k, v := range params {
		if k == "dpop_jkt" && out.Get("dpop_jkt") != "" {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out, nil
}

// parkedRequest is a parked query as the request it stands for: the query itself, or for
// a pushed request what was pushed, which is the only place its redirect_uri is. A handle
// that opens nothing answers the query, with no redirect_uri to send anybody to.
func (s *Server) parkedRequest(ctx context.Context, authzQuery string) url.Values {
	q := parseQuery(authzQuery)
	handle := q.Get("request_uri")
	if handle == "" {
		return q
	}
	pushed, err := s.readPushedRequest(ctx, handle, q.Get("client_id"))
	if err != nil {
		s.log.InfoContext(ctx, "a parked pushed request could not be read", "err", err, "correlation_id", correlationID(ctx))
		return q
	}
	pushed.Set("client_id", q.Get("client_id"))
	return pushed
}

// answerPrompts says these prompts have been answered, wherever the request is kept:
// taken out of the query a browser carries, or for a pushed request, out of the row. The
// browser's copy of a pushed request holds no prompt to take out, and has no say in it,
// or whoever held the browser could answer prompt=login by editing a URL.
func (s *Server) answerPrompts(ctx context.Context, authzQuery string, answered ...string) string {
	handle := parseQuery(authzQuery).Get("request_uri")
	if handle == "" {
		return consumePrompt(authzQuery, answered...)
	}
	if err := store.AnswerPushedPrompts(ctx, s.db, pushedHash(handle), answered); err != nil {
		s.log.ErrorContext(ctx, "recording an answered prompt", "err", err, "correlation_id", correlationID(ctx))
	}
	return authzQuery
}

// newRequestURI mints an opaque handle.
func newRequestURI() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return requestURIPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// renderAuthzFailure reports a failure that cannot be sent to a redirect_uri.
//
// Everything reaching here failed BEFORE a redirect target was established, so
// there is nowhere to send it except the browser. Rendering through
// html/template, because the reason can contain text derived from what the
// caller supplied.
func (s *Server) renderAuthzFailure(w http.ResponseWriter, r *http.Request, reason string) {
	s.renderPageStatus(w, r, http.StatusBadRequest, "federr", map[string]any{
		"Reason":        reason,
		"CorrelationID": correlationID(r.Context()),
	})
}
