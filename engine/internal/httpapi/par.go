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

	"signari.dev/engine/internal/oauth"
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

	// parLifetime is short because the handle is used immediately -- the client
	// redirects the browser as soon as it has one. Anything longer is a window
	// in which a captured handle still works.
	parLifetime = 90 * time.Second

	maxPARBody = 64 << 10
)

// handlePAR accepts a pushed authorization request.
func (s *Server) handlePAR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Duplicate parameters are REFUSED, not resolved by taking the first.
	//
	// RFC 6749 §3.1: a request must not include a parameter more than once. The
	// tempting behaviour -- take the first, ignore the rest -- is parameter
	// pollution: whether the first or the last wins differs between servers,
	// proxies and libraries, so a request carrying two `redirect_uri` values can
	// be validated against one and acted on with the other.
	//
	// Found while writing a test that accidentally sent two, and got a success
	// because the valid one happened to come first.
	for name, values := range r.PostForm {
		if len(values) > 1 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("the parameter %q appears %d times; each may appear at most once",
					name, len(values)))
			return
		}
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

	clientID := r.PostForm.Get("client_id")
	c, err := s.lookupClient(ctx, clientID)
	if err != nil || c == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}

	// THE point of the endpoint: the client authenticates here. Without it,
	// anybody could push a request in a client's name and the integrity property
	// would be worth nothing -- the parameters would still be attacker-chosen,
	// just harder to see.
	if c.Type == "confidential" {
		if err := s.authenticateConfidentialClient(ctx, r, c, r.PostForm.Get("client_secret")); err != nil {
			s.log.Info("PAR client authentication failed", "client_id", clientID, "err", err,
				"correlation_id", correlationID(ctx))
			writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}

	// Validated NOW, with the same rules the authorization endpoint applies.
	// Deferring validation to redemption would let a client push nonsense,
	// receive a handle, and discover the problem in a browser -- where the error
	// has to be rendered to a person instead of returned to the caller that can
	// act on it.
	req := oauth.AuthzRequest{
		ClientID:            clientID,
		RedirectURI:         r.PostForm.Get("redirect_uri"),
		ResponseType:        r.PostForm.Get("response_type"),
		Scope:               r.PostForm.Get("scope"),
		State:               r.PostForm.Get("state"),
		Nonce:               r.PostForm.Get("nonce"),
		CodeChallenge:       r.PostForm.Get("code_challenge"),
		CodeChallengeMethod: r.PostForm.Get("code_challenge_method"),
	}
	if aerr := oauth.ValidateAuthz(req, c, nil); aerr != nil {
		// Returned as a normal error response, NOT as a redirect. There is no
		// browser here, and redirecting a back-channel caller would be
		// meaningless -- worse, it would echo an unvalidated redirect_uri.
		writeError(w, http.StatusBadRequest, aerr.Code, aerr.Description)
		return
	}

	// Everything the client sent, kept verbatim.
	params := map[string]string{}
	for k, v := range r.PostForm {
		switch k {
		case "client_secret", "client_assertion", "client_assertion_type":
			// Never stored. These authenticate the push and have no business
			// surviving into the authorization, where they would sit in a jsonb
			// column being a credential nobody remembers is there.
			continue
		}
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	handle, err := newRequestURI()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	blob, err := json.Marshal(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	sum := sha256.Sum256([]byte(handle))
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.pushed_requests (uri_hash, org_id, client_id, params, expires_at)
		VALUES ($1, $2::uuid, $3, $4, now() + $5::interval)`,
		sum[:], c.OrgID, clientID, blob, parLifetime.String()); err != nil {
		s.log.Error("storing a pushed request", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSONBody(w, map[string]any{
		"request_uri": handle,
		"expires_in":  int(parLifetime.Seconds()),
	})
}

// consumePushedRequest redeems a handle at the authorization endpoint.
//
// Returns the pushed parameters. Single use, enforced in the same statement
// that reads, so two concurrent redemptions cannot both succeed.
func (s *Server) consumePushedRequest(ctx context.Context, requestURI, clientID string) (url.Values, error) {
	if !strings.HasPrefix(requestURI, requestURIPrefix) {
		return nil, fmt.Errorf("request_uri is not a pushed request handle")
	}
	sum := sha256.Sum256([]byte(requestURI))

	var blob []byte
	var storedClient string
	err := s.db.QueryRow(ctx, `
		UPDATE core.pushed_requests
		SET used_at = now()
		WHERE uri_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING params, client_id`, sum[:]).Scan(&blob, &storedClient)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("this request_uri has already been used, or has expired")
		}
		return nil, err
	}

	// Bound to the client that pushed it. Without this check a handle pushed by
	// one client could be redeemed by another -- which would let a client begin
	// an authorization carrying somebody else's registered redirect_uri.
	if storedClient != clientID {
		return nil, fmt.Errorf("this request_uri was issued to a different client")
	}

	var params map[string]string
	if err := json.Unmarshal(blob, &params); err != nil {
		return nil, err
	}
	out := url.Values{}
	for k, v := range params {
		out.Set(k, v)
	}
	return out, nil
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

// clientRequiresPAR reports whether a client may only start through PAR.
func (s *Server) clientRequiresPAR(ctx context.Context, clientID string) (bool, error) {
	var required bool
	err := s.db.QueryRow(ctx,
		`SELECT require_pushed_authorization FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&required)
	return required, err
}

// renderAuthzFailure reports a failure that cannot be sent to a redirect_uri.
//
// Everything reaching here failed BEFORE a redirect target was established, so
// there is nowhere to send it except the browser. Rendering through
// html/template, because the reason can contain text derived from what the
// caller supplied.
func (s *Server) renderAuthzFailure(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = federationErrorPage.Execute(w, map[string]string{
		"Reason":        reason,
		"CorrelationID": correlationID(r.Context()),
	})
}
