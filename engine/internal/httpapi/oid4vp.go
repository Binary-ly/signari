package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/oid4vp"
	"signari.dev/engine/internal/store"
)

// Signing in with a credential from a wallet (12.12): this server as an OpenID4VP
// verifier, on the same device. The browser is sent to the wallet with a request, the
// wallet posts its presentation to the response URI (direct_post, specs/oid4vp.txt:1341-
// 1446), and the browser comes back with a response code the wallet was handed, which is
// how a presentation posted from somewhere else cannot finish somebody else's sign-in
// (:2022-2037). After that it is the ordinary external-identity path.
//
// Same device only. A cross-device sign-in needs a page with a code to scan and words to
// go with it, and this server writes no words a person has not, in either language.

// vpBodyLimit bounds what a wallet may post: a credential, its disclosures and a
// key binding, with room for a certificate chain in a header.
const vpBodyLimit = 256 << 10

func (s *Server) vpBase(slug string) string {
	return s.cfg.Issuer + "/oid4vp/" + url.PathEscape(slug)
}

// loadVPVerifier is store.LoadVPVerifier among this instance's organisations.
func (s *Server) loadVPVerifier(r *http.Request, slug string) (*store.VPVerifier, error) {
	v, err := store.LoadVPVerifier(r.Context(), s.db, s.cfg.Root, slug)
	if err == nil && !s.ownedBy(r.Context(), s.db, v.OrgID, "wallet sign-in") {
		return nil, store.ErrVPVerifierUnknown
	}
	return v, err
}

// vpClientID is the verifier's whole client identifier, which a key binding's aud is
// held to.
func (s *Server) vpClientID(v *store.VPVerifier) (string, error) {
	var leaf *x509.Certificate
	if len(v.Chain) > 0 {
		leaf = v.Chain[0]
	}
	return oid4vp.ClientID(v.Prefix, s.vpBase(v.Slug)+"/response", leaf)
}

// vpRequest is the request a wallet is sent. responseKey is the PKCS #8 key its answer
// is encrypted to under direct_post.jwt, named by the state so the answer says which
// request it is, and nil otherwise.
func (s *Server) vpRequest(v *store.VPVerifier, clientID, nonce, state, walletNonce string,
	responseKey []byte) (oid4vp.Request, error) {
	req := oid4vp.Request{ClientID: clientID, ResponseURI: s.vpBase(v.Slug) + "/response",
		ResponseMode: v.ResponseMode, Nonce: nonce, State: state, WalletNonce: walletNonce, Ask: v.Ask()}
	if responseKey != nil {
		k, err := oid4vp.ParseResponseKey(responseKey)
		if err != nil {
			return req, err
		}
		req.EncryptTo = oid4vp.ResponseJWK(&k.PublicKey, state)
	}
	return req, nil
}

// handleVPStart begins a sign-in and sends the browser to the wallet.
func (s *Server) handleVPStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	s.noteRemember(w, r)
	v, err := s.loadVPVerifier(r, slug)
	if err != nil {
		if !errors.Is(err, store.ErrVPVerifierUnknown) {
			s.log.ErrorContext(ctx, "loading a wallet sign-in", "slug", slug, "err", err)
		}
		s.federationError(w, r, "That sign-in method is not available.")
		return
	}
	clientID, err := s.vpClientID(v)
	if err != nil {
		// The certificate does not name this server's host, which every wallet
		// would refuse: said here, where an operator reads it.
		s.log.ErrorContext(ctx, "a wallet sign-in cannot be offered", "slug", slug, "err", err)
		s.federationError(w, r, "That sign-in method is not available.")
		return
	}
	nonce, err := randomToken()
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	state, binding, err := store.BeginFederatedLogin(ctx, tx, store.PendingLogin{
		ProviderID: v.ProviderID, OrgID: v.OrgID, Nonce: nonce,
		ReturnTo: s.validFederationReturn(r.URL.Query().Get("return")),
	})
	// An answer encrypted to a key of this request's own, so one key never opens two
	// people's answers.
	var responseKey []byte
	if err == nil && v.ResponseMode == oid4vp.ModeDirectPostJWT {
		if responseKey, _, err = oid4vp.NewResponseKey(state); err == nil {
			err = store.SetVPResponseKey(ctx, tx, s.cfg.Root, v.ProviderID, state, responseKey)
		}
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		s.log.ErrorContext(ctx, "beginning a wallet sign-in", "err", err)
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}

	req, err := s.vpRequest(v, clientID, nonce, state, "", responseKey)
	if err != nil {
		s.log.ErrorContext(ctx, "building the wallet request", "slug", slug, "err", err)
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	// A signed request goes by reference, fetched by GET or by POST as the wallet
	// can; an unsigned one has every parameter in the URL, since a redirect_uri
	// verifier has nothing to sign with (specs/oid4vp.txt:615).
	requestURI := ""
	if v.Prefix.Signed() {
		requestURI = s.vpBase(slug) + "/request/" + url.PathEscape(state)
	}
	target, err := req.URL(v.WalletURL, requestURI, v.Prefix.Signed())
	if err != nil {
		s.log.ErrorContext(ctx, "building the wallet request", "slug", slug, "err", err)
		s.federationError(w, r, "That sign-in method is not available.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: FederationCookieName, Value: binding, Path: "/",
		Secure: true, HttpOnly: true,
		// Lax, as for any provider: the wallet sends the browser back with a
		// top-level GET.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// handleVPRequest answers a wallet fetching a signed request object, by GET as JAR has
// it or by POST with its own nonce (specs/oid4vp.txt:680-743). It may be fetched more
// than once: nothing in it is a secret the wallet does not already hold.
func (s *Server) handleVPRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.loadVPVerifier(r, r.PathValue("slug"))
	if err != nil || !v.Prefix.Signed() {
		http.NotFound(w, r)
		return
	}
	state := r.PathValue("state")
	nonce, responseKey, err := store.PendingVPRequest(ctx, s.db, s.cfg.Root, v.ProviderID, state)
	if err != nil {
		if !errors.Is(err, store.ErrVPRequestGone) {
			s.log.ErrorContext(ctx, "reading a wallet request", "err", err)
		}
		http.NotFound(w, r)
		return
	}
	walletNonce := ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, vpBodyLimit)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "the body is not a form")
			return
		}
		// Echoed in the request object, so the wallet can tell this answer
		// from a replayed one (:692-694). Its own value, so it is bounded and
		// otherwise taken as it comes.
		if walletNonce = r.PostForm.Get("wallet_nonce"); len(walletNonce) > 256 {
			writeError(w, http.StatusBadRequest, "invalid_request", "wallet_nonce is too long")
			return
		}
	}
	clientID, err := s.vpClientID(v)
	if err != nil {
		s.log.ErrorContext(ctx, "a wallet sign-in cannot be offered", "slug", v.Slug, "err", err)
		http.NotFound(w, r)
		return
	}
	req, err := s.vpRequest(v, clientID, nonce, state, walletNonce, responseKey)
	var signed string
	if err == nil {
		signed, err = oid4vp.Sign(req.Parameters(time.Now()), v.Key, v.Chain)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "signing a wallet request", "slug", v.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "the request could not be signed")
		return
	}
	// "the content type application/oauth-authz-req+jwt" (:718).
	w.Header().Set("Content-Type", "application/"+oid4vp.TypRequest)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(signed))
}

// vpProved is what a presentation proved, as it waits for the browser: who the person
// is within the issuer, what the operator reads, and the claims for the mappings.
type vpProved struct {
	Subject string          `json:"sub"`
	Email   string          `json:"email,omitempty"`
	Name    string          `json:"name,omitempty"`
	Claims  json.RawMessage `json:"claims"`
}

// handleVPResponse is the response URI: a wallet posts its presentation here, and it is
// checked now, so a presentation that fails is refused to the wallet with a 4xx rather
// than accepted and failed later out of its sight.
func (s *Server) handleVPResponse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	r.Body = http.MaxBytesReader(w, r.Body, vpBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the body is not a form")
		return
	}
	v, err := s.loadVPVerifier(r, slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid_request", "no such verifier")
		return
	}
	// An encrypted answer carries its state inside, and names the request's key, which
	// is the state too, in its header (:1458).
	state := r.PostForm.Get("state")
	var encrypted *jose.JSONWebEncryption
	if jwe := r.PostForm.Get("response"); jwe != "" {
		if encrypted, err = oid4vp.ParseResponse(jwe); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "the response is not one this verifier can open")
			return
		}
		state = encrypted.Header.KeyID
	}
	// "checking that the value of the received state parameter corresponds to a
	// recent Authorization Request" (:2045-2047), before anything is verified, so
	// nobody without a live request can make this server check signatures.
	nonce, responseKey, err := store.PendingVPRequest(ctx, s.db, s.cfg.Root, v.ProviderID, state)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "this request has expired or has been answered")
		return
	}
	vpToken := r.PostForm.Get("vp_token")
	switch {
	case encrypted != nil && responseKey == nil:
		writeError(w, http.StatusBadRequest, "invalid_request", "this request did not ask for an encrypted answer")
		return
	case encrypted != nil:
		key, kerr := oid4vp.ParseResponseKey(responseKey)
		if kerr == nil {
			vpToken, kerr = oid4vp.OpenResponse(encrypted, key, state, state)
		}
		if kerr != nil {
			s.log.InfoContext(ctx, "an encrypted answer was refused", "slug", slug, "err", kerr,
				"correlation_id", correlationID(ctx))
			writeError(w, http.StatusBadRequest, "invalid_request", "the response is not one this verifier can open")
			return
		}
	case responseKey != nil && vpToken != "":
		// Asked for encrypted, so a credential sent in clear is refused: only an
		// error may come unencrypted (:1574).
		writeError(w, http.StatusBadRequest, "invalid_request", "this request asked for an encrypted answer")
		return
	}
	// /oid4vp/<slug>/done, which the wallet sends the browser back to.
	done := s.vpBase(slug) + "/done" + "?" + url.Values{"state": {state}}.Encode()

	if e := r.PostForm.Get("error"); e != "" {
		// Processed, so a 200 (:1415), and the browser is sent back to be told.
		// The wallet's text is not shown to anybody: it is the wallet's to choose.
		s.log.InfoContext(ctx, "a wallet refused", "slug", slug, "error", e, "correlation_id", correlationID(ctx))
		writeJSON(w, http.StatusOK, map[string]string{"redirect_uri": done + "&error=" + url.QueryEscape("access_denied")})
		return
	}

	clientID, err := s.vpClientID(v)
	if err != nil {
		s.log.ErrorContext(ctx, "a wallet sign-in cannot be offered", "slug", slug, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "this verifier is not configured")
		return
	}
	presented, err := oid4vp.Verify(vpToken, oid4vp.Expect{ClientID: clientID, Nonce: nonce,
		Ask: v.Ask(), Issuers: v.Issuers, FromMetadata: v.IssuersFromMetadata, Now: time.Now(),
		Fetch: func(uri, accept string) ([]byte, string, error) { return s.fetchForVerifier(ctx, uri, accept) }})
	if err == nil {
		var proved []byte
		if proved, err = vpIdentity(v, presented); err == nil {
			var code string
			code, err = store.PresentVP(ctx, s.db, v.ProviderID, state, proved)
			if err == nil {
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, http.StatusOK, map[string]string{
					"redirect_uri": done + "&response_code=" + url.QueryEscape(code)})
				return
			}
		}
	}
	s.log.InfoContext(ctx, "a presentation was refused", "slug", slug, "err", err,
		"correlation_id", correlationID(ctx))
	writeError(w, http.StatusBadRequest, "invalid_request", "the presentation was not accepted")
}

// What the verifier fetches is read within this long, and no larger than this. A status
// list of a million credentials at eight bits is a megabyte before compression.
const (
	verifierFetchTimeout = 10 * time.Second
	verifierFetchLimit   = 4 << 20
)

// fetchForVerifier GETs what a presentation's check needs: the Status List Token a
// credential names (specs/token-status-list.txt:730-750), or a believed issuer's JWT VC
// Issuer Metadata and key set (specs/sdjwtvc.txt:1140-1170). Through the outbound
// dialler, so an address in the private network is refused unless an operator named it.
func (s *Server) fetchForVerifier(ctx context.Context, uri, accept string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, verifierFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", accept)
	resp, err := s.outboundClient(verifierFetchTimeout).Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	// A status list "MUST use an HTTP status code in the 2xx range"
	// (specs/token-status-list.txt:754); metadata "MUST use an HTTP 200"
	// (specs/sdjwtvc.txt:1168).
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", fmt.Errorf("%s answered %d", uri, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, verifierFetchLimit+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > verifierFetchLimit {
		return nil, "", fmt.Errorf("%s is larger than %d bytes", uri, verifierFetchLimit)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// vpIdentity is who a verified presentation says the person is.
func vpIdentity(v *store.VPVerifier, p *oid4vp.Presented) ([]byte, error) {
	subject, err := vpScalar(p.Claims, v.Subject)
	if err != nil || subject == "" {
		return nil, fmt.Errorf("the claim that identifies the person: %w", err)
	}
	out := vpProved{Subject: store.VPSubject(p.Issuer, subject)}
	if v.Email != nil {
		if out.Email, err = vpScalar(p.Claims, v.Email); err != nil {
			return nil, err
		}
	}
	if v.Name != nil {
		if out.Name, err = vpScalar(p.Claims, v.Name); err != nil {
			return nil, err
		}
	}
	if out.Claims, err = json.Marshal(p.Claims); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// vpScalar is the one string or number a path selects. A list or an object does not
// identify anybody or address them.
func vpScalar(claims map[string]any, path oid4vp.Path) (string, error) {
	got, err := oid4vp.Select(claims, path)
	if err != nil {
		return "", err
	}
	if len(got) != 1 {
		return "", fmt.Errorf("%s selects %d values", path, len(got))
	}
	switch t := got[0].(type) {
	case string:
		return t, nil
	case json.Number:
		return t.String(), nil
	}
	return "", fmt.Errorf("%s is not a string or a number", path)
}

// handleVPDone is where the wallet sends the browser back, with the code it was handed.
// The pending sign-in is consumed with this browser's cookie, as any provider's
// callback is, and the presentation opened with the code.
func (s *Server) handleVPDone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" || (q.Get("response_code") == "" && q.Get("error") == "") {
		s.federationError(w, r, "That sign-in link is incomplete.")
		return
	}
	c, err := r.Cookie(FederationCookieName)
	if err != nil || c.Value == "" {
		s.federationError(w, r, "This sign-in was started in a different browser, or the "+
			"link is more than ten minutes old. Please try again.")
		return
	}
	s.clearFederationCookie(w)

	v, err := s.loadVPVerifier(r, slug)
	if err != nil {
		s.federationError(w, r, "That sign-in method is not available.")
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	pending, err := store.ConsumeFederatedLogin(ctx, tx, state, c.Value)
	if err != nil {
		_ = tx.Rollback(ctx)
		s.log.InfoContext(ctx, "a wallet sign-in was refused", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, err.Error())
		return
	}
	if pending.ProviderID != v.ProviderID {
		_ = tx.Rollback(ctx)
		s.federationError(w, r, "That sign-in link does not match this provider.")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	if q.Get("error") != "" {
		s.federationError(w, r, "The sign-in was cancelled or refused by the provider.")
		return
	}

	raw, err := store.OpenVPPresentation(pending, q.Get("response_code"))
	var proved vpProved
	if err == nil {
		err = json.Unmarshal(raw, &proved)
	}
	if err != nil {
		s.log.InfoContext(ctx, "a wallet sign-in's presentation could not be opened", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationError(w, r, "The provider's response could not be verified.")
		return
	}
	s.completeFederation(w, r, &federation.Config{
		ID: v.ProviderID, OrgID: v.OrgID, Slug: v.Slug, DisplayName: v.DisplayName,
		Policy: v.Policy, Kind: federation.KindOID4VP,
	}, pending, federation.ExternalIdentity{
		Subject: proved.Subject, Email: proved.Email, Name: proved.Name,
		// The issuer attested the address, and whether that counts as
		// verified is the operator's to say, as for a SAML upstream.
		EmailVerified: proved.Email != "" && v.Policy.TrustsEmailVerification,
		RawClaims:     proved.Claims,
	})
}
