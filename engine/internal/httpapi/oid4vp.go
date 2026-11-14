package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/oid4vp"
	"signari.dev/engine/internal/qr"
	"signari.dev/engine/internal/store"
)

// Signing in with a credential from a wallet (12.12): this server as an OpenID4VP
// verifier, on the same device. The browser is sent to the wallet with a request, the
// wallet posts its presentation to the response URI (direct_post, specs/oid4vp.txt:1341-
// 1446), and the browser comes back with a response code the wallet was handed, which is
// how a presentation posted from somewhere else cannot finish somebody else's sign-in
// (:2022-2037). After that it is the ordinary external-identity path.
//
// With the operator's say-so the wallet may be on another device instead, by a code to
// scan (handleVPStart). That answer cannot be told from one an attacker relayed to
// somebody else's phone, so it finishes only with a code emailed to the linked account's
// own address, typed on the page that began it (handleVPConfirm).

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

// handleVPStart begins a sign-in and sends the browser to the wallet. Where the operator
// lets the wallet be on another device, and the person has not chosen this one, it shows
// a page instead: this device, or a code to scan, whose request is a sign-in of its own
// marked as from another device, so a wallet answering it is never handed a response
// code and only the account's emailed code finishes it.
func (s *Server) handleVPStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")
	s.noteRemember(w, r)
	v, err := s.loadVPVerifier(r, slug)
	if err != nil {
		if !errors.Is(err, store.ErrVPVerifierUnknown) {
			s.log.ErrorContext(ctx, "loading a wallet sign-in", "slug", slug, "err", err)
		}
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}
	clientID, err := s.vpClientID(v)
	if err != nil {
		// The certificate does not name this server's host, which every wallet
		// would refuse: said here, where an operator reads it.
		s.log.ErrorContext(ctx, "a wallet sign-in cannot be offered", "slug", slug, "err", err)
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}
	nonce, err := randomToken()
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	returnTo := s.validFederationReturn(r.URL.Query().Get("return"))
	cross := v.CrossDevice && v.Prefix.Signed() && r.URL.Query().Get("device") != "this"

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	state, binding, err := store.BeginFederatedLogin(ctx, tx, store.PendingLogin{
		ProviderID: v.ProviderID, OrgID: v.OrgID, Nonce: nonce, ReturnTo: returnTo, VPCrossDevice: cross,
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
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}

	target, err := s.vpTarget(v, clientID, nonce, state, responseKey, !cross)
	if err != nil {
		s.log.ErrorContext(ctx, "building the wallet request", "slug", slug, "err", err)
		s.federationRefusal(w, r, "federr.unavailable")
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
	if !cross {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	s.renderVPChoice(w, r, v, state, target, returnTo, "")
}

// vpTarget is the URL that takes a request to the wallet. A signed request goes by
// reference, fetched by POST as the wallet can when byPost, or by GET; an unsigned one
// has every parameter in the URL, since a redirect_uri verifier has nothing to sign with
// (specs/oid4vp.txt:615). A code to scan names the request by GET, as the cross-device
// flow has it (:245): by POST the URL also carries the verifier's metadata (:328),
// which leaves it too long for a code a phone can read across a desk.
func (s *Server) vpTarget(v *store.VPVerifier, clientID, nonce, state string, responseKey []byte,
	byPost bool) (string, error) {
	req, err := s.vpRequest(v, clientID, nonce, state, "", responseKey)
	if err != nil {
		return "", err
	}
	requestURI := ""
	if v.Prefix.Signed() {
		requestURI = s.vpBase(v.Slug) + "/request/" + url.PathEscape(state)
	}
	return req.URL(v.WalletURL, requestURI, v.Prefix.Signed() && byPost)
}

// renderVPChoice is the page a cross-device wallet sign-in starts on: the wallet on this
// device, which begins a sign-in of its own, or target as a code to scan with the wallet
// on another, which this page then waits on. notice is a key said above both, or "".
func (s *Server) renderVPChoice(w http.ResponseWriter, r *http.Request, v *store.VPVerifier, state, target,
	returnTo, notice string) {
	base := "/oid4vp/" + url.PathEscape(v.Slug)
	here := base + "/start?device=this"
	if returnTo != "" {
		here += "&return=" + url.QueryEscape(returnTo)
	}
	data := map[string]any{"Mode": "choose", "Provider": v.DisplayName, "HereURL": here,
		"WaitURL": base + "/wait?" + url.Values{"state": {state}}.Encode(),
		"NextURL": base + "/confirm?" + url.Values{"state": {state}}.Encode(), "WalletScript": true}
	if notice != "" {
		data["Notice"] = s.tr(r).Text(notice)
	}
	// The code is the other device's only way in, and a request too long for one
	// leaves this device alone, said in the log where an operator reads it.
	if code, err := qr.Encode([]byte(target)); err == nil {
		// template.HTML because the encoder writes this SVG from a matrix of booleans:
		// integers in coordinates, and nothing of the request's text.
		data["QR"] = template.HTML(code.SVG(4, 4))
	} else {
		s.log.WarnContext(r.Context(), "a wallet request does not fit a code to scan", "slug", v.Slug, "err", err)
	}
	s.renderPage(w, r, "wallet", data)
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
	pending, err := store.PendingVPRequest(ctx, s.db, s.cfg.Root, v.ProviderID, state)
	if err != nil {
		if !errors.Is(err, store.ErrVPRequestGone) {
			s.log.ErrorContext(ctx, "reading a wallet request", "err", err)
		}
		http.NotFound(w, r)
		return
	}
	nonce, responseKey := pending.Nonce, pending.ResponseKey
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
	// Refused is a cross-device request the wallet declined, kept so the page waiting
	// on it can say so rather than wait out the ten minutes.
	Refused bool `json:"refused,omitempty"`
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
	pending, err := store.PendingVPRequest(ctx, s.db, s.cfg.Root, v.ProviderID, state)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "this request has expired or has been answered")
		return
	}
	nonce, responseKey := pending.Nonce, pending.ResponseKey
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
		if pending.CrossDevice {
			// The browser to tell is on the device the sign-in began on, and learns
			// it from what is kept here.
			if err := store.PresentVPCrossDevice(ctx, s.db, s.cfg.Root, v.ProviderID, state,
				[]byte(`{"refused":true}`)); err != nil {
				s.log.InfoContext(ctx, "keeping a wallet's refusal", "slug", slug, "err", err)
			}
			writeJSON(w, http.StatusOK, map[string]string{})
			return
		}
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
		Ask: v.Ask(), Issuers: v.Issuers, FromMetadata: v.IssuersFromMetadata, Anchors: v.IssuerRoots, Now: time.Now(),
		Fetch: func(uri, accept string) ([]byte, string, error) { return s.fetchForVerifier(ctx, uri, accept) }})
	if err == nil {
		var proved []byte
		if proved, err = vpIdentity(v, presented); err == nil && pending.CrossDevice {
			// No redirect_uri: the wallet's browser is not the one that began this,
			// so "processing at the Wallet stops" (:1912), and the page that began it
			// finishes with the account's emailed code.
			if err = store.PresentVPCrossDevice(ctx, s.db, s.cfg.Root, v.ProviderID, state, proved); err == nil {
				w.Header().Set("Cache-Control", "no-store")
				writeJSON(w, http.StatusOK, map[string]string{})
				return
			}
		} else if err == nil {
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
// credential names (specs/token-status-list.txt:730-750), a believed issuer's JWT VC
// Issuer Metadata and key set (specs/sdjwtvc.txt:1140-1170), or a CRL its certificates
// name (specs/rfc5280.txt:2554-2558). Through the outbound
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
		s.federationRefusal(w, r, "federr.linkincomplete")
		return
	}
	c, err := r.Cookie(FederationCookieName)
	if err != nil || c.Value == "" {
		s.federationRefusal(w, r, "federr.otherbrowser")
		return
	}
	s.clearFederationCookie(w)

	v, err := s.loadVPVerifier(r, slug)
	if err != nil {
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	pending, err := store.ConsumeFederatedLogin(ctx, tx, state, c.Value)
	if err != nil {
		_ = tx.Rollback(ctx)
		s.log.InfoContext(ctx, "a wallet sign-in was refused", "slug", slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationRefusal(w, r, federatedLoginRefusal(err))
		return
	}
	if pending.ProviderID != v.ProviderID {
		_ = tx.Rollback(ctx)
		s.federationRefusal(w, r, "federr.linkmismatch")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	if q.Get("error") != "" {
		s.federationRefusal(w, r, "federr.cancelled")
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
		s.federationRefusal(w, r, "federr.unverified")
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

// handleVPWait answers the page a cross-device sign-in began on, which asks every few
// seconds whether the wallet has answered. Only for the browser holding the sign-in's
// cookie; nothing is started or spent by asking.
func (s *Server) handleVPWait(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	c, err := r.Cookie(FederationCookieName)
	v, verr := s.loadVPVerifier(r, r.PathValue("slug"))
	if err != nil || c.Value == "" || verr != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"gone": true})
		return
	}
	_, _, err = store.VPCrossDeviceAnswer(ctx, s.db, s.cfg.Root, v.ProviderID, r.URL.Query().Get("state"), c.Value)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"answered": true})
	case errors.Is(err, store.ErrVPNotAnswered):
		writeJSON(w, http.StatusOK, map[string]bool{"answered": false})
	default:
		if !errors.Is(err, store.ErrFederatedLoginGone) && !errors.Is(err, store.ErrFederatedLoginOtherBrowser) {
			s.log.ErrorContext(ctx, "reading a cross-device answer", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]bool{"gone": true})
	}
}

// vpCrossDeviceAccount is the active account a cross-device answer signs in: the one
// already linked to its subject at this provider, with an address to send the code to.
// "" for anybody else, since a code can only go to an account's own address, and an
// account made from the answer would have none it had shown was its own.
func (s *Server) vpCrossDeviceAccount(ctx context.Context, v *store.VPVerifier, subject string) (string, error) {
	var userID string
	err := s.db.QueryRow(ctx, `
		SELECT u.id::text FROM core.federated_identities f JOIN core.users u ON u.id = f.user_id
		WHERE f.provider_id = $1::uuid AND f.subject = $2 AND u.org_id = $3::uuid AND u.status = 'active'
		  AND u.email IS NOT NULL`, v.ProviderID, subject, v.OrgID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return userID, err
}

// handleVPConfirmPage is where the waiting page goes once the wallet has answered: the
// linked account is sent its code, once, and the page asks for it. Asked before the
// wallet answered, it is the waiting page again.
func (s *Server) handleVPConfirmPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	c, err := r.Cookie(FederationCookieName)
	if err != nil || c.Value == "" || state == "" {
		s.federationRefusal(w, r, "federr.otherbrowser")
		return
	}
	v, err := s.loadVPVerifier(r, r.PathValue("slug"))
	if err != nil {
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}
	raw, _, err := store.VPCrossDeviceAnswer(ctx, s.db, s.cfg.Root, v.ProviderID, state, c.Value)
	if errors.Is(err, store.ErrVPNotAnswered) {
		s.renderVPWaitingAgain(w, r, v, state)
		return
	}
	_, userID, key := s.vpCrossDeviceProved(ctx, v, raw, err)
	if key != "" {
		s.federationRefusal(w, r, key)
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sent, err := store.StartVPConfirmation(ctx, tx, userID, v.OrgID, v.ProviderID, state)
	if err == nil && sent {
		err = audit.Write(ctx, tx, audit.Event{Type: "federation.wallet_code_sent", OrgID: v.OrgID, SubjectID: userID,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"provider": v.Slug}})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "sending a cross-device wallet code", "slug", v.Slug, "err", err)
		s.federationRefusal(w, r, federatedLoginRefusal(err))
		return
	}
	s.renderVPCode(w, r, v, state, "")
}

// vpCrossDeviceProved reads what a cross-device answer proved and the account it signs
// in, or the key of the refusal to show.
func (s *Server) vpCrossDeviceProved(ctx context.Context, v *store.VPVerifier, raw []byte, err error) (
	vpProved, string, string) {
	var proved vpProved
	if err != nil {
		if !errors.Is(err, store.ErrFederatedLoginGone) && !errors.Is(err, store.ErrFederatedLoginOtherBrowser) {
			s.log.ErrorContext(ctx, "reading a cross-device answer", "slug", v.Slug, "err", err)
		}
		return proved, "", federatedLoginRefusal(err)
	}
	if err := json.Unmarshal(raw, &proved); err != nil {
		return proved, "", "federr.unverified"
	}
	if proved.Refused {
		return proved, "", "federr.cancelled"
	}
	userID, err := s.vpCrossDeviceAccount(ctx, v, proved.Subject)
	if err != nil {
		s.log.ErrorContext(ctx, "finding a cross-device answer's account", "slug", v.Slug, "err", err)
		return proved, "", "federr.generic"
	}
	if userID == "" {
		s.log.InfoContext(ctx, "a cross-device answer names no account with an address", "slug", v.Slug,
			"correlation_id", correlationID(ctx))
		return proved, "", "federr.crossnoaccount"
	}
	return proved, userID, ""
}

// renderVPWaitingAgain is the waiting page for a request the wallet has not answered,
// its code made again from what was kept.
func (s *Server) renderVPWaitingAgain(w http.ResponseWriter, r *http.Request, v *store.VPVerifier, state string) {
	ctx := r.Context()
	pending, err := store.PendingVPRequest(ctx, s.db, s.cfg.Root, v.ProviderID, state)
	var clientID, target string
	if err == nil {
		clientID, err = s.vpClientID(v)
	}
	if err == nil {
		target, err = s.vpTarget(v, clientID, pending.Nonce, state, pending.ResponseKey, false)
	}
	if err != nil {
		s.federationRefusal(w, r, federatedLoginRefusal(err))
		return
	}
	s.renderVPChoice(w, r, v, state, target, "", "wallet.notyet")
}

// renderVPCode is the page that takes the code sent to the account.
func (s *Server) renderVPCode(w http.ResponseWriter, r *http.Request, v *store.VPVerifier, state, msg string) {
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	s.renderPage(w, r, "wallet", map[string]any{"Mode": "code", "Provider": v.DisplayName, "State": state,
		"Action": "/oid4vp/" + url.PathEscape(v.Slug) + "/confirm", "Error": msg,
		"CSRF": csrf, "CSRFField": csrfFormField})
}

// handleVPConfirm takes the code sent to the account and, with it, finishes the
// cross-device sign-in as that account and no other: the ordinary external-identity
// path, told which account it must end at.
func (s *Server) handleVPConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	state := r.PostForm.Get("state")
	c, err := r.Cookie(FederationCookieName)
	if err != nil || c.Value == "" || state == "" {
		s.federationRefusal(w, r, "federr.otherbrowser")
		return
	}
	v, err := s.loadVPVerifier(r, r.PathValue("slug"))
	if err != nil {
		s.federationRefusal(w, r, "federr.unavailable")
		return
	}
	raw, attempt, err := store.VPCrossDeviceAnswer(ctx, s.db, s.cfg.Root, v.ProviderID, state, c.Value)
	if err == nil && attempt == "" {
		err = store.ErrVPNotAnswered
	}
	if errors.Is(err, store.ErrVPNotAnswered) {
		s.renderVPWaitingAgain(w, r, v, state)
		return
	}
	proved, userID, key := s.vpCrossDeviceProved(ctx, v, raw, err)
	if key != "" {
		s.federationRefusal(w, r, key)
		return
	}
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	// The second-factor budget, keyed by the account the code is for: whoever holds
	// this page is the one guessing.
	if !s.allowSecondFactorAttempt(ctx, w, userID, ip) {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ok, err := store.VerifyEmailSignIn(ctx, tx, userID, attempt, strings.TrimSpace(r.PostForm.Get("code")))
	if err != nil {
		s.log.ErrorContext(ctx, "checking a cross-device wallet code", "err", err)
		s.federationRefusal(w, r, "federr.generic")
		return
	}
	if !ok {
		// Committed: the count against the code outlives the refusal.
		if err := tx.Commit(ctx); err != nil {
			s.log.ErrorContext(ctx, "committing a wrong cross-device wallet code", "err", err)
		}
		s.recordSecondFactorFailure(ctx, userID, ip)
		s.auditDetached(ctx, audit.Event{Type: audit.EventLoginFailed, OrgID: v.OrgID, SubjectID: userID,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"reason": "bad_wallet_code", "provider": v.Slug}})
		s.renderVPCode(w, r, v, state, s.tr(r).Text("wallet.code.wrong"))
		return
	}
	pending, err := store.ConsumeFederatedLogin(ctx, tx, state, c.Value)
	if err == nil && pending.ProviderID != v.ProviderID {
		err = store.ErrFederatedLoginGone
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.log.InfoContext(ctx, "a cross-device wallet sign-in was refused", "slug", v.Slug, "err", err,
			"correlation_id", correlationID(ctx))
		s.federationRefusal(w, r, federatedLoginRefusal(err))
		return
	}
	s.clearFederationCookie(w)
	pending.RequireUserID = userID
	s.completeFederation(w, r, &federation.Config{
		ID: v.ProviderID, OrgID: v.OrgID, Slug: v.Slug, DisplayName: v.DisplayName,
		Policy: v.Policy, Kind: federation.KindOID4VP,
	}, pending, federation.ExternalIdentity{
		Subject: proved.Subject, Email: proved.Email, Name: proved.Name,
		EmailVerified: proved.Email != "" && v.Policy.TrustsEmailVerification,
		RawClaims:     proved.Claims,
	})
}
