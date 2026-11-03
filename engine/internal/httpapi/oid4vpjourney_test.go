package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oid4vp"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/sdjwt"
	"signari.dev/engine/internal/store"
)

const (
	walletIssuer = "https://pid-issuer.test"
	walletVCT    = "urn:example:pid:1"
)

// holderWallet is a person's wallet and the issuer that gave them a credential.
type holderWallet struct {
	t              *testing.T
	holder, issuer *ecdsa.PrivateKey
	subject        string
}

func newHolderWallet(t *testing.T, subject string) *holderWallet {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	return &holderWallet{t: t, holder: gen(), issuer: gen(), subject: subject}
}

func (wl *holderWallet) sign(key *ecdsa.PrivateKey, typ string, claims any) string {
	wl.t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		wl.t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	obj, err := s.Sign(b)
	if err != nil {
		wl.t.Fatal(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

// present answers a request object the way a wallet does: the credential with the
// claims asked for disclosed, bound to the request by its nonce and the verifier's
// client id.
func (wl *holderWallet) present(clientID, nonce string) string {
	wl.t.Helper()
	payload, ds, err := sdjwt.Payload(
		map[string]any{"iss": walletIssuer, "vct": walletVCT, "iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix()},
		map[string]any{"personal_id": wl.subject, "email": "wallet-" + wl.subject + "@example.test",
			"given_name": "Ada"})
	if err != nil {
		wl.t.Fatal(err)
	}
	payload["cnf"] = map[string]any{"jwk": jose.JSONWebKey{Key: wl.holder.Public()}}
	sd := sdjwt.Combine(wl.sign(wl.issuer, "dc+sd-jwt", payload), ds)
	kb := wl.sign(wl.holder, oid4vp.TypKeyBinding, map[string]any{"iat": time.Now().Unix(), "aud": clientID,
		"nonce": nonce, "sd_hash": sdjwt.DigestOf(sd)})
	b, _ := json.Marshal(map[string][]string{store.CredentialQueryID: {sd + kb}})
	return string(b)
}

// vpFixture is a wallet sign-in in the sign-in fixture's organisation, believing the
// wallet's issuer, with x509_san_dns and a certificate for the test issuer's host.
func newVPFixture(t *testing.T, wl *holderWallet) (*signInFixture, string, *x509.Certificate) {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root

	host := strings.TrimPrefix(f.srv.cfg.Issuer, "https://")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)

	slug := "wallet-" + strings.TrimPrefix(f.clientID, "si-")
	spec := store.IdentityProviderSpec{Slug: slug, Kind: "oid4vp", AllowSignup: true, VP: &store.VPSpec{
		Prefix: "x509_san_dns", VCTValues: []string{walletVCT}, SubjectClaim: "personal_id", EmailClaim: "email",
		KeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		ChainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	providerID, err := store.AddIdentityProvider(ctx, tx, root, f.orgID, spec)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: wl.issuer.Public(), Use: "sig"}}})
	if err := store.SetVPTrustedIssuer(ctx, tx, f.orgID, slug, walletIssuer, jwks); err != nil {
		t.Fatal(err)
	}
	// The fixture's person is this credential's subject.
	if err := store.LinkFederatedIdentity(ctx, tx, providerID, f.userID, f.orgID,
		federation.ExternalIdentity{Subject: store.VPSubject(walletIssuer, "person-1")}, false); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE id = $1::uuid`, providerID)
	})
	return f, slug, leaf
}

// start is the browser following the sign-in button: the wallet's URL, and the
// cookie that binds the sign-in to this browser.
func (f *signInFixture) startVP(t *testing.T, slug string) (*url.URL, *http.Cookie) {
	t.Helper()
	ret := url.QueryEscape(oidc.PathAuthorize + "?" + f.plainAuthz())
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/start?return="+ret, nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start answered %d: %.300s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Scheme != "openid4vp" {
		t.Fatalf("sent to %q", rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == FederationCookieName {
			return loc, c
		}
	}
	t.Fatal("no binding cookie")
	return nil, nil
}

// fetch is the wallet fetching the request object by POST with its own nonce, and
// checking it as section 5.10.1 says a wallet must.
func (f *signInFixture) fetchVP(t *testing.T, loc *url.URL, leaf *x509.Certificate) map[string]any {
	t.Helper()
	q := loc.Query()
	reqURI, err := url.Parse(q.Get("request_uri"))
	if err != nil || q.Get("request_uri_method") != "post" {
		t.Fatalf("the wallet was sent %v", q)
	}
	req := httptest.NewRequest(http.MethodPost, reqURI.RequestURI(), strings.NewReader("wallet_nonce=wn-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Result().Header.Get("Content-Type") != "application/oauth-authz-req+jwt" {
		t.Fatalf("the request URI answered %d %q: %.300s", rec.Code, rec.Result().Header.Get("Content-Type"), rec.Body)
	}
	tok, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := tok.Verify(leaf.PublicKey)
	if err != nil {
		t.Fatalf("the request object is not signed by the certificate's key: %v", err)
	}
	var p map[string]any
	_ = json.Unmarshal(payload, &p)
	if p["client_id"] != q.Get("client_id") || p["wallet_nonce"] != "wn-1" || p["response_mode"] != "direct_post" {
		t.Fatalf("request object %v", p)
	}
	return p
}

// post is the wallet answering at the response URI.
func (f *signInFixture) postVP(t *testing.T, responseURI string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	u, _ := url.Parse(responseURI)
	req := httptest.NewRequest(http.MethodPost, u.RequestURI(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestAPersonSignsInWithACredentialFromTheirWallet(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, leaf := newVPFixture(t, wl)
	loc, cookie := f.startVP(t, slug)
	if want := "x509_san_dns:" + leaf.DNSNames[0]; loc.Query().Get("client_id") != want {
		t.Fatalf("client_id %q, want %q", loc.Query().Get("client_id"), want)
	}
	p := f.fetchVP(t, loc, leaf)
	clientID, nonce, state, responseURI := p["client_id"].(string), p["nonce"].(string), p["state"].(string),
		p["response_uri"].(string)

	// Answered before anything is checked: the response URI takes nothing for a
	// request it did not make.
	if rec := f.postVP(t, responseURI, url.Values{"state": {"made-up"}, "vp_token": {wl.present(clientID, nonce)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a made-up state answered %d", rec.Code)
	}
	// Made for another verifier, and for another request: refused to the wallet,
	// which is how it learns.
	for name, vp := range map[string]string{
		"another verifier": wl.present("x509_san_dns:elsewhere.example", nonce),
		"another request":  wl.present(clientID, "another-nonce"),
	} {
		if rec := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {vp}}); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d %.200s", name, rec.Code, rec.Body)
		}
	}

	rec := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {wl.present(clientID, nonce)}})
	if rec.Code != http.StatusOK || rec.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("the presentation answered %d: %.300s", rec.Code, rec.Body)
	}
	var answer struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil || answer.RedirectURI == "" {
		t.Fatalf("answered %s", rec.Body)
	}
	// Answered once.
	if again := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {wl.present(clientID, nonce)}}); again.Code != http.StatusBadRequest {
		t.Errorf("a second presentation for one request answered %d", again.Code)
	}

	back, _ := url.Parse(answer.RedirectURI)
	// Somebody else's browser, with the code and without the cookie, gets nothing:
	// that is the session fixation section 14.2 is about.
	stray := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(stray, httptest.NewRequest(http.MethodGet, back.RequestURI(), nil))
	if stray.Code == http.StatusSeeOther || hasSession(stray) {
		t.Fatalf("a browser without the binding finished the sign-in: %d", stray.Code)
	}

	done := httptest.NewRequest(http.MethodGet, back.RequestURI(), nil)
	done.AddCookie(cookie)
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, done)
	if out.Code != http.StatusSeeOther || !hasSession(out) {
		t.Fatalf("coming back answered %d: %.300s", out.Code, out.Body)
	}
	// The fixture's person, who is linked to this credential's subject, and
	// nobody made for the occasion.
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions
		WHERE user_id = $1::uuid`, f.userID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("the linked person has %d sessions: %v", sessions, err)
	}
	// And the sign-in carries on to the application it started at.
	if !strings.HasPrefix(out.Header().Get("Location"), oidc.PathAuthorize) {
		t.Errorf("sent on to %q", out.Header().Get("Location"))
	}

	// The same code again, even with the cookie, is a sign-in already used.
	reuse := httptest.NewRequest(http.MethodGet, back.RequestURI(), nil)
	reuse.AddCookie(cookie)
	rerec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rerec, reuse)
	if hasSession(rerec) {
		t.Error("a response code was used twice")
	}
}

// A browser that comes back with the cookie and a code it was not given is refused.
func TestAWalletSignInNeedsTheCodeTheWalletWasGiven(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, leaf := newVPFixture(t, wl)
	loc, cookie := f.startVP(t, slug)
	p := f.fetchVP(t, loc, leaf)
	rec := f.postVP(t, p["response_uri"].(string), url.Values{"state": {p["state"].(string)},
		"vp_token": {wl.present(p["client_id"].(string), p["nonce"].(string))}})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	req := httptest.NewRequest(http.MethodGet, "/oid4vp/"+slug+"/done?state="+url.QueryEscape(p["state"].(string))+
		"&response_code=guessed", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, req)
	if hasSession(out) || out.Code == http.StatusSeeOther {
		t.Fatalf("a guessed response code signed somebody in: %d", out.Code)
	}
}

// The handler looks before it verifies, so a second post is turned away there; two
// posts racing both get past the look, and the store is what lets only one of them
// record a presentation.
func TestARequestIsAnsweredOnceEvenByTwoAtOnce(t *testing.T) {
	wl := newHolderWallet(t, "person-1")
	f, slug, leaf := newVPFixture(t, wl)
	loc, _ := f.startVP(t, slug)
	state := f.fetchVP(t, loc, leaf)["state"].(string)
	v, err := store.LoadVPVerifier(context.Background(), f.pool, f.srv.cfg.Root, slug)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PresentVP(context.Background(), f.pool, v.ProviderID, state, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PresentVP(context.Background(), f.pool, v.ProviderID, state, []byte(`{}`)); err != store.ErrVPRequestGone {
		t.Fatalf("a second presentation was recorded: %v", err)
	}
}

func hasSession(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}
