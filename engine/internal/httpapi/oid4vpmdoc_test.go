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
	"signari.dev/engine/internal/oid4vp/mdoctest"
	"signari.dev/engine/internal/store"
)

const mdlNameSpace = "org.iso.18013.5.1"

// newMdocVPFixture is a wallet sign-in that asks for a mobile driving licence, believing
// the IACA of is, with the fixture's person linked to document number D1234567.
func newMdocVPFixture(t *testing.T, is *mdoctest.Issuer, responseMode string) (*signInFixture, string, *x509.Certificate) {
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

	slug := "mdl-" + strings.TrimPrefix(f.clientID, "si-")
	spec := store.IdentityProviderSpec{Slug: slug, Kind: "oid4vp", AllowSignup: true, VP: &store.VPSpec{
		Prefix: "x509_san_dns", Format: oid4vp.FormatMdoc, DocType: oid4vp.MdocDocType,
		IACARootsPEM: is.RootsPEM(), ResponseMode: responseMode,
		SubjectClaim: `["` + mdlNameSpace + `","document_number"]`, NameClaim: `["` + mdlNameSpace + `","given_name"]`,
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
	if err := store.LinkFederatedIdentity(ctx, tx, providerID, f.userID, f.orgID, federation.ExternalIdentity{
		Subject: store.VPSubject("mdoc:"+oid4vp.MdocDocType+":UT", "D1234567")}, false); err != nil {
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

func mdlDoc(t *testing.T) mdoctest.Doc {
	return mdoctest.Doc{DocType: oid4vp.MdocDocType, DeviceKey: mdoctest.DeviceKey(t),
		Elements: map[string]map[string]any{mdlNameSpace: {"document_number": "D1234567", "given_name": "Ada"}}}
}

// mdocToken is the wallet's vp_token: its DeviceResponse for the transcript of e.
func mdocToken(t *testing.T, is *mdoctest.Issuer, d mdoctest.Doc, e oid4vp.Expect) string {
	t.Helper()
	transcript, err := oid4vp.SessionTranscript(e)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string][]string{store.CredentialQueryID: {is.Present(t, d, transcript)}})
	return string(b)
}

// The whole sign-in with a mobile driving licence: the request asks for an mdoc of its
// document type, the wallet answers with its DeviceResponse signed for this request, and
// the person its document number is linked to is signed in, in the browser that began.
func TestAPersonSignsInWithAMobileDrivingLicence(t *testing.T) {
	is := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT"})
	f, slug, leaf := newMdocVPFixture(t, is, "")
	loc, cookie := f.startVP(t, slug)
	p := f.fetchVP(t, loc, leaf)
	clientID, nonce, state, responseURI := p["client_id"].(string), p["nonce"].(string), p["state"].(string),
		p["response_uri"].(string)
	asked, _ := json.Marshal(p["dcql_query"])
	meta, _ := json.Marshal(p["client_metadata"])
	if !strings.Contains(string(asked), `"format":"mso_mdoc"`) ||
		!strings.Contains(string(asked), `"doctype_value":"`+oid4vp.MdocDocType+`"`) ||
		!strings.Contains(string(asked), `"path":["`+mdlNameSpace+`","document_number"]`) ||
		!strings.Contains(string(meta), `"mso_mdoc"`) || strings.Contains(string(meta), "sd-jwt") {
		t.Fatalf("asked %s with %s", asked, meta)
	}
	here := oid4vp.Expect{ClientID: clientID, Nonce: nonce, ResponseURI: responseURI}

	// Signed for another response URI, as a relay would: refused.
	elsewhere := here
	elsewhere.ResponseURI = "https://elsewhere.example/response"
	if rec := f.postVP(t, responseURI, url.Values{"state": {state},
		"vp_token": {mdocToken(t, is, mdlDoc(t), elsewhere)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an mdoc signed for another response URI answered %d", rec.Code)
	}
	// Another authority's licence: refused.
	other := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT"})
	if rec := f.postVP(t, responseURI, url.Values{"state": {state},
		"vp_token": {mdocToken(t, other, mdlDoc(t), here)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an mdoc from an IACA nobody believes answered %d", rec.Code)
	}

	rec := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {mdocToken(t, is, mdlDoc(t), here)}})
	var answer struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &answer) != nil || answer.RedirectURI == "" {
		t.Fatalf("the licence answered %d: %.300s", rec.Code, rec.Body)
	}
	back, _ := url.Parse(answer.RedirectURI)
	done := httptest.NewRequest(http.MethodGet, back.RequestURI(), nil)
	done.AddCookie(cookie)
	out := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(out, done)
	if out.Code != http.StatusSeeOther || !hasSession(out) {
		t.Fatalf("coming back answered %d: %.300s", out.Code, out.Body)
	}
	var sessions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.sessions
		WHERE user_id = $1::uuid`, f.userID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("the linked person has %d sessions: %v", sessions, err)
	}
}

// Asked for an encrypted answer, the device signs a transcript naming the key the answer
// is encrypted to (specs/oid4vp.txt:3230-3240). One signed as if for an answer in clear,
// even encrypted to the right key, is refused; the one naming the key signs the person in.
func TestAnEncryptedMdocAnswerIsBoundToItsKey(t *testing.T) {
	is := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT"})
	f, slug, leaf := newMdocVPFixture(t, is, oid4vp.ModeDirectPostJWT)
	loc, _ := f.startVP(t, slug)
	p := f.fetchVP(t, loc, leaf)
	clientID, nonce, state, responseURI := p["client_id"].(string), p["nonce"].(string), p["state"].(string),
		p["response_uri"].(string)
	meta, _ := json.Marshal(p["client_metadata"])
	var cm struct {
		JWKS jose.JSONWebKeySet `json:"jwks"`
	}
	if err := json.Unmarshal(meta, &cm); err != nil || len(cm.JWKS.Keys) != 1 {
		t.Fatalf("client_metadata %s: %v", meta, err)
	}
	to := cm.JWKS.Keys[0]
	encrypt := func(vpToken string) string {
		var token map[string]any
		_ = json.Unmarshal([]byte(vpToken), &token)
		e, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: to.Key, KeyID: to.KeyID}, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]any{"vp_token": token, "state": state})
		obj, err := e.Encrypt(b)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := obj.CompactSerialize()
		return out
	}
	clear := oid4vp.Expect{ClientID: clientID, Nonce: nonce, ResponseURI: responseURI}
	if rec := f.postVP(t, responseURI, url.Values{"response": {encrypt(mdocToken(t, is, mdlDoc(t), clear))}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a transcript without the key's thumbprint answered %d", rec.Code)
	}
	bound := clear
	bound.EncryptedTo = &to
	if rec := f.postVP(t, responseURI, url.Values{"response": {encrypt(mdocToken(t, is, mdlDoc(t), bound))}}); rec.Code != http.StatusOK {
		t.Fatalf("the bound answer answered %d: %.300s", rec.Code, rec.Body)
	}
}

// An mdoc sign-in believes IACA certificates and nothing else: an SD-JWT VC is not what it
// asked for, an issuer cannot be believed for it, and replacing its IACA stops the old
// authority's licences at once.
func TestAnMdocSignInBelievesOnlyItsIACA(t *testing.T) {
	is := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT"})
	f, slug, leaf := newMdocVPFixture(t, is, "")
	ctx := context.Background()
	wl := newHolderWallet(t, "person-1")
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: wl.issuer.Public(), Use: "sig"}}})
	if err := store.SetVPTrustedIssuer(ctx, f.pool, f.orgID, slug, walletIssuer, jwks); err == nil ||
		!strings.Contains(err.Error(), "IACA") {
		t.Errorf("an issuer believed for an mdoc sign-in: %v", err)
	}

	loc, _ := f.startVP(t, slug)
	p := f.fetchVP(t, loc, leaf)
	clientID, nonce, state, responseURI := p["client_id"].(string), p["nonce"].(string), p["state"].(string),
		p["response_uri"].(string)
	if rec := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {wl.present(clientID, nonce)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an SD-JWT VC to an mdoc sign-in answered %d", rec.Code)
	}

	next := mdoctest.NewIssuer(t, mdoctest.IssuerOptions{Country: "UT"})
	roots := next.RootsPEM()
	if err := store.ChangeIdentityProvider(ctx, f.pool, f.orgID, slug, store.IdentityProviderChange{IACARoots: &roots}); err != nil {
		t.Fatal(err)
	}
	here := oid4vp.Expect{ClientID: clientID, Nonce: nonce, ResponseURI: responseURI}
	if rec := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {mdocToken(t, is, mdlDoc(t), here)}}); rec.Code != http.StatusBadRequest {
		t.Errorf("the replaced IACA's licence answered %d", rec.Code)
	}
	if rec := f.postVP(t, responseURI, url.Values{"state": {state}, "vp_token": {mdocToken(t, next, mdlDoc(t), here)}}); rec.Code != http.StatusOK {
		t.Errorf("the new IACA's licence answered %d: %.300s", rec.Code, rec.Body)
	}
}
