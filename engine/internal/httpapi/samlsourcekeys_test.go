package httpapi

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// samlUpstream is a SAML upstream with nothing asked of it.
type samlUpstream struct {
	f          *signInFixture
	slug       string
	providerID string
}

func newSAMLUpstream(t *testing.T) *samlUpstream {
	t.Helper()
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	_, certPEM, err := saml.NewSPKey("https://upstream.test", saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	u := &samlUpstream{f: f, slug: fmt.Sprintf("src-%d", time.Now().UnixNano())}
	if err := f.pool.QueryRow(context.Background(), `WITH ip AS (
		  INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		  VALUES ($1::uuid, $2, 'Upstream', 'saml', '', '{}') RETURNING id
		)
		INSERT INTO core.saml_sources (provider_id, org_id, entity_id, sso_url, cert_pem)
		SELECT id, $1::uuid, 'https://upstream.test/idp', 'https://upstream.test/sso', $3 FROM ip
		RETURNING provider_id::text`, f.orgID, u.slug, certPEM).Scan(&u.providerID); err != nil {
		t.Fatal(err)
	}
	return u
}

func (u *samlUpstream) get(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	u.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/source/"+u.slug+path, nil))
	return rec
}

// The whole of it from the operator's side: a key made and published, the upstream
// held to it, and the request that then goes out verifying against the certificate
// the metadata handed over, and nothing else.
func TestAnUpstreamIsSentRequestsSignedByTheKeyItsMetadataPublishes(t *testing.T) {
	u := newSAMLUpstream(t)
	ctx, pool, root := context.Background(), u.f.pool, u.f.srv.root
	on, off := true, false

	if rec := u.get("/metadata"); !strings.Contains(rec.Body.String(), `AuthnRequestsSigned="false"`) ||
		strings.Contains(rec.Body.String(), "KeyDescriptor") {
		t.Fatalf("metadata before any key: %s", rec.Body.String())
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, &on, nil); err == nil {
		t.Fatal("held to signing with no key to sign with")
	}

	key, err := store.AddSAMLSourceKey(ctx, pool, root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	if rec := u.get("/start"); strings.Contains(rec.Header().Get("Location"), "Signature=") {
		t.Fatalf("signed before it was asked to be: %s", rec.Header().Get("Location"))
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, &on, nil); err != nil {
		t.Fatal(err)
	}

	metadata := u.get("/metadata").Body.String()
	block, _ := pem.Decode([]byte(key.Certificate))
	if !strings.Contains(metadata, `AuthnRequestsSigned="true"`) || !strings.Contains(metadata, `<KeyDescriptor use="signing">`) ||
		!strings.Contains(metadata, saml.CertificateB64(block.Bytes)) {
		t.Fatalf("metadata does not publish the key: %s", metadata)
	}

	rec := u.get("/start")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther {
		t.Fatalf("starting: %d %v", rec.Code, err)
	}
	if err := saml.VerifyRedirectSignature(loc.RawQuery, key.Certificate, "SAMLRequest"); err != nil {
		t.Fatalf("the request did not verify against the published certificate: %v", err)
	}

	// A newer key signs, the older stays published for the overlap, and a retired
	// one goes.
	newer, err := store.AddSAMLSourceKey(ctx, pool, root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.saml_source_keys SET created_at = now() + interval '1 minute' WHERE id = $1::uuid`, newer.ID); err != nil {
		t.Fatal(err)
	}
	loc, err = url.Parse(u.get("/start").Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if err := saml.VerifyRedirectSignature(loc.RawQuery, newer.Certificate, "SAMLRequest"); err != nil {
		t.Errorf("the newest key did not sign: %v", err)
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, key.ID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.get("/metadata").Body.String(), saml.CertificateB64(block.Bytes)) {
		t.Error("a retired key is still published")
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, newer.ID); err == nil {
		t.Error("the last key the upstream is held to was retired")
	}
	if err := store.SetSAMLSourceKeyUse(ctx, pool, u.f.orgID, u.slug, &off, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireSAMLSourceKey(ctx, pool, u.f.orgID, u.slug, newer.ID); err != nil {
		t.Errorf("a key nothing is held to was kept: %v", err)
	}
}

// The private half is sealed, and sealed for this and nothing else.
func TestAnUpstreamKeyIsSealedUnderTheRootKey(t *testing.T) {
	u := newSAMLUpstream(t)
	ctx := context.Background()
	k, err := store.AddSAMLSourceKey(ctx, u.f.pool, u.f.srv.root, u.f.orgID, u.slug, saml.SPKeySigning)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := u.f.pool.QueryRow(ctx, `SELECT key_sealed FROM core.saml_source_keys WHERE id = $1::uuid`, k.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "PRIVATE") {
		t.Fatal("the key is stored in the clear")
	}
	if _, err := u.f.srv.root.Open(sealed, "something_else"); err == nil {
		t.Error("the key opened under another context")
	}
}
