package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

func clientKeyPair(t *testing.T) (keyPEM, certPEM string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "c"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A provider set up with a certificate and no secret, through the API: the key is
// sealed where it lies, read back by nothing, and what a sign-in loads can sign. A
// method the provider would refuse on somebody's first sign-in is refused here.
func TestAProviderCanBeSignedInToWithACertificateAlone(t *testing.T) {
	s, _ := newTestServer(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.root = root
	ctx := context.Background()
	org, slug, path := newDriftIdP(t, s, "oidc")
	put := func(body map[string]any, want int) string {
		t.Helper()
		rec := call(t, s, http.MethodPut, path+"/token-auth", testToken, body)
		if rec.Code != want {
			t.Fatalf("%v answered %d, want %d: %s", body["method"], rec.Code, want, rec.Body.String())
		}
		return rec.Body.String()
	}

	put(map[string]any{"method": "client_secret_basic"}, http.StatusBadRequest)
	put(map[string]any{"method": "private_key_jwt"}, http.StatusBadRequest)
	put(map[string]any{"method": "tls_client_auth"}, http.StatusBadRequest)
	put(map[string]any{"method": "carrier_pigeon"}, http.StatusBadRequest)

	keyPEM, certPEM := clientKeyPair(t)
	_, otherCert := clientKeyPair(t)
	put(map[string]any{"method": "private_key_jwt", "client_key": keyPEM, "client_certificate": otherCert}, http.StatusBadRequest)
	put(map[string]any{"method": "tls_client_auth", "client_key": keyPEM}, http.StatusBadRequest)

	put(map[string]any{"method": "private_key_jwt", "client_key": keyPEM, "client_certificate": certPEM}, http.StatusOK)

	var sealed []byte
	var method string
	if err := s.db.QueryRow(ctx, `SELECT client_key, token_auth_method FROM core.identity_providers
		WHERE org_id = $1::uuid AND slug = $2`, org, slug).Scan(&sealed, &method); err != nil {
		t.Fatal(err)
	}
	if method != federation.AuthPrivateKeyJWT || strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Errorf("stored method %q, and the key is in the clear: %v", method, strings.Contains(string(sealed), "PRIVATE KEY"))
	}
	listed := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/identity-providers", testToken, nil).Body.String()
	if !strings.Contains(listed, `"has_client_key":true`) || strings.Contains(listed, "PRIVATE KEY") {
		t.Errorf("the listing reads %s", listed)
	}

	c, err := store.LoadIdentityProvider(ctx, s.db, root, slug)
	if err != nil {
		t.Fatal(err)
	}
	if c.TokenAuth.Method != federation.AuthPrivateKeyJWT || c.TokenAuth.Key == nil || c.TokenAuth.Certificate == nil {
		t.Errorf("a sign-in loads %+v", c.TokenAuth)
	}

	// The key is kept when only the method moves, and a certificate for it now
	// satisfies mutual TLS.
	put(map[string]any{"method": "tls_client_auth"}, http.StatusOK)
	c, err = store.LoadIdentityProvider(ctx, s.db, root, slug)
	if err != nil || c.TokenAuth.Method != federation.AuthTLS || c.TokenAuth.Key == nil {
		t.Errorf("after moving the method a sign-in loads %+v, %v", c.TokenAuth, err)
	}
	// A new certificate is checked against the key held, which only the root opens.
	put(map[string]any{"method": "tls_client_auth", "client_certificate": otherCert}, http.StatusBadRequest)
}

func TestASAMLUpstreamHasNoTokenEndpointToSignInTo(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org := newDriftMigrationOrg(t, s, false)
	slug := fmt.Sprintf("saml-%d", time.Now().UnixNano())
	if _, err := s.db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, 'S', 'saml', '')`, org, slug); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.identity_providers WHERE slug = $1`, slug)
	})
	rec := call(t, s, http.MethodPut, "/admin/organizations/"+org+"/identity-providers/"+slug+"/token-auth", testToken,
		map[string]any{"method": "client_secret_post"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a SAML upstream answered %d", rec.Code)
	}
}
