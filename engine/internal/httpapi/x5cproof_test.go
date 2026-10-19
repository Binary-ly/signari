package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vci"
)

// A key proof whose `x5c` chain verifies to a CA the organisation trusts gets a
// credential (2.07). The proof code checked chains against
// ProofContext.TrustedX5CRoots, and nothing could put a root there, so every
// such proof was refused; `credential trust-root` is that writer.
func TestAnX5CProofToATrustedRootGetsACredential(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	ctx := context.Background()

	ca := func(name string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
		t.Helper()
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return k, cert, der
	}
	trustedKey, trustedCA, trustedDER := ca("wallet provider")
	strangerKey, strangerCA, _ := ca("somebody else")

	wa := newWallet(t)
	leafFrom := func(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) []byte {
		t.Helper()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device key"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, wa.key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	request := func(leaf []byte) (int, map[string]any) {
		t.Helper()
		_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
		nonce, _ := nb["c_nonce"].(string)
		opts := (&jose.SignerOptions{}).
			WithType(jose.ContentType(oid4vci.TypProof)).
			WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(leaf)})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: wa.key}, opts)
		if err != nil {
			t.Fatal(err)
		}
		claims, _ := json.Marshal(map[string]any{"aud": f.srv.cfg.Issuer, "iat": time.Now().Unix(), "nonce": nonce})
		obj, err := signer.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := obj.CompactSerialize()
		body := `{"credential_configuration_id":"IdentityCredential",
		          "proofs":{"jwt":[` + mustJSONString(t, proof) + `]}}`
		return f.postJSON(t, "/oid4vci/credential", f.mintAccessToken(t), body)
	}

	trustedLeaf := leafFrom(trustedKey, trustedCA)
	if status, body := request(trustedLeaf); status != http.StatusBadRequest || body["error"] != "invalid_proof" {
		t.Errorf("with no root registered an x5c proof gave %d %v, want 400 invalid_proof", status, body)
	}

	name := fmt.Sprintf("wallet-provider-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.credential_proof_roots (org_id, name, certificate)
		VALUES ($1::uuid, $2, $3)`, f.orgID, name, trustedDER); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.credential_proof_roots
			WHERE org_id = $1::uuid AND name = $2`, f.orgID, name)
	})

	status, body := request(trustedLeaf)
	if status != http.StatusOK {
		t.Fatalf("an x5c chain to a trusted root gave %d %v, want a credential", status, body)
	}
	if creds, _ := body["credentials"].([]any); len(creds) != 1 {
		t.Fatalf("expected one credential, got %v", body)
	}
	// A chain to a CA nobody registered is still refused.
	if status, body := request(leafFrom(strangerKey, strangerCA)); status != http.StatusBadRequest {
		t.Errorf("an x5c chain to an untrusted CA gave %d %v, want 400", status, body)
	}
}
