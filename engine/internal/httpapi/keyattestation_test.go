package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vci"
)

// A key attestation from an attester `signari attester add` registered gets a
// credential (2.07). The proof code verified attestations against
// ProofContext.TrustedAttesters, and the credential endpoint never filled it,
// so every attested proof was refused while docs/oid4vci.md said to register an
// attester. The proof names its key by `kid` alone, which only an attestation
// can resolve.
func TestAnAttestedKeyGetsACredential(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	ctx := context.Background()

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attesterJWK := jose.JSONWebKey{Key: attesterKey.Public(), Algorithm: string(jose.ES256), KeyID: "attester-1"}
	wa := newWallet(t)
	wa.jwk.KeyID = "device-key-1"

	attestation := func() string {
		t.Helper()
		holder, err := wa.jwk.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		body, _ := json.Marshal(map[string]any{
			"attested_keys": []json.RawMessage{holder},
			"iat":           now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: attesterKey},
			(&jose.SignerOptions{}).WithType(jose.ContentType(oid4vci.TypKeyAttestation)))
		if err != nil {
			t.Fatal(err)
		}
		obj, err := signer.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := obj.CompactSerialize()
		return s
	}
	proof := func(nonce string) string {
		t.Helper()
		opts := (&jose.SignerOptions{}).
			WithType(jose.ContentType(oid4vci.TypProof)).
			WithHeader("kid", "device-key-1").
			WithHeader(jose.HeaderKey(oid4vci.HeaderKeyAttestation), attestation())
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: wa.key}, opts)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"aud": f.srv.cfg.Issuer, "iat": time.Now().Unix(), "nonce": nonce})
		obj, err := signer.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := obj.CompactSerialize()
		return s
	}
	request := func() (int, map[string]any) {
		t.Helper()
		_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
		nonce, _ := nb["c_nonce"].(string)
		body := `{"credential_configuration_id":"IdentityCredential",
		          "proofs":{"jwt":[` + mustJSONString(t, proof(nonce)) + `]}}`
		return f.postJSON(t, "/oid4vci/credential", f.mintAccessToken(t), body)
	}

	// No attester registered: the attestation cannot be checked, so it is refused.
	if status, body := request(); status != http.StatusBadRequest || body["error"] != "invalid_proof" {
		t.Errorf("with no attester registered the attested proof gave %d %v, want 400 invalid_proof",
			status, body)
	}

	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{attesterJWK}})
	name := fmt.Sprintf("wallet-provider-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.client_attesters (org_id, name, jwks)
		VALUES ($1::uuid, $2, $3)`, f.orgID, name, jwks); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.client_attesters
			WHERE org_id = $1::uuid AND name = $2`, f.orgID, name)
	})

	status, body := request()
	if status != http.StatusOK {
		t.Fatalf("an attested key from a registered attester gave %d %v, want a credential", status, body)
	}
	creds, _ := body["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("expected one credential, got %v", body)
	}
}
