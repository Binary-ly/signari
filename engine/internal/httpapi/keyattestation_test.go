package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vci"
)

// keyAttester vouches for wallet keys, as a wallet provider does.
type keyAttester struct {
	key *ecdsa.PrivateKey
}

func newKeyAttester(t *testing.T) *keyAttester {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &keyAttester{key: k}
}

// register makes the organisation trust this attester, as `attester add` does.
func (a *keyAttester) register(t *testing.T, f *tokenFixture) {
	t.Helper()
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: a.key.Public(), Algorithm: string(jose.ES256), KeyID: "attester-1"}}})
	name := fmt.Sprintf("wallet-provider-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO core.client_attesters (org_id, name, jwks)
		VALUES ($1::uuid, $2, $3)`, f.orgID, name, jwks); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.client_attesters
			WHERE org_id = $1::uuid AND name = $2`, f.orgID, name)
	})
}

// attest signs an Appendix D attestation over the wallet's key.
func (a *keyAttester) attest(t *testing.T, wa *wallet) string {
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
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: a.key},
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

// attestedProof is a proof naming its key by `kid` alone, which only the
// attestation it carries can resolve.
func attestedProof(t *testing.T, f *tokenFixture, wa *wallet, attestation, nonce string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(oid4vci.TypProof)).
		WithHeader("kid", wa.jwk.KeyID).
		WithHeader(jose.HeaderKey(oid4vci.HeaderKeyAttestation), attestation)
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

// askForIdentityCredential spends a fresh c_nonce on the proof makeProof builds.
func askForIdentityCredential(t *testing.T, f *tokenFixture, makeProof func(nonce string) string) (int, map[string]any) {
	t.Helper()
	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	body := `{"credential_configuration_id":"IdentityCredential",
	          "proofs":{"jwt":[` + mustJSONString(t, makeProof(nonce)) + `]}}`
	return f.postJSON(t, "/oid4vci/credential", f.mintAccessToken(t), body)
}

// A key attestation from an attester `signari attester add` registered gets a
// credential (2.07). The proof code verified attestations against
// ProofContext.TrustedAttesters, and the credential endpoint never filled it,
// so every attested proof was refused while docs/oid4vci.md said to register an
// attester.
func TestAnAttestedKeyGetsACredential(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	att := newKeyAttester(t)
	wa := newWallet(t)
	wa.jwk.KeyID = "device-key-1"
	attested := func(nonce string) string { return attestedProof(t, f, wa, att.attest(t, wa), nonce) }

	// No attester registered: the attestation cannot be checked, so it is refused.
	if status, body := askForIdentityCredential(t, f, attested); status != http.StatusBadRequest || body["error"] != "invalid_proof" {
		t.Errorf("with no attester registered the attested proof gave %d %v, want 400 invalid_proof",
			status, body)
	}

	att.register(t, f)
	status, body := askForIdentityCredential(t, f, attested)
	if status != http.StatusOK {
		t.Fatalf("an attested key from a registered attester gave %d %v, want a credential", status, body)
	}
	if creds, _ := body["credentials"].([]any); len(creds) != 1 {
		t.Fatalf("expected one credential, got %v", body)
	}
}

// A configuration that requires a key attestation is issued only on one, and is
// the only kind whose metadata says so: specs/oid4vci.txt:2429 has
// key_attestations_required "MUST NOT be present" when none is required.
func TestACredentialThatRequiresAttestationIsIssuedOnlyToAnAttestedKey(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	att := newKeyAttester(t)
	att.register(t, f)
	wa := newWallet(t)
	wa.jwk.KeyID = "device-key-1"
	plain := func(nonce string) string { return wa.proof(t, f.srv.cfg.Issuer, nonce) }
	attested := func(nonce string) string { return attestedProof(t, f, wa, att.attest(t, wa), nonce) }

	advertised := func() bool {
		t.Helper()
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"/.well-known/openid-credential-issuer", nil))
		var md struct {
			Configs map[string]struct {
				Proofs map[string]map[string]any `json:"proof_types_supported"`
			} `json:"credential_configurations_supported"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
			t.Fatalf("metadata (%d): %v", rec.Code, err)
		}
		_, ok := md.Configs["IdentityCredential"].Proofs["jwt"]["key_attestations_required"]
		return ok
	}

	if advertised() {
		t.Error("a configuration that does not require an attestation advertised key_attestations_required")
	}
	if status, _ := askForIdentityCredential(t, f, plain); status != http.StatusOK {
		t.Fatalf("before the requirement, a plain jwk proof gave %d", status)
	}

	if _, err := f.pool.Exec(context.Background(), `UPDATE core.credential_configurations
		SET require_key_attestation = true WHERE org_id = $1::uuid AND config_id = 'IdentityCredential'`,
		f.orgID); err != nil {
		t.Fatal(err)
	}
	if !advertised() {
		t.Error("a configuration that requires an attestation does not advertise key_attestations_required")
	}
	if status, body := askForIdentityCredential(t, f, plain); status != http.StatusBadRequest || body["error"] != "invalid_proof" {
		t.Errorf("an unattested proof for a configuration requiring attestation gave %d %v, want 400", status, body)
	}
	if status, body := askForIdentityCredential(t, f, attested); status != http.StatusOK {
		t.Errorf("an attested proof for that configuration gave %d %v, want a credential", status, body)
	}
}
