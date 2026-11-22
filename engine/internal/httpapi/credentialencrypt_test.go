package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// OpenID4VCI §10, the way a wallet goes about it: the key from the issuer's metadata, the
// request sealed to that, and the credential sealed back to a key of the wallet's own.

type sealingWallet struct {
	f       *tokenFixture
	token   string
	wa      *wallet
	private *ecdsa.PrivateKey
}

func newSealingWallet(t *testing.T) *sealingWallet {
	t.Helper()
	f := newTokenFixture(t)
	configureCredential(t, f)
	ctx := context.Background()
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	f.srv.SetInstance(instanceID)
	root, err := keys.NewRootKey("credential-encrypt-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid AND purpose = 'encryption'`, instanceID)
	})
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &sealingWallet{f: f, token: f.mintAccessToken(t, "IdentityCredential"), wa: newWallet(t), private: private}
}

// rotate gives the issuer a key, or a new one.
func (s *sealingWallet) rotate(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	var instanceID string
	if err := s.f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		s.f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	tx, err := s.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := keys.RotateEncryptionKey(ctx, tx, instanceID, s.f.srv.root, "test"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (s *sealingWallet) metadata(t *testing.T) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%d %.200s", rec.Code, rec.Body)
	}
	return out
}

// issuerKey is the key to seal a request to, as the metadata publishes it.
func (s *sealingWallet) issuerKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	asked, _ := s.metadata(t)["credential_request_encryption"].(map[string]any)
	raw, err := json.Marshal(asked["jwks"])
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("the published keys are %s (%v)", raw, err)
	}
	return set.Keys[0]
}

func seal(t *testing.T, key jose.JSONWebKey, payload string) string {
	t.Helper()
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: key.Key, KeyID: key.KeyID},
		(&jose.EncrypterOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := encrypter.Encrypt([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// walletEncryption is the credential_response_encryption of a request.
func (s *sealingWallet) walletEncryption(t *testing.T, change map[string]any) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: s.private.Public(), KeyID: "wallet-1", Algorithm: "ECDH-ES", Use: "enc"}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	var key map[string]any
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatal(err)
	}
	asked := map[string]any{"jwk": key, "enc": "A256GCM"}
	for name, value := range change {
		if name == "alg" || name == "use" || name == "d" {
			if value == nil {
				delete(key, name)
			} else {
				key[name] = value
			}
			continue
		}
		asked[name] = value
	}
	out, err := json.Marshal(asked)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func (s *sealingWallet) body(t *testing.T, encryption string) string {
	t.Helper()
	_, nb := s.f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	body := `{"credential_configuration_id":"IdentityCredential",`
	if encryption != "" {
		body += `"credential_response_encryption":` + encryption + `,`
	}
	return body + `"proofs":{"jwt":[` + mustJSONString(t, s.wa.proof(t, s.f.srv.cfg.Issuer, nonce)) + `]}}`
}

func (s *sealingWallet) post(t *testing.T, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+s.token)
	rec := httptest.NewRecorder()
	s.f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

func (s *sealingWallet) opened(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Header().Get("Content-Type") != "application/jwt" {
		t.Fatalf("it answered %d %q: %.200s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	object, err := jose.ParseEncrypted(rec.Body.String(), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	// §10: "the JWE MUST include the same value in the kid".
	if object.Header.KeyID != "wallet-1" {
		t.Errorf("kid is %q", object.Header.KeyID)
	}
	plain, err := object.Decrypt(s.private)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(plain, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// All the way: a key out of the metadata, a sealed request, and a credential only the
// wallet can read.
func TestAWalletGetsItsCredentialSealed(t *testing.T) {
	s := newSealingWallet(t)
	s.rotate(t)
	body := s.body(t, s.walletEncryption(t, nil))
	rec := s.post(t, "/oid4vci/credential", "application/jwt", seal(t, s.issuerKey(t), body))
	if rec.Code != http.StatusOK {
		t.Fatalf("it answered %d %.300s", rec.Code, rec.Body)
	}
	if credentials, _ := s.opened(t, rec)["credentials"].([]any); len(credentials) != 1 {
		t.Errorf("it opened to no credential")
	}
	if strings.Contains(rec.Body.String(), "credentials") {
		t.Error("the response is readable")
	}
}

// §8.2: "Credential Request encryption MUST be used if the credential_response_encryption
// parameter is included, to prevent it being substituted by an attacker".
func TestAKeyToSealToHasToArriveSealed(t *testing.T) {
	s := newSealingWallet(t)
	s.rotate(t)
	rec := s.post(t, "/oid4vci/credential", "application/json", s.body(t, s.walletEncryption(t, nil)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_encryption_parameters") {
		t.Errorf("it answered %d %.200s", rec.Code, rec.Body)
	}
}

// Encrypting the request does not ask for anything back.
func TestASealedRequestCanHaveAPlainAnswer(t *testing.T) {
	s := newSealingWallet(t)
	s.rotate(t)
	rec := s.post(t, "/oid4vci/credential", "application/jwt", seal(t, s.issuerKey(t), s.body(t, "")))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") ||
		!strings.Contains(rec.Body.String(), "credentials") {
		t.Errorf("it answered %d %q: %.200s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
}

// Refused before anything is issued: a credential that cannot be delivered has spent a
// proof for nothing, and sending it in the clear is the one thing it must not do.
func TestWhatCannotBeSealedToIsRefusedFirst(t *testing.T) {
	s := newSealingWallet(t)
	s.rotate(t)
	ctx := context.Background()
	count := func() int {
		t.Helper()
		var n int
		if err := s.f.pool.QueryRow(ctx, `SELECT count(*) FROM core.credential_notifications WHERE org_id = $1::uuid`,
			s.f.orgID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	for name, change := range map[string]map[string]any{
		"compressed":          {"zip": "DEF"},
		"no alg":              {"alg": nil},
		"a key wrap with RSA": {"alg": "RSA1_5"},
		"another enc":         {"enc": "A192GCM"},
		"a signing key":       {"use": "sig"},
		"a private key":       {"d": base64.RawURLEncoding.EncodeToString(s.private.D.FillBytes(make([]byte, 32)))},
	} {
		rec := s.post(t, "/oid4vci/credential", "application/jwt",
			seal(t, s.issuerKey(t), s.body(t, s.walletEncryption(t, change))))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_encryption_parameters") {
			t.Errorf("%s answered %d %.200s", name, rec.Code, rec.Body)
		}
	}
	if n := count(); n != before {
		t.Errorf("%d credentials were issued on the way to being refused", n-before)
	}
}

func TestARequestThatDoesNotOpenIsRefused(t *testing.T) {
	s := newSealingWallet(t)
	s.rotate(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	real := s.issuerKey(t)
	for name, body := range map[string]string{
		"not a JWE":        "nonsense",
		"to a stranger":    seal(t, jose.JSONWebKey{Key: stranger.Public(), KeyID: "not-held"}, "{}"),
		"to the wrong key": seal(t, jose.JSONWebKey{Key: stranger.Public(), KeyID: real.KeyID}, "{}"),
	} {
		if rec := s.post(t, "/oid4vci/credential", "application/jwt", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d", name, rec.Code)
		}
	}
}

// A wallet's cached key still opens after a rotation, a new wallet is given the new one,
// and a second rotation is how a lost key stops opening anything.
func TestAnEncryptionKeyRotatedOutStillOpens(t *testing.T) {
	s := newSealingWallet(t)
	if got := s.metadata(t)["credential_request_encryption"]; got != nil {
		t.Errorf("with no key the metadata offers %v", got)
	}
	if got := s.metadata(t)["credential_response_encryption"]; got != nil {
		t.Errorf("with no key to arrive sealed to, the metadata offers to seal back: %v", got)
	}
	s.rotate(t)
	old := s.issuerKey(t)
	s.rotate(t)
	if current := s.issuerKey(t); current.KeyID == old.KeyID {
		t.Error("the metadata still offers the key rotated out")
	}
	rec := s.post(t, "/oid4vci/credential", "application/jwt", seal(t, old, s.body(t, "")))
	if rec.Code != http.StatusOK {
		t.Errorf("a request sealed to the old key answered %d %.200s", rec.Code, rec.Body)
	}
	s.rotate(t)
	rec = s.post(t, "/oid4vci/credential", "application/jwt", seal(t, old, s.body(t, "")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("two rotations later the old key answered %d %.200s", rec.Code, rec.Body)
	}
}

// The deferred road, both of its answers.
func TestADeferredCredentialIsSealedToo(t *testing.T) {
	s := newSealingWallet(t)
	s.rotate(t)
	ctx := context.Background()
	if _, err := s.f.pool.Exec(ctx, `UPDATE core.credential_configurations SET deferred = true
		WHERE org_id = $1::uuid`, s.f.orgID); err != nil {
		t.Fatal(err)
	}
	encryption := s.walletEncryption(t, nil)
	first := s.post(t, "/oid4vci/credential", "application/jwt", seal(t, s.issuerKey(t), s.body(t, encryption)))
	if first.Code != http.StatusAccepted {
		t.Fatalf("it answered %d %.200s", first.Code, first.Body)
	}
	transaction, _ := s.opened(t, first)["transaction_id"].(string)
	if transaction == "" {
		t.Fatal("no transaction")
	}
	asked := `{"transaction_id":"` + transaction + `","credential_response_encryption":` + encryption + `}`
	if rec := s.post(t, "/oid4vci/deferred_credential", "application/json", asked); rec.Code != http.StatusBadRequest {
		t.Errorf("asking in the clear for a sealed answer answered %d", rec.Code)
	}
	waiting := s.post(t, "/oid4vci/deferred_credential", "application/jwt", seal(t, s.issuerKey(t), asked))
	if waiting.Code != http.StatusAccepted {
		t.Fatalf("waiting answered %d %.200s", waiting.Code, waiting.Body)
	}
	s.opened(t, waiting)

	parked, err := store.PendingCredentialRequests(ctx, s.f.pool, s.f.orgID)
	if err != nil || len(parked) != 1 {
		t.Fatalf("waiting: %v, %v", parked, err)
	}
	if err := store.DecideCredentialRequest(ctx, s.f.pool, s.f.orgID, parked[0].ID, true); err != nil {
		t.Fatal(err)
	}
	delivered := s.post(t, "/oid4vci/deferred_credential", "application/jwt", seal(t, s.issuerKey(t), asked))
	if delivered.Code != http.StatusOK {
		t.Fatalf("delivery answered %d %.200s", delivered.Code, delivered.Body)
	}
	if credentials, _ := s.opened(t, delivered)["credentials"].([]any); len(credentials) != 1 {
		t.Error("it opened to no credential")
	}
}
