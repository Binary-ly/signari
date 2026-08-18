package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Adversarial tests for the credential endpoint.
//
// The endpoint mints a credential bound to a key the caller supplies, and every
// proof it accepts costs a nonce redemption, two elliptic-curve operations and
// two database round trips. Both halves of that sentence are attack surface:
// what gets bound, and how much work one request can buy.

// THE race: two requests presenting the same c_nonce at the same moment.
//
// Single use has to hold under concurrency or it does not hold at all — a
// captured proof is replayed by a script, not by a person taking turns. The
// guarantee lives in the UPDATE's WHERE clause rather than in a read-then-write,
// which is the difference between a check and a lock.
func TestAConcurrentNonceReplayMintsExactlyOneCredential(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	body := `{"credential_configuration_id":"IdentityCredential","proofs":{"jwt":[` +
		mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce)) + `]}}`

	const racers = 8
	var wg sync.WaitGroup
	results := make([]int, racers)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			defer wg.Done()
			status, _ := f.postJSON(t, "/oid4vci/credential", token, body)
			results[i] = status
		}(i)
	}
	wg.Wait()

	issued := 0
	for _, s := range results {
		if s == http.StatusOK {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("%d of %d concurrent replays were issued a credential; single "+
			"use must survive concurrency or it is not single use", issued, racers)
	}
}

// A symmetric key offered as the binding key.
//
// §F.1 forbids a MAC algorithm for the proof, and the reason applies to the key
// as well: an `oct` JWK is a shared secret, so "the key the credential is bound
// to" would be a value the issuer also holds — and anybody who read it could
// present the credential.
func TestASymmetricBindingKeyIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithType(jose.ContentType("openid4vci-proof+jwt")).
			WithHeader("jwk", jose.JSONWebKey{Key: secret, Algorithm: "HS256"}))
	if err != nil {
		// go-jose may refuse to embed a symmetric JWK at all, which is itself
		// the right answer.
		t.Skip("the JOSE library refuses to build this proof, which is correct")
	}
	claims, _ := json.Marshal(map[string]any{"aud": f.srv.cfg.Issuer, "nonce": nonce})
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Skip("the JOSE library refuses to sign this proof, which is correct")
	}
	raw, _ := obj.CompactSerialize()

	status, _ := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"IdentityCredential","proofs":{"jwt":[`+
			mustJSONString(t, raw)+`]}}`)
	if status == http.StatusOK {
		t.Fatal("a credential was bound to a symmetric key, which the issuer also " +
			"holds — anybody who reads it could present the credential")
	}
}

// A proof whose `jwk` carries PRIVATE key material.
//
// Nothing good comes of a wallet sending its private key, but the credential
// would still bind and the issuer would have logged a secret it should never
// have seen. Refused rather than stripped.
func TestAProofCarryingPrivateKeyMaterialIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The PRIVATE key embedded, rather than k.Public().
	priv := &jose.JSONWebKey{Key: k, Algorithm: string(jose.ES256)}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k},
		(&jose.SignerOptions{}).WithType(jose.ContentType("openid4vci-proof+jwt")).
			WithHeader("jwk", priv))
	if err != nil {
		t.Fatal(err)
	}
	// `iat` included deliberately. Without it the proof is refused for being
	// undated, and this test would pass without the private-key guard ever
	// running — which a mutation proved it did.
	claims, _ := json.Marshal(map[string]any{
		"aud": f.srv.cfg.Issuer, "nonce": nonce, "iat": time.Now().Unix()})
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := obj.CompactSerialize()

	// This asserts the BEHAVIOUR — a proof carrying private key material is
	// refused — not which layer refuses it. go-jose rejects the embedded private
	// JWK inside ParseSigned, so our own IsPublic guard never runs and removing
	// it fails nothing. Both facts are recorded rather than one of them implied:
	// the request is genuinely reachable (go-jose serialises the private scalar,
	// verified separately), and the library is what stops it.
	status, _ := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"IdentityCredential","proofs":{"jwt":[`+
			mustJSONString(t, raw)+`]}}`)
	if status == http.StatusOK {
		t.Fatal("a proof embedding private key material was accepted; the issuer " +
			"would have logged a secret it should never have seen")
	}
}

// A body that is not an object, and one that names a member twice.
func TestMalformedCredentialRequestsAreRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	for _, body := range []string{
		`[]`, `"string"`, `null`, `{`,
		`{"credential_configuration_id":"IdentityCredential",` +
			`"credential_identifier":"also-this"}`,
	} {
		status, _ := f.postJSON(t, "/oid4vci/credential", token, body)
		if status == http.StatusOK {
			t.Errorf("accepted: %s", body)
		}
	}
}

// §8.2: the proofs object "contains exactly one parameter named as the proof
// type". Two would leave which was honoured up to map iteration order.
//
// The jwt proof here is VALID, so the only thing that can refuse this request is
// the count itself. An earlier version used a placeholder proof and passed
// because the placeholder failed validation — the check it was written for never
// ran, and a mutation showed it.
func TestTwoProofTypesAreRefusedEvenWhenOneIsValid(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	valid := mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce))

	status, resp := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"IdentityCredential",`+
			`"proofs":{"jwt":[`+valid+`],"di_vp":[{}]}}`)
	if status == http.StatusOK {
		t.Fatal("a request carrying two proof types was accepted; which one was " +
			"honoured would depend on map iteration order")
	}
	if d, _ := resp["error_description"].(string); !strings.Contains(d, "exactly one") {
		t.Errorf("refused for the wrong reason: %v", d)
	}
}

// An access token for another audience must not open this endpoint, even though
// it verifies. RFC 9700 §2.3: a resource server MUST refuse a token that was not
// meant for it.
func TestATokenForAnotherResourceIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)

	// A token audienced to a downstream API via RFC 8707 `resource`.
	ctx := t.Context()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := f.srv.mintSet(ctx, tx, c, f.orgID, f.userID, "", "",
		[]string{}, []string{"https://billing.example/api"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	status, _ := f.postJSON(t, "/oid4vci/credential", resp.AccessToken,
		`{"credential_configuration_id":"IdentityCredential"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a token audienced to another API "+
			"opened the credential endpoint", status)
	}
}
