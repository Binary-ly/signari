package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/abca"
	"signari.dev/engine/internal/oidc"
)

// Attestation-Based Client Authentication end to end.
//
// internal/abca proves the rules against the draft. What only reaches here is
// whether the pieces are actually wired: the challenge endpoint issues something
// the token endpoint will accept, the client row selects the method, and a
// challenge is genuinely single-use across two HTTP requests.

type abcaKey struct {
	priv *ecdsa.PrivateKey
	jwk  jose.JSONWebKey
}

func newABCAKey(t *testing.T) *abcaKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &abcaKey{priv: k, jwk: jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"}}
}

func (k *abcaKey) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderType, typ)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// abcaFixture registers a trusted attester and switches the client to
// attest_jwt_client_auth.
type abcaFixture struct {
	*tokenFixture
	attester *abcaKey
	instance *abcaKey
}

func newABCAFixture(t *testing.T) *abcaFixture {
	t.Helper()
	f := newTokenFixture(t)
	attester, instance := newABCAKey(t), newABCAKey(t)

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{attester.jwk}}
	blob, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.client_attesters (org_id, name, jwks)
		VALUES ($1::uuid, $2, $3)`, f.orgID, "test-attester-"+f.clientID, blob); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients SET token_endpoint_auth_method = $2, client_type = 'confidential',
		       client_secret_hash = 'unused'
		WHERE client_id = $1`, f.clientID, abca.MethodPoP); err != nil {
		t.Fatal(err)
	}
	return &abcaFixture{tokenFixture: f, attester: attester, instance: instance}
}

func (f *abcaFixture) attestation(t *testing.T) string {
	t.Helper()
	raw, err := f.instance.jwk.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return f.attester.sign(t, abca.TypAttestation, map[string]any{
		"sub": f.clientID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(raw)},
	})
}

func (f *abcaFixture) pop(t *testing.T, challenge, jti string) string {
	t.Helper()
	claims := map[string]any{
		"aud": tokenTestIssuer,
		"jti": jti,
		"iat": time.Now().Unix(),
	}
	if challenge != "" {
		claims["challenge"] = challenge
	}
	return f.instance.sign(t, abca.TypPoP, claims)
}

// fetchChallenge exercises §6.1's endpoint.
func (f *abcaFixture) fetchChallenge(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, oidc.PathAttestationChallenge, nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the challenge endpoint gave %d: %s", rec.Code, rec.Body.String())
	}
	// §6.1: "MUST make the response uncacheable by adding a Cache-Control header
	// field including the value no-store." A cached challenge is a reused one.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("the challenge response has Cache-Control %q; §6.1 requires no-store", cc)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ch, _ := body["attestation_challenge"].(string)
	if ch == "" {
		t.Fatalf("no attestation_challenge in %s", rec.Body.String())
	}
	return ch
}

// postABCA authenticates a token request with the two headers.
func (f *abcaFixture) postABCA(t *testing.T, form url.Values, att, pop string) (int, map[string]any, http.Header) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if att != "" {
		req.Header.Set(abca.HeaderAttestation, att)
	}
	if pop != "" {
		req.Header.Set(abca.HeaderPoP, pop)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Header()
}

func (f *abcaFixture) codeRequest(t *testing.T, verifier string) url.Values {
	t.Helper()
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil, []string{"openid"})
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}
}

// The whole mechanism, working.
func TestAClientAuthenticatesWithAnAttestationAndPoP(t *testing.T) {
	f := newABCAFixture(t)
	challenge := f.fetchChallenge(t)

	status, body, _ := f.postABCA(t,
		f.codeRequest(t, "verifier-abca-happy-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		f.attestation(t), f.pop(t, challenge, "jti-happy-1"))

	if status != http.StatusOK {
		t.Fatalf("attestation-based client authentication failed: %d %v", status, body)
	}
	if _, ok := body["access_token"]; !ok {
		t.Fatalf("no access token: %v", body)
	}
}

// §6.1: we offer a challenge endpoint, so a PoP without a challenge is refused --
// and §7.4 requires the refusal to hand back a fresh one.
func TestAPoPWithNoChallengeIsRefusedWithAFreshChallenge(t *testing.T) {
	f := newABCAFixture(t)

	status, body, hdr := f.postABCA(t,
		f.codeRequest(t, "verifier-abca-nochal-aaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		f.attestation(t), f.pop(t, "", "jti-nochal-1"))

	if status == http.StatusOK {
		t.Fatalf("a PoP with no challenge authenticated: %v", body)
	}
	if body["error"] != abca.ErrUseChallenge {
		t.Fatalf("error is %v, want %s", body["error"], abca.ErrUseChallenge)
	}
	// §7.4: "MUST be accompanied by the OAuth-Client-Attestation-Challenge HTTP
	// header field parameter". Telling a client to use a challenge without giving
	// it one is a loop it cannot break.
	if hdr.Get(abca.HeaderChallenge) == "" {
		t.Fatal("use_attestation_challenge was returned without a fresh challenge " +
			"in the OAuth-Client-Attestation-Challenge header; the client has been " +
			"told to retry with something it has not been given")
	}

	// The message must say the challenge was ABSENT, not that it was rejected.
	//
	// Mutation showed the explicit empty-challenge branch is not load-bearing for
	// the outcome: an empty challenge simply fails the store lookup and produces
	// the same error code by a longer route. What the branch buys is telling a
	// client that omitted the claim to add it, rather than sending an integrator
	// to investigate an expiry or a reuse that never happened. That distinction is
	// the branch's whole reason to exist, so it is what gets asserted -- the same
	// treatment given to the equivalent branches in the DPoP refresh binding and
	// the exchange subject-token check.
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "requires") || !strings.Contains(desc, "carry a challenge") {
		t.Fatalf("the refusal says %q; a PoP with no challenge at all must be told "+
			"to include one, not that its challenge was unknown or expired", desc)
	}
}

// A challenge is single use. This is what makes a captured PoP worthless rather
// than merely short-lived, and it can only be shown across two real requests.
func TestAChallengeCannotBeUsedTwice(t *testing.T) {
	f := newABCAFixture(t)
	challenge := f.fetchChallenge(t)

	status, body, _ := f.postABCA(t,
		f.codeRequest(t, "verifier-abca-once-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		f.attestation(t), f.pop(t, challenge, "jti-once-1"))
	if status != http.StatusOK {
		t.Fatalf("the first use failed: %d %v", status, body)
	}

	// Same challenge, fresh jti and a fresh code: only the challenge is reused.
	status, body, _ = f.postABCA(t,
		f.codeRequest(t, "verifier-abca-once-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		f.attestation(t), f.pop(t, challenge, "jti-once-2"))
	if status == http.StatusOK {
		t.Fatalf("a challenge was accepted twice; a captured PoP would then be "+
			"replayable for the challenge's whole lifetime: %v", body)
	}
}

// An attestation for one client must not authenticate another. Attestations are
// long-lived and reusable by design, so without §7.1 rule 7 one valid attestation
// would let its holder act as every client.
func TestAnAttestationForAnotherClientIsRefused(t *testing.T) {
	f := newABCAFixture(t)
	challenge := f.fetchChallenge(t)

	raw, err := f.instance.jwk.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	wrong := f.attester.sign(t, abca.TypAttestation, map[string]any{
		"sub": "some-other-client",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": json.RawMessage(raw)},
	})

	status, body, _ := f.postABCA(t,
		f.codeRequest(t, "verifier-abca-other-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		wrong, f.pop(t, challenge, "jti-other-1"))
	if status == http.StatusOK {
		t.Fatalf("an attestation naming a different client authenticated this one: %v", body)
	}
}

// §7.1 rule 1 and §7.2 rule 1: "There is precisely one" of each header.
func TestMissingAttestationHeadersAreRefused(t *testing.T) {
	f := newABCAFixture(t)
	challenge := f.fetchChallenge(t)
	att, pop := f.attestation(t), f.pop(t, challenge, "jti-missing-1")

	for _, tc := range []struct{ name, att, pop string }{
		{"neither", "", ""},
		{"attestation only", att, ""},
		{"pop only", "", pop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := f.postABCA(t,
				f.codeRequest(t, "verifier-abca-hdr-"+strings.Repeat("z", 30)),
				tc.att, tc.pop)
			if status == http.StatusOK {
				t.Fatalf("authenticated with %s: %v", tc.name, body)
			}
		})
	}
}

// The metadata a client reads to discover any of this, §8 and §6.1.
func TestDiscoveryAdvertisesAttestationSupport(t *testing.T) {
	f := newABCAFixture(t)
	req := httptest.NewRequest(http.MethodGet, oidc.PathDiscovery, nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery gave %d", rec.Code)
	}
	var md map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}

	methods, _ := md["token_endpoint_auth_methods_supported"].([]any)
	found := false
	for _, m := range methods {
		if m == abca.MethodPoP {
			found = true
		}
		// The combined DPoP mode is not implemented, so advertising it would be
		// the same dishonesty as advertising an endpoint that 404s.
		if m == abca.MethodDPoP {
			t.Fatalf("discovery advertises %s, which is not implemented", abca.MethodDPoP)
		}
	}
	if !found {
		t.Fatalf("discovery does not advertise %s: %v", abca.MethodPoP, methods)
	}

	// §8 makes both algorithm lists a MUST once the PoP mechanism is offered, and
	// §6.1 makes challenge_endpoint a MUST once the endpoint exists.
	for _, k := range []string{
		"client_attestation_signing_alg_values_supported",
		"client_attestation_pop_signing_alg_values_supported",
		"challenge_endpoint",
	} {
		if _, ok := md[k]; !ok {
			t.Fatalf("discovery omits %q, which the draft makes a MUST once this "+
				"mechanism is offered", k)
		}
	}
	if got := md["challenge_endpoint"]; got != tokenTestIssuer+oidc.PathAttestationChallenge {
		t.Fatalf("challenge_endpoint is %v", got)
	}
}
