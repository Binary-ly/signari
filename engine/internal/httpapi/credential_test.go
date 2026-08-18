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
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/sdjwt"
)

// The OID4VCI Credential Issuer, end to end: nonce → proof → credential.
//
// internal/sdjwt proves the format against the specification's own digest
// vector, and internal/oid4vci proves the proof rules. What is untested until
// here is whether a wallet can actually obtain a credential — and whether the
// credential it gets back is one a verifier could check.

type wallet struct {
	key *ecdsa.PrivateKey
	jwk *jose.JSONWebKey
}

func newWallet(t *testing.T) *wallet {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &wallet{key: k, jwk: &jose.JSONWebKey{Key: k.Public(), Algorithm: string(jose.ES256)}}
}

func (wa *wallet) proof(t *testing.T, audience, nonce string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(oid4vci.TypProof)).
		WithHeader("jwk", wa.jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: wa.key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"aud": audience, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	body, _ := json.Marshal(claims)
	obj, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

// configureCredential registers what this deployment issues.
func configureCredential(t *testing.T, f *tokenFixture) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.credential_configurations
			(org_id, config_id, vct, always_claims, selective_claims, lifetime, display_name)
		VALUES ($1::uuid, 'IdentityCredential', 'https://signari.test/identity',
		        ARRAY['sub'], ARRAY['email','preferred_username','email_verified'],
		        interval '30 days', 'Identity')`, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(c, `DELETE FROM core.credential_configurations
			WHERE org_id = $1::uuid`, f.orgID)
	})
}

// mintAccessToken produces a token for the fixture's user, the way the
// pre-authorized code grant would.
func (f *tokenFixture) mintAccessToken(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := f.srv.mintSet(ctx, tx, c, f.orgID, f.userID, "", "", []string{}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

func (f *tokenFixture) postJSON(t *testing.T, path, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The whole journey a wallet performs.
func TestAWalletObtainsAnSDJWTVerifiableCredential(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)

	// §7: the nonce endpoint is NOT a protected resource — no token.
	status, nonceBody := f.postJSON(t, "/oid4vci/nonce", "", "")
	if status != http.StatusOK {
		t.Fatalf("nonce endpoint gave %d: %v", status, nonceBody)
	}
	nonce, _ := nonceBody["c_nonce"].(string)
	if nonce == "" {
		t.Fatalf("no c_nonce returned: %v", nonceBody)
	}

	proof := wa.proof(t, f.srv.cfg.Issuer, nonce)
	body := `{"credential_configuration_id":"IdentityCredential",
	          "proofs":{"jwt":[` + mustJSONString(t, proof) + `]}}`

	status, resp := f.postJSON(t, "/oid4vci/credential", token, body)
	if status != http.StatusOK {
		t.Fatalf("credential endpoint gave %d: %v", status, resp)
	}

	creds, _ := resp["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("credentials = %v, want one", resp["credentials"])
	}
	first, _ := creds[0].(map[string]any)
	credential, _ := first["credential"].(string)
	if credential == "" {
		t.Fatalf("no credential in %v", first)
	}

	// It must be a real SD-JWT VC, not a plain JWT.
	jwt, disclosures, kb, err := sdjwt.Split(credential)
	if err != nil {
		t.Fatalf("the credential is not an SD-JWT: %v", err)
	}
	if kb != "" {
		t.Error("an issued credential must not carry a key binding JWT")
	}
	if len(disclosures) == 0 {
		t.Fatal("no disclosures: nothing is selectively disclosable, so this is " +
			"an ordinary JWT with extra syntax")
	}

	// The payload must carry the frame claims and NOT the selective ones.
	claims := decodeJWTPayload(t, jwt)
	if claims["vct"] != "https://signari.test/identity" {
		t.Errorf("vct = %v", claims["vct"])
	}
	if claims["iss"] != f.srv.cfg.Issuer {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["cnf"] == nil {
		t.Error("no cnf: the credential is not bound to the holder's key, which " +
			"makes it a bearer token")
	}
	if claims["_sd_alg"] != sdjwt.AlgSHA256 {
		t.Errorf("_sd_alg = %v", claims["_sd_alg"])
	}
	if _, leaked := claims["email"]; leaked {
		t.Error("email appears in the payload in the clear, so it is not " +
			"selectively disclosable at all")
	}

	// Every disclosure's digest must be in _sd, which is what a verifier checks.
	sd := map[string]bool{}
	for _, d := range claims["_sd"].([]any) {
		sd[d.(string)] = true
	}
	for _, enc := range disclosures {
		if !sd[sdjwt.DigestOf(enc)] {
			d, _ := sdjwt.Parse(enc)
			t.Errorf("the disclosure for %q has a digest that is not in _sd, so a "+
				"verifier would reject it", d.Name)
		}
	}
}

// The typ header is what a verifier keys on (draft-18 §3.2.1).
func TestTheIssuedCredentialCarriesTheCurrentMediaType(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	_, resp := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"IdentityCredential","proofs":{"jwt":[`+
			mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce))+`]}}`)

	creds := resp["credentials"].([]any)
	credential := creds[0].(map[string]any)["credential"].(string)
	jwt, _, _, _ := sdjwt.Split(credential)
	header := decodeJWTHeader(t, jwt)

	// Compared against a LITERAL, not against sdjwt.TypSDJWTVC.
	//
	// This test originally asserted header["typ"] != sdjwt.TypSDJWTVC, which is
	// a tautology: changing the constant to the deprecated "vc+sd-jwt" moved
	// both sides together and the test still passed. A mutation found it. The
	// value a verifier keys on is a fact about the wire, so the wire value is
	// what belongs here.
	if header["typ"] != "dc+sd-jwt" {
		t.Fatalf("typ = %v, want dc+sd-jwt — draft-18 renamed it from vc+sd-jwt, "+
			"and issuing the old value keeps it alive in verifiers", header["typ"])
	}
}

// A c_nonce is single use. Replaying a proof must not mint a second credential.
func TestACredentialNonceCannotBeReplayed(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	body := `{"credential_configuration_id":"IdentityCredential","proofs":{"jwt":[` +
		mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce)) + `]}}`

	if status, resp := f.postJSON(t, "/oid4vci/credential", token, body); status != http.StatusOK {
		t.Fatalf("first request gave %d: %v", status, resp)
	}
	status, resp := f.postJSON(t, "/oid4vci/credential", token, body)
	if status == http.StatusOK {
		t.Fatal("the same proof minted a second credential; a captured proof " +
			"would be replayable indefinitely")
	}
	if resp["error"] != "invalid_proof" {
		t.Errorf("error = %v, want invalid_proof", resp["error"])
	}
}

// Without a token the endpoint says nothing.
func TestTheCredentialEndpointRequiresAnAccessToken(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)

	status, _ := f.postJSON(t, "/oid4vci/credential", "",
		`{"credential_configuration_id":"IdentityCredential"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

// A configuration this issuer does not offer.
func TestAnUnknownCredentialConfigurationIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	wa := newWallet(t)
	token := f.mintAccessToken(t)

	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, resp := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"SomethingElse","proofs":{"jwt":[`+
			mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce))+`]}}`)
	if status == http.StatusOK {
		t.Fatal("a credential was issued for a configuration nobody registered")
	}
	if resp["error"] != "unsupported_credential_type" {
		t.Errorf("error = %v", resp["error"])
	}
}

// A request with no proof at all: there would be no key to bind to.
func TestACredentialRequestWithoutAProofIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	status, resp := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"IdentityCredential"}`)
	if status == http.StatusOK {
		t.Fatal("a credential was issued with no key proof, so it is bound to " +
			"nothing and is a bearer token")
	}
	if resp["error"] != "invalid_credential_request" {
		t.Errorf("error = %v", resp["error"])
	}
	// The message must name the missing thing. Removing the guard leaves a
	// fall-through that says "the jwt proofs array is empty" for a request that
	// carried no proofs parameter at all — true, and useless to the wallet
	// author reading it.
	if d, _ := resp["error_description"].(string); !strings.Contains(d, "proofs is required") {
		t.Errorf("error_description = %q; it should say what is missing", d)
	}
}

// §12.2: the metadata is published only when something is configured, and
// `credential_issuer` must equal the identifier the wallet built the URL from.
func TestCredentialIssuerMetadata(t *testing.T) {
	f := newTokenFixture(t)

	// Asserted on THIS configuration, not on the deployment being empty.
	//
	// The endpoint publishes what the whole deployment issues (§12.2 metadata is
	// per issuer, not per tenant), so an "is it 404 when empty" assertion depends
	// on no other test or operator having defined anything — which is a property
	// of the database, not of the code. It failed exactly that way once, on data
	// left behind by an end-to-end run.
	if _, before := credentialConfigNames(t, f)["IdentityCredential"]; before {
		t.Fatal("the fixture's configuration already exists; the check below " +
			"would prove nothing")
	}

	configureCredential(t, f)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/.well-known/openid-credential-issuer", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata gave %d once a credential was configured", rec.Code)
	}
	var md map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md["credential_issuer"] != f.srv.cfg.Issuer {
		t.Errorf("credential_issuer = %v; §12.2.3 makes this the mix-up defence",
			md["credential_issuer"])
	}
	supported, _ := md["credential_configurations_supported"].(map[string]any)
	entry, ok := supported["IdentityCredential"].(map[string]any)
	if !ok {
		t.Fatalf("the configuration is not advertised: %v", supported)
	}
	if entry["format"] != "dc+sd-jwt" {
		t.Errorf("format = %v", entry["format"])
	}
	if entry["proof_types_supported"] == nil {
		t.Error("proof_types_supported is absent, which per §8.2 makes the key " +
			"proof optional — the opposite of what this issuer requires")
	}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func decodeJWTPayload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	return decodeJWTPart(t, jwt, 1)
}

func decodeJWTHeader(t *testing.T, jwt string) map[string]any {
	t.Helper()
	return decodeJWTPart(t, jwt, 0)
}

func decodeJWTPart(t *testing.T, jwt string, i int) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// credentialConfigNames reads what the metadata endpoint currently advertises.
func credentialConfigNames(t *testing.T, f *tokenFixture) map[string]bool {
	t.Helper()
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/.well-known/openid-credential-issuer", nil))
	out := map[string]bool{}
	if rec.Code != http.StatusOK {
		return out
	}
	var md map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	supported, _ := md["credential_configurations_supported"].(map[string]any)
	for k := range supported {
		out[k] = true
	}
	return out
}
