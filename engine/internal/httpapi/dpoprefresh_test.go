package httpapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oidc"
)

// RFC 9449 §5, the second sentence:
//
//	"When an authorization server supporting DPoP issues a refresh token to a
//	public client that presents a valid DPoP proof at the token endpoint, the
//	refresh token MUST be bound to the respective public key. The binding MUST
//	be validated when the refresh token is later presented to get new access
//	tokens."
//
// The token endpoint verified proofs correctly before this: well formed, in
// date, unreplayed, signed by the key it names. That is a check on the PROOF.
// The binding is a different check, and its absence meant a stolen refresh
// token could be replayed by anyone holding any key -- they present it with
// their own, the proof verifies because it is a genuine proof of their key, and
// they receive a fresh access token bound to themselves. The access token was
// sender-constrained; the credential that mints new ones, and outlives them all,
// was not.

type proofKey struct {
	priv *ecdsa.PrivateKey
	jwk  jose.JSONWebKey
}

func newProofKey(t *testing.T) *proofKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &proofKey{priv: k, jwk: jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"}}
}

func (p *proofKey) thumbprint(t *testing.T) string {
	t.Helper()
	th, err := p.jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(th)
}

// proof builds a DPoP proof for the token endpoint. jti varies per call because
// the server refuses a replayed proof, and every refresh in these tests is a
// separate request.
func (p *proofKey) proof(t *testing.T, jti string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).
		WithHeader(jose.HeaderType, "dpop+jwt").
		WithHeader("jwk", p.jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"jti": jti,
		"htm": http.MethodPost,
		"htu": tokenTestIssuer + oidc.PathToken,
		"iat": time.Now().Unix(),
	})
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

// postDPoP is f.post with a proof attached.
func (f *tokenFixture) postDPoP(t *testing.T, form url.Values, proof string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// boundRefreshToken runs a full code redemption under a DPoP proof and returns
// the refresh token the family bound to that key.
func (f *tokenFixture) boundRefreshToken(t *testing.T, key *proofKey, verifier string) string {
	t.Helper()
	code := f.issueCodeWithDetailsAndScopes(t, verifier, nil,
		[]string{"openid", "offline_access"})

	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {f.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {verifier},
	}, key.proof(t, "jti-issue-"+verifier[:12]))
	if status != http.StatusOK {
		t.Fatalf("redemption under DPoP gave %d: %v", status, body)
	}
	if got := body["token_type"]; got != "DPoP" {
		t.Fatalf("token_type is %v, so the request was not treated as "+
			"sender-constrained and the test proves nothing", got)
	}
	rt, ok := body["refresh_token"].(string)
	if !ok {
		t.Fatalf("no refresh token issued: %v", body)
	}
	return rt
}

// The attack the binding exists to stop.
func TestARefreshTokenCannotBeUsedWithADifferentDPoPKey(t *testing.T) {
	f := newTokenFixture(t)
	victim := newProofKey(t)
	thief := newProofKey(t)
	if victim.thumbprint(t) == thief.thumbprint(t) {
		t.Fatal("the two test keys are identical; the test cannot distinguish them")
	}

	rt := f.boundRefreshToken(t, victim, "verifier-dpop-refresh-aaaaaaaaaaaaaaaaaaaaaa")

	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {f.clientID},
	}, thief.proof(t, "jti-thief-0001"))

	if status == http.StatusOK {
		t.Fatalf("a refresh token bound to one key was accepted with a proof for "+
			"another: a stolen refresh token mints access tokens for the thief, "+
			"and sender-constraining is defeated for the longest-lived credential "+
			"in the grant: %v", body)
	}
	if body["error"] != "invalid_dpop_proof" {
		t.Fatalf("refused with %v, want invalid_dpop_proof", body["error"])
	}
}

// Stripping the header entirely must not be a way around the binding. This is
// the more likely attempt of the two: a thief with no key at all.
func TestABoundRefreshTokenIsRefusedWithNoProofAtAll(t *testing.T) {
	f := newTokenFixture(t)
	key := newProofKey(t)
	rt := f.boundRefreshToken(t, key, "verifier-dpop-refresh-bbbbbbbbbbbbbbbbbbbbbb")

	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {f.clientID},
	}, "")

	if status == http.StatusOK {
		t.Fatalf("a bound refresh token was accepted with no DPoP proof; omitting "+
			"the header cannot be the way to escape the binding: %v", body)
	}

	// The refusal must say WHICH thing is wrong.
	//
	// Security does not depend on this: with no proof the presented thumbprint
	// is empty, and a constant-time compare against a real one fails on length
	// alone -- mutation confirmed the request is refused either way. What the
	// separate branch buys is a client being told to attach a proof rather than
	// being told its key is the wrong one, which sends a developer looking for a
	// key mismatch that does not exist. Asserted here so the branch has a reason
	// that can fail; without this, it is a line nobody could tell had been
	// deleted.
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "must be") || !strings.Contains(desc, "proof of possession") {
		t.Fatalf("the refusal says %q; a client with no proof needs to be told to "+
			"send one, not that its key does not match", desc)
	}
}

// And the legitimate client keeps working -- a binding that refuses everyone is
// not a binding, it is an outage.
func TestTheBoundKeyStillRefreshesSuccessfully(t *testing.T) {
	f := newTokenFixture(t)
	key := newProofKey(t)
	rt := f.boundRefreshToken(t, key, "verifier-dpop-refresh-cccccccccccccccccccccc")

	status, body := f.postDPoP(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {f.clientID},
	}, key.proof(t, "jti-legit-0001"))

	if status != http.StatusOK {
		t.Fatalf("the bound key was refused its own refresh token: %d %v", status, body)
	}
	if got := body["token_type"]; got != "DPoP" {
		t.Fatalf("the refreshed token is %v, not DPoP: the binding survived but "+
			"the constraint on the new access token did not", got)
	}

	// The binding must survive rotation too: §5 says the client "MUST present a
	// DPoP proof for the same key ... EACH TIME that refresh token is used".
	rotated := body["refresh_token"].(string)
	thief := newProofKey(t)
	status, _ = f.postDPoP(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated},
		"client_id": {f.clientID},
	}, thief.proof(t, "jti-thief-0002"))
	if status == http.StatusOK {
		t.Fatal("the successor token accepted a different key: the binding held " +
			"for one rotation and was lost at the next")
	}
}
