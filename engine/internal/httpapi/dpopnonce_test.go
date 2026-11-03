package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
)

func nonceRoot(t *testing.T) *keys.RootKey {
	t.Helper()
	secret := make([]byte, 32)
	secret[0] = 3
	root, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// proofWith is a proof for the token endpoint carrying a nonce, none when empty.
func (p *proofKey) proofWith(t *testing.T, nonce string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderType, "dpop+jwt").WithHeader("jwk", p.jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"jti": fmt.Sprintf("n-%d", time.Now().UnixNano()), "htm": http.MethodPost,
		"htu": tokenTestIssuer + oidc.PathToken, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	body, _ := json.Marshal(claims)
	obj, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *tokenFixture) tokenRequest(t *testing.T, proof string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"none"}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// §8: a proof with no nonce, or a stale one, is sent back with the value to use, and a
// client that does so gets past this check.
func TestAProofMustCarryARecentNonce(t *testing.T) {
	f := newTokenFixture(t)
	f.srv.SetRootKey(nonceRoot(t))
	f.srv.SetDPoPNonces(true)
	p := newProofKey(t)

	demanded := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusBadRequest || body["error"] != "use_dpop_nonce" {
			t.Fatalf("answered %d: %s", rec.Code, rec.Body.String())
		}
		values := rec.Header().Values("DPoP-Nonce")
		if len(values) != 1 {
			t.Fatalf("%d DPoP-Nonce headers: §8 allows one", len(values))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("a response carrying a nonce can be cached: %q", rec.Header().Get("Cache-Control"))
		}
		return values[0]
	}

	nonce := demanded(f.tokenRequest(t, p.proofWith(t, "")))
	if !regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`).MatchString(nonce) {
		t.Errorf("%q is not 1*NQCHAR", nonce)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(nonce); err != nil || len(raw) < 16 {
		t.Errorf("%q is too short to be unpredictable", nonce)
	}
	demanded(f.tokenRequest(t, p.proofWith(t, "made-up")))

	// With it, the request reaches the grant, which refuses the made-up token: the
	// proof itself is no longer the objection.
	rec := f.tokenRequest(t, p.proofWith(t, nonce))
	if strings.Contains(rec.Body.String(), "use_dpop_nonce") || strings.Contains(rec.Body.String(), "invalid_dpop_proof") {
		t.Errorf("a current nonce answered %d: %s", rec.Code, rec.Body.String())
	}

	// One from the last window still works; older does not.
	now := time.Now()
	if !f.srv.dpopNonceRecent(f.srv.dpopNonceAt(now.Add(-dpopNonceWindow)), now) {
		t.Error("a nonce from the last window was refused")
	}
	stale := f.srv.dpopNonceAt(now.Add(-3 * dpopNonceWindow))
	if f.srv.dpopNonceRecent(stale, now) {
		t.Error("a stale nonce was accepted")
	}
	demanded(f.tokenRequest(t, p.proofWith(t, stale)))
}

// §9: a protected resource says the same thing with a 401.
func TestAResourceAsksForANonceToo(t *testing.T) {
	f := newTokenFixture(t)
	f.srv.SetRootKey(nonceRoot(t))
	f.srv.SetDPoPNonces(true)
	p := newProofKey(t)
	r := httptest.NewRequest(http.MethodPost, "/oauth2/userinfo", nil)
	r.Header.Set("DPoP", p.resourceProof(t, f.srv.cfg.Issuer+"/oauth2/userinfo", "a-token"))
	rec := httptest.NewRecorder()
	if !f.srv.boundTokenRefused(rec, r, "a-token", &tokens.Confirmation{JKT: p.thumbprint(t)}, "test", false) {
		t.Fatal("a proof with no nonce was accepted")
	}
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("DPoP-Nonce") == "" ||
		!strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Errorf("answered %d, %q, %q", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Header().Get("DPoP-Nonce"))
	}
}

// A nonce is this server's: another issuer, or a nonce made without the root key, is
// not the same value.
func TestANonceCannotBeWorkedOut(t *testing.T) {
	f := newTokenFixture(t)
	f.srv.SetRootKey(nonceRoot(t))
	f.srv.SetDPoPNonces(true)
	now := time.Now()
	ours := f.srv.dpopNonceAt(now)
	secret := make([]byte, 32)
	secret[0] = 4
	other, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.root = other
	if f.srv.dpopNonceAt(now) == ours {
		t.Error("two root keys gave one nonce")
	}
}

// Left off, nothing changes: a client that cannot retry goes on working.
func TestNoNonceIsDemandedUnasked(t *testing.T) {
	f := newTokenFixture(t)
	f.srv.SetRootKey(nonceRoot(t))
	rec := f.tokenRequest(t, newProofKey(t).proofWith(t, ""))
	if strings.Contains(rec.Body.String(), "use_dpop_nonce") || rec.Header().Get("DPoP-Nonce") != "" {
		t.Errorf("answered %d: %s", rec.Code, rec.Body.String())
	}
	f.srv.root = nil
	f.srv.SetDPoPNonces(true)
	if f.srv.dpopNonces {
		t.Error("nonces were turned on with nothing to make them from")
	}
}
