package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/store"
)

// Signed userinfo, and what is encrypted to a client. Every response here is opened with
// the client's private key, which this server never held.

// encryptingClient is a client that has registered a key to be encrypted to.
type encryptingClient struct {
	*signInFixture
	private *ecdsa.PrivateKey
	cookie  string
}

func newEncryptingClient(t *testing.T) *encryptingClient {
	t.Helper()
	f := newResponseClient(t, "")
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private.Public(), KeyID: "enc-1", Use: "enc"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET jwks = $2::jsonb WHERE client_id = $1`,
		f.clientID, string(jwks)); err != nil {
		t.Fatal(err)
	}
	return &encryptingClient{signInFixture: f, private: private, cookie: f.signInAndReturnCookie(t)}
}

// set writes the columns a test is about, as named.
func (c *encryptingClient) set(t *testing.T, sql string) {
	t.Helper()
	if _, err := c.pool.Exec(context.Background(), `UPDATE core.clients SET `+sql+` WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
}

// decrypted opens what was encrypted to the client.
func (c *encryptingClient) decrypted(t *testing.T, raw string) string {
	t.Helper()
	object, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("not encrypted: %q: %v", raw, err)
	}
	plain, err := object.Decrypt(c.private)
	if err != nil {
		t.Fatalf("it does not open with the client's key: %v", err)
	}
	return string(plain)
}

func (c *encryptingClient) userinfo(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	token := c.redeemPlain(t, c.authorizePlain(t, c.cookie))["access_token"].(string)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// OIDC Core §2: "If the ID Token is encrypted, it MUST be signed then encrypted".
func TestAnIDTokenIsSignedThenEncryptedToTheClient(t *testing.T) {
	c := newEncryptingClient(t)
	c.set(t, `id_token_encrypted_response_alg = 'ECDH-ES', id_token_encrypted_response_enc = 'A256GCM'`)
	body := c.redeemPlain(t, c.authorizePlain(t, c.cookie))
	raw, _ := body["id_token"].(string)
	if strings.Count(raw, ".") != 4 {
		t.Fatalf("the token endpoint gave %q", raw)
	}
	inner := c.verified(t, c.decrypted(t, raw), c.srv.cfg.Issuer)
	if inner["sub"] == nil {
		t.Errorf("what opened is not an ID token: %v", inner)
	}
	if access, _ := body["access_token"].(string); strings.Count(access, ".") != 2 {
		t.Errorf("an access token is for a resource server and was encrypted to the client: %q", access)
	}

	// And on the front channel, where it travels through the browser.
	_, outer := carried(t, c.authorizeWith(t, c.cookie, url.Values{"response_type": {"code id_token"},
		"nonce": {"n-0S6_WzA2Mj"}}))
	hybrid := c.verified(t, c.decrypted(t, outer.Get("id_token")), c.srv.cfg.Issuer)
	if hybrid["c_hash"] == nil {
		t.Errorf("what opened is not the hybrid token: %v", hybrid)
	}
}

// §5.3.2, each way a client can ask.
func TestUserinfoAnswersTheWayTheClientAsked(t *testing.T) {
	c := newEncryptingClient(t)
	const both = `userinfo_signed_response_alg = 'ES256',
		userinfo_encrypted_response_alg = 'ECDH-ES', userinfo_encrypted_response_enc = 'A256GCM'`

	plain := c.userinfo(t)
	if !strings.HasPrefix(plain.Header().Get("Content-Type"), "application/json") {
		t.Errorf("with nothing asked for it answered %q", plain.Header().Get("Content-Type"))
	}

	c.set(t, `userinfo_signed_response_alg = 'ES256'`)
	signed := c.userinfo(t)
	if signed.Header().Get("Content-Type") != "application/jwt" {
		t.Errorf("signed, it answered %q", signed.Header().Get("Content-Type"))
	}
	// verified holds it to §5.3.2: "MUST contain the Claims iss (issuer) and aud".
	if claims := c.verified(t, signed.Body.String(), c.srv.cfg.Issuer); claims["sub"] == nil {
		t.Errorf("signed, it said %v", claims)
	}

	c.set(t, both)
	nested := c.userinfo(t)
	if nested.Header().Get("Content-Type") != "application/jwt" {
		t.Errorf("signed and encrypted, it answered %q", nested.Header().Get("Content-Type"))
	}
	if claims := c.verified(t, c.decrypted(t, nested.Body.String()), c.srv.cfg.Issuer); claims["sub"] == nil {
		t.Errorf("signed and encrypted, it said %v", claims)
	}

	// "The response MAY be encrypted without also being signed."
	c.set(t, `userinfo_signed_response_alg = NULL`)
	sealed := c.userinfo(t)
	var claims map[string]any
	if err := json.Unmarshal([]byte(c.decrypted(t, sealed.Body.String())), &claims); err != nil || claims["sub"] == nil {
		t.Errorf("encrypted alone, it opened to %v (%v)", claims, err)
	}
	if sealed.Header().Get("Content-Type") != "application/jwt" {
		t.Errorf("encrypted alone, it answered %q", sealed.Header().Get("Content-Type"))
	}
}

// JARM §2.2: "the JSON document will be signed then encrypted".
func TestAnAuthorizationResponseIsSignedThenEncrypted(t *testing.T) {
	c := newEncryptingClient(t)
	c.set(t, `authorization_encrypted_response_alg = 'ECDH-ES', authorization_encrypted_response_enc = 'A256GCM'`)
	// Signed RS256 by default, which this fixture has no key for.
	c.set(t, `authorization_signed_response_alg = 'ES256'`)
	for _, tc := range signedModes {
		_, outer := carried(t, c.authorizeWith(t, c.cookie, url.Values{"response_mode": {tc.mode}}))
		if len(outer) != 1 {
			t.Fatalf("%s carried %v", tc.mode, outer)
		}
		claims := c.opened(t, c.decrypted(t, outer.Get("response")), c.srv.cfg.Issuer)
		if claims["code"] == nil || claims["state"] != "s" {
			t.Errorf("%s said %v", tc.mode, claims)
		}
	}

	// A refusal of a plain mode reaches it the same way: asking for encryption asks for
	// a signature too, and a plain response would be neither.
	_, outer := carried(t, c.authorizeWith(t, c.cookie, url.Values{"response_mode": {"query"}}))
	if claims := c.opened(t, c.decrypted(t, outer.Get("response")), c.srv.cfg.Issuer); claims["error"] != "invalid_request" {
		t.Errorf("a plain mode for a client that encrypts said %v", claims)
	}
}

// A client that asked for encryption gets it or gets nothing. Its keys can only go away
// by hand, since every writer refuses that, and then nothing goes out in the clear.
func TestWhatCannotBeEncryptedIsNotSent(t *testing.T) {
	c := newEncryptingClient(t)
	token := c.redeemPlain(t, c.authorizePlain(t, c.cookie))["access_token"].(string)
	unredeemed, err := url.Parse(c.authorizePlain(t, c.cookie).Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	c.set(t, `jwks = NULL, id_token_encrypted_response_alg = 'ECDH-ES', id_token_encrypted_response_enc = 'A256GCM',
		userinfo_encrypted_response_alg = 'ECDH-ES', userinfo_encrypted_response_enc = 'A256GCM',
		authorization_encrypted_response_alg = 'ECDH-ES', authorization_encrypted_response_enc = 'A256GCM',
		authorization_signed_response_alg = 'ES256'`)

	form := url.Values{"grant_type": {"authorization_code"}, "code": {unredeemed.Query().Get("code")},
		"client_id": {c.clientID}, "redirect_uri": {"https://rp.test/cb"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	redeem := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	redeem.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	redeemed := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(redeemed, redeem)
	if redeemed.Code != http.StatusInternalServerError || strings.Contains(redeemed.Body.String(), "id_token") {
		t.Errorf("the token endpoint with no key answered %d %.200s", redeemed.Code, redeemed.Body)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	userinfo := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(userinfo, req)
	if userinfo.Code != http.StatusInternalServerError || strings.Contains(userinfo.Body.String(), `"sub"`) {
		t.Errorf("userinfo with no key answered %d %.200s", userinfo.Code, userinfo.Body)
	}

	response := c.authorizeWith(t, c.cookie, url.Values{"response_mode": {"jwt"}})
	if response.Code != http.StatusInternalServerError || response.Header().Get("Location") != "" {
		t.Errorf("a response with no key answered %d %q", response.Code, response.Header().Get("Location"))
	}

	hybrid := c.authorizeWith(t, c.cookie, url.Values{"response_type": {"code id_token"}, "nonce": {"n"},
		"response_mode": {"jwt"}})
	if hybrid.Code != http.StatusInternalServerError || hybrid.Header().Get("Location") != "" {
		t.Errorf("a hybrid response with no key answered %d %q", hybrid.Code, hybrid.Header().Get("Location"))
	}
}

// The rules each road to these settings shares.
func TestEncryptionNeedsAKeyAndAnAlgorithmThatIsOffered(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	set := func(s store.ClientSettings) error {
		t.Helper()
		return setClientSettings(t, f, s)
	}
	text := func(s string) *string { return &s }

	if err := set(store.ClientSettings{IDTokenEncryptedAlg: text("ECDH-ES")}); !errors.Is(err, store.ErrInvalidClientSetting) ||
		!strings.Contains(err.Error(), "set-keys") {
		t.Errorf("encrypting with no key answered %v", err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	marked, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private.Public(), KeyID: "e", Use: "enc"}}})
	if err != nil {
		t.Fatal(err)
	}
	signing, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private.Public(), KeyID: "s", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	hash := "untouched"
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET client_secret_hash = $2 WHERE client_id = $1`,
		f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetClientMessageKeys(ctx, f.pool, f.clientID, marked); err != nil {
		t.Fatal(err)
	}
	var method, secret string
	if err := f.pool.QueryRow(ctx, `SELECT token_endpoint_auth_method, COALESCE(client_secret_hash, '')
		FROM core.clients WHERE client_id = $1`, f.clientID).Scan(&method, &secret); err != nil {
		t.Fatal(err)
	}
	if method == "private_key_jwt" || secret != hash {
		t.Errorf("registering keys to be encrypted to changed how the client authenticates: %q, secret %q", method, secret)
	}

	for name, s := range map[string]store.ClientSettings{
		"no such algorithm":     {IDTokenEncryptedAlg: text("RSA1_5")},
		"a shared key":          {UserinfoEncryptedAlg: text("dir")},
		"no such encryption":    {AuthorizationEncryptedAlg: text("ECDH-ES"), AuthorizationEncryptedEnc: text("A128CTR")},
		"encryption alone":      {IDTokenEncryptedEnc: text("A256GCM")},
		"a key of another kind": {UserinfoEncryptedAlg: text("RSA-OAEP-256")},
	} {
		if err := set(s); !errors.Is(err, store.ErrInvalidClientSetting) {
			t.Errorf("%s answered %v", name, err)
		}
	}

	// JARM §3: "the default for this value is A128CBC-HS256".
	if err := set(store.ClientSettings{IDTokenEncryptedAlg: text("ECDH-ES")}); err != nil {
		t.Fatal(err)
	}
	got, err := store.ClientSettingsOf(ctx, f.pool, f.clientID)
	if err != nil || got.IDTokenEncryption.Alg != "ECDH-ES" || got.IDTokenEncryption.Enc != "A128CBC-HS256" {
		t.Errorf("stored %+v (%v)", got.IDTokenEncryption, err)
	}

	// Keys cannot be replaced from under what is encrypted to them.
	if _, err := store.SetClientMessageKeys(ctx, f.pool, f.clientID, signing); !errors.Is(err, store.ErrInvalidClientSetting) {
		t.Errorf("replacing the only key to encrypt to answered %v", err)
	}
	if _, err := store.SetClientKeys(ctx, f.pool, f.clientID, signing); !errors.Is(err, store.ErrInvalidClientSetting) {
		t.Errorf("replacing it through private_key_jwt answered %v", err)
	}

	if err := set(store.ClientSettings{IDTokenEncryptedAlg: text("")}); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ClientSettingsOf(ctx, f.pool, f.clientID); err != nil || got.IDTokenEncryption.Alg != "" || got.IDTokenEncryption.Enc != "" {
		t.Errorf("turning it off left %+v (%v)", got.IDTokenEncryption, err)
	}

	// Registration, which used to drop all of this and leave a client asking for
	// encryption with plaintext.
	register := func(body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(body))
		req.RemoteAddr = freshAddress() + ":443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+registrationToken(t, f))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, out := register(`{"redirect_uris":["https://rp.test/cb"],"id_token_encrypted_response_alg":"ECDH-ES",
		"id_token_encrypted_response_enc":"A256GCM","jwks":` + string(marked) + `}`)
	id, _ := out["client_id"].(string)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	if code != http.StatusCreated || out["id_token_encrypted_response_alg"] != "ECDH-ES" ||
		out["id_token_encrypted_response_enc"] != "A256GCM" {
		t.Errorf("registering encryption answered %d %v", code, out)
	}
	if code, out := register(`{"redirect_uris":["https://rp.test/cb"],"id_token_encrypted_response_alg":"ECDH-ES"}`); code != http.StatusBadRequest ||
		out["error"] != "invalid_client_metadata" {
		t.Errorf("encryption with no keys registered: %d %v", code, out)
		if id, _ := out["client_id"].(string); id != "" {
			_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id)
		}
	}
}
