package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oidc"
)

// signingClient is a client with a registered key, and the claims of a request that
// would be accepted, for a test to change one of.
type signingClient struct {
	*signInFixture
	key *ecdsa.PrivateKey
}

func newSigningClient(t *testing.T) *signingClient {
	t.Helper()
	f := newSignInFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "good", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET jwks = $2::jsonb, first_party = true WHERE client_id = $1`,
		f.clientID, string(jwks)); err != nil {
		t.Fatal(err)
	}
	return &signingClient{signInFixture: f, key: key}
}

func (c *signingClient) claims() map[string]any {
	return map[string]any{
		"iss": c.clientID, "aud": c.srv.cfg.Issuer, "client_id": c.clientID,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "response_type": "code", "scope": "openid",
		"redirect_uri": "https://rp.test/cb", "state": "signed-state",
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256",
	}
}

func signRequest(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The request is what the client signed, and nothing a browser added to the URL counts:
// RFC 9101 §6.3. From the signature to a code a client redeems.
func TestARequestObjectIsTheRequestAndNotTheQuery(t *testing.T) {
	c := newSigningClient(t)
	b := newTestBrowser(t, c.srv.Routes())
	b.post("/login", b.get("/login"), url.Values{"username": {c.email}, "password": {signInTestPassword}})
	if b.value(SessionCookieName) == "" {
		t.Fatal("the fixture did not sign in")
	}
	coded := b.get(oidc.PathAuthorize + "?" + url.Values{
		"client_id": {c.clientID}, "request": {signRequest(t, c.key, jose.ES256, "good", c.claims())},
		"state": {"tampered"}, "scope": {"openid admin"}, "redirect_uri": {"https://evil.test/cb"},
	}.Encode())
	loc, err := url.Parse(coded.Header().Get("Location"))
	if err != nil || loc.Host != "rp.test" {
		t.Fatalf("the request went to %q (%d): %.200s", coded.Header().Get("Location"), coded.Code, coded.Body.String())
	}
	if loc.Query().Get("state") != "signed-state" {
		t.Errorf("the state came from the URL and not the object: %q", loc.Query().Get("state"))
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code: %s", loc)
	}
	tokens := c.redeemPlain(t, coded)
	if tokens["access_token"] == nil {
		t.Errorf("the code redeemed to %v", tokens)
	}
}

// What the pages hand on through the browser is a handle. Spread over a URL, the
// parameters would be open to whoever holds the browser, and the signature bought nothing.
func TestAPersonSigningInCarriesAHandleAndNotTheRequest(t *testing.T) {
	c := newSigningClient(t)
	b := newTestBrowser(t, c.srv.Routes())
	rec := b.get(oidc.PathAuthorize + "?" + url.Values{"client_id": {c.clientID},
		"request": {signRequest(t, c.key, jose.ES256, "good", c.claims())}}.Encode())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("answered %d, to %q: %.200s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	authz := regexp.MustCompile(`name="authz" value="([^"]*)"`).FindStringSubmatch(rec.Body.String())
	if authz == nil {
		t.Fatal("the sign-in page carries no request")
	}
	parked, err := url.ParseQuery(html.UnescapeString(authz[1]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(parked.Get("request_uri"), requestURIPrefix) {
		t.Errorf("no handle in %v", parked)
	}
	for _, leaked := range []string{"redirect_uri", "state", "code_challenge", "scope", "request"} {
		if parked.Has(leaked) {
			t.Errorf("%s reached the browser: %v", leaked, parked)
		}
	}
	if strings.Contains(rec.Body.String(), "signed-state") {
		t.Error("the signed state is on the page")
	}
}

// §6.2: anything short of a signature by the client's own key, on what it says, for this
// server, now, is `invalid_request_object`, and not a request that carries on without it.
func TestARequestObjectThatProvesNothingIsRefused(t *testing.T) {
	c := newSigningClient(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	changed := func(key, value string) map[string]any {
		claims := c.claims()
		claims[key] = value
		return claims
	}
	expired := c.claims()
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	tooLong := c.claims()
	tooLong["exp"] = time.Now().Add(2 * time.Hour).Unix()
	early := c.claims()
	early["nbf"] = time.Now().Add(time.Hour).Unix()
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(mustJSON(t, c.claims())) + "."

	for name, object := range map[string]string{
		"another key":          signRequest(t, other, jose.ES256, "good", c.claims()),
		"a key not registered": signRequest(t, c.key, jose.ES256, "missing", c.claims()),
		"a shared secret":      signRequest(t, []byte("0123456789abcdef0123456789abcdef"), jose.HS256, "good", c.claims()),
		"no signature":         none,
		"another client":       signRequest(t, c.key, jose.ES256, "good", changed("client_id", "somebody-else")),
		"another issuer":       signRequest(t, c.key, jose.ES256, "good", changed("iss", "somebody-else")),
		"another server":       signRequest(t, c.key, jose.ES256, "good", changed("aud", "https://other.test")),
		"expired":              signRequest(t, c.key, jose.ES256, "good", expired),
		"good for too long":    signRequest(t, c.key, jose.ES256, "good", tooLong),
		"not yet good":         signRequest(t, c.key, jose.ES256, "good", early),
		"a request_uri inside": signRequest(t, c.key, jose.ES256, "good", changed("request_uri", "https://x.test/r")),
		"encrypted":            "a.b.c.d.e",
		"garbage":              "not.a.jwt",
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
				"client_id": {c.clientID}, "redirect_uri": {"https://rp.test/cb"}, "request": {object}}.Encode(), nil))
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil || loc.Query().Get("error") != "invalid_request_object" {
				t.Errorf("answered %d, to %q", rec.Code, rec.Header().Get("Location"))
			}
		})
	}

	// With no redirect_uri in the query there is nowhere checked to send a refusal.
	rec := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
		"client_id": {c.clientID}, "request": {signRequest(t, other, jose.ES256, "good", c.claims())}}.Encode(), nil))
	if rec.Code >= 300 && rec.Code < 400 {
		t.Errorf("a refused object was redirected with nothing validated: %q", rec.Header().Get("Location"))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (c *signingClient) push(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("client_id", c.clientID)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = freshAddress() + ":443"
	rec := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// RFC 9101 §10.5, the downgrade: with the signature optional an attacker just leaves it
// off. Held to it, a client's unsigned request goes nowhere, by the front door or a push,
// and a signed one goes through both.
func TestAClientHeldToSigningCannotBeDowngraded(t *testing.T) {
	c := newSigningClient(t)
	ctx := context.Background()
	if _, err := c.pool.Exec(ctx, `UPDATE core.clients SET require_signed_request_object = true WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	b := newTestBrowser(t, c.srv.Routes())
	b.post("/login", b.get("/login"), url.Values{"username": {c.email}, "password": {signInTestPassword}})

	plain := b.get(oidc.PathAuthorize + "?" + c.plainAuthz())
	if loc, _ := url.Parse(plain.Header().Get("Location")); loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("an unsigned request answered %d, to %q", plain.Code, plain.Header().Get("Location"))
	}
	unsigned := url.Values{"response_type": {"code"}, "redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	if rec := c.push(t, unsigned); rec.Code != http.StatusBadRequest {
		t.Errorf("an unsigned push answered %d: %.200s", rec.Code, rec.Body.String())
	}

	byValue := b.get(oidc.PathAuthorize + "?" + url.Values{"client_id": {c.clientID},
		"request": {signRequest(t, c.key, jose.ES256, "good", c.claims())}}.Encode())
	if loc, _ := url.Parse(byValue.Header().Get("Location")); loc == nil || loc.Query().Get("code") == "" {
		t.Errorf("a signed request answered %d, to %q", byValue.Code, byValue.Header().Get("Location"))
	}

	pushed := c.push(t, url.Values{"request": {signRequest(t, c.key, jose.ES256, "good", c.claims())}})
	if pushed.Code != http.StatusCreated {
		t.Fatalf("a signed push answered %d: %.200s", pushed.Code, pushed.Body.String())
	}
	var out struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	coded := b.get(oidc.PathAuthorize + "?" + url.Values{"client_id": {c.clientID}, "request_uri": {out.RequestURI}}.Encode())
	if loc, _ := url.Parse(coded.Header().Get("Location")); loc == nil || loc.Query().Get("code") == "" {
		t.Errorf("redeeming a signed push answered %d, to %q", coded.Code, coded.Header().Get("Location"))
	}
}

// The mark that says a push was signed is this server's. A client saying so itself,
// unsigned, is not then let through once it is held to signing.
func TestAClientCannotSayItSigned(t *testing.T) {
	c := newSigningClient(t)
	pushed := c.push(t, url.Values{"response_type": {"code"}, "redirect_uri": {"https://rp.test/cb"}, "scope": {"openid"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		signedRequestMark: {"1"}})
	if pushed.Code != http.StatusCreated {
		t.Fatalf("the push answered %d: %.200s", pushed.Code, pushed.Body.String())
	}
	var out struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Exec(context.Background(), `UPDATE core.clients SET require_signed_request_object = true WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
		"client_id": {c.clientID}, "request_uri": {out.RequestURI}}.Encode(), nil))
	if loc, _ := url.Parse(rec.Header().Get("Location")); loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("a push claiming a signature answered %d, to %q", rec.Code, rec.Header().Get("Location"))
	}
}

// An object sent by value came through the browser, so it is not the push a client held
// to PAR promised, though it is parked the same way.
func TestARequestObjectByValueIsNotAPush(t *testing.T) {
	c := newSigningClient(t)
	if _, err := c.pool.Exec(context.Background(), `UPDATE core.clients SET require_pushed_authorization = true WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	c.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
		"client_id": {c.clientID}, "request": {signRequest(t, c.key, jose.ES256, "good", c.claims())}}.Encode(), nil))
	if rec.Code != http.StatusBadRequest && !strings.Contains(rec.Body.String(), "pushing") {
		t.Errorf("a by-value object satisfied a PAR-only client: %d, to %q", rec.Code, rec.Header().Get("Location"))
	}
}
