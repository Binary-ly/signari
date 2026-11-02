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

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
)

// RFC 9701, and FAPI 2.0 Message Signing's other two halves.

// resourceServer is a confidential client asking about a token it holds.
type resourceServer struct {
	*tokenFixture
	secret, access string
}

func newResourceServer(t *testing.T) *resourceServer {
	t.Helper()
	f := newTokenFixture(t)
	const verifier = "verifier-for-a-signed-introspection-0123456789abc"
	status, body := f.post(t, f.redeem(f.issueCode(t, verifier), verifier))
	if status != http.StatusOK {
		t.Fatalf("redemption: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET client_type = 'confidential',
		client_secret_hash = $2, token_endpoint_auth_method = 'client_secret_post' WHERE client_id = $1`,
		f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	return &resourceServer{tokenFixture: f, secret: secret, access: access}
}

func (rs *resourceServer) introspect(t *testing.T, accept string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, oidc.PathIntrospection, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	rs.srv.Routes().ServeHTTP(rec, req)
	return rec
}

func (rs *resourceServer) asked(token string) url.Values {
	return url.Values{"token": {token}, "client_id": {rs.clientID}, "client_secret": {rs.secret}}
}

func (rs *resourceServer) set(t *testing.T, sql string) {
	t.Helper()
	if _, err := rs.pool.Exec(context.Background(), `UPDATE core.clients SET `+sql+` WHERE client_id = $1`, rs.clientID); err != nil {
		t.Fatal(err)
	}
}

// verifiedIntrospection reads a response as a resource server should, typ first.
func (rs *resourceServer) verifiedIntrospection(t *testing.T, raw string) (map[string]any, map[string]any) {
	t.Helper()
	token, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatalf("no signed response in %q: %v", raw, err)
	}
	key, published := rs.srv.cfg.Keys.ByKID(token.Signatures[0].Header.KeyID)
	if !published {
		t.Fatalf("signed by a key nobody published")
	}
	payload, err := token.Verify(key.Signer().Public())
	if err != nil {
		t.Fatal(err)
	}
	// §5: "the JWT typ ("type") header parameter to "token-introspection+jwt"".
	if typ := token.Signatures[0].Protected.ExtraHeaders[jose.HeaderType]; typ != "token-introspection+jwt" {
		t.Errorf("typ is %v", typ)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != rs.srv.cfg.Issuer || claims["aud"] != rs.clientID {
		t.Errorf("iss %v, aud %v", claims["iss"], claims["aud"])
	}
	if iat, _ := claims["iat"].(float64); time.Since(time.Unix(int64(iat), 0)) > time.Minute {
		t.Errorf("iat is %v", claims["iat"])
	}
	// §5: "SHOULD NOT include the sub and exp claims".
	for _, name := range []string{"sub", "exp", "active", "scope"} {
		if _, there := claims[name]; there {
			t.Errorf("%s is at the top level, where it reads as a token's", name)
		}
	}
	inner, _ := claims["token_introspection"].(map[string]any)
	return claims, inner
}

func TestAnIntrospectionAnswerIsSignedWhenItIsAskedForSigned(t *testing.T) {
	rs := newResourceServer(t)
	rs.set(t, `introspection_signed_response_alg = 'ES256'`)

	plain := rs.introspect(t, "", rs.asked(rs.access))
	if plain.Code != http.StatusOK || !strings.HasPrefix(plain.Header().Get("Content-Type"), "application/json") {
		t.Errorf("unasked it answered %d %q", plain.Code, plain.Header().Get("Content-Type"))
	}

	rec := rs.introspect(t, introspectionJWT, rs.asked(rs.access))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != introspectionJWT {
		t.Fatalf("asked, it answered %d %q: %.200s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control is %q", rec.Header().Get("Cache-Control"))
	}
	if _, inner := rs.verifiedIntrospection(t, rec.Body.String()); inner["active"] != true || inner["sub"] == nil {
		t.Errorf("it said %v", inner)
	}

	// §5: "MUST set the value of the active member ... to false and MUST NOT include
	// other members."
	gone := rs.introspect(t, introspectionJWT, rs.asked("nothing-this-server-issued"))
	if _, inner := rs.verifiedIntrospection(t, gone.Body.String()); len(inner) != 1 || inner["active"] != false {
		t.Errorf("about a token it never issued, it said %v", inner)
	}
}

// §5: "MUST refuse to serve introspection requests that don't authenticate the caller
// and return an HTTP status code 400", which is not what RFC 7662's caller gets.
func TestAnUnauthenticatedAskForASignedAnswerIs400(t *testing.T) {
	rs := newResourceServer(t)
	wrong := url.Values{"token": {rs.access}, "client_id": {rs.clientID}, "client_secret": {"not-it"}}
	rec := rs.introspect(t, introspectionJWT, wrong)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("a bad secret, asking for a JWT, answered %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if plain := rs.introspect(t, "", wrong); plain.Code != http.StatusUnauthorized {
		t.Errorf("a bad secret, asking for JSON, answered %d", plain.Code)
	}
	rs.set(t, `client_type = 'public', client_secret_hash = NULL, token_endpoint_auth_method = 'none'`)
	public := rs.introspect(t, introspectionJWT, url.Values{"token": {rs.access}, "client_id": {rs.clientID}})
	if public.Code != http.StatusBadRequest {
		t.Errorf("a public client, asking for a JWT, answered %d", public.Code)
	}
}

// §6: "The default, if omitted, is RS256." With no such key nothing is sent, and JSON
// would be the downgrade §5 warns of.
func TestAnIntrospectionAnswerNobodyCanSignIsNotSent(t *testing.T) {
	rs := newResourceServer(t)
	rec := rs.introspect(t, introspectionJWT, rs.asked(rs.access))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "active") {
		t.Errorf("with no RS256 key it answered %d %.200s", rec.Code, rec.Body)
	}

	generated, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(generated, keys.StateActive)
	next, err := keys.NewSet(append(rs.srv.cfg.Keys.Keys(), active)...)
	if err != nil {
		t.Fatal(err)
	}
	rs.srv.cfg.Keys = next
	signed := rs.introspect(t, introspectionJWT, rs.asked(rs.access))
	if alg, _ := tokenHeader(t, signed.Body.String()); alg != "RS256" {
		t.Errorf("with nothing set it is signed %s", alg)
	}
}

// RFC 9701's default is one FAPI rules out, and this fixture has no RS256 key to prove it.
func TestAClientHeldToFAPIIsNotAnsweredInRS256(t *testing.T) {
	rs := newResourceServer(t)
	rs.set(t, `security_profile = 'fapi2'`)
	rec := rs.introspect(t, introspectionJWT, rs.asked(rs.access))
	if alg, _ := tokenHeader(t, rec.Body.String()); alg != "ES256" {
		t.Errorf("a client held to FAPI is signed %s", alg)
	}
}

func TestAnIntrospectionAnswerIsSignedThenEncrypted(t *testing.T) {
	rs := newResourceServer(t)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private.Public(), KeyID: "rs", Use: "enc"}}})
	if err != nil {
		t.Fatal(err)
	}
	rs.set(t, `introspection_signed_response_alg = 'ES256', introspection_encrypted_response_alg = 'ECDH-ES',
		introspection_encrypted_response_enc = 'A256GCM', jwks = '`+string(jwks)+`'::jsonb`)
	rec := rs.introspect(t, introspectionJWT, rs.asked(rs.access))
	object, err := jose.ParseEncrypted(rec.Body.String(), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("not encrypted: %.200s: %v", rec.Body, err)
	}
	opened, err := object.Decrypt(private)
	if err != nil {
		t.Fatal(err)
	}
	if _, inner := rs.verifiedIntrospection(t, string(opened)); inner["active"] != true {
		t.Errorf("it said %v", inner)
	}
}

// Message Signing §5.3.1 and §5.4.1, a whole sign-in for a client held to both: only a
// signed request, only at the push, and only a signed response back.
func TestMessageSigningHoldsAClientToBothEnds(t *testing.T) {
	c := newSigningClient(t)
	ctx := context.Background()
	if _, err := c.pool.Exec(ctx, `UPDATE core.clients SET client_type = 'confidential',
		token_endpoint_auth_method = 'private_key_jwt', dpop_bound_access_tokens = true,
		require_pushed_authorization = true, require_signed_request_object = true,
		authorization_signed_response_alg = 'ES256', response_types = ARRAY['code'],
		security_profile = 'fapi2-message-signing' WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	push := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		form.Set("client_id", c.clientID)
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", c.assertionFrom(t, c.key, c.clientID))
		req := httptest.NewRequest(http.MethodPost, "/oauth2/par", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		c.srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	plain, err := url.ParseQuery(c.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	if rec := push(plain); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "sign") {
		t.Errorf("an unsigned push answered %d %.200s", rec.Code, rec.Body)
	}

	// §5.3.1 asks for both dates, which a request object need not otherwise carry.
	claims := c.claims()
	if rec := push(url.Values{"request": {signRequest(t, c.key, jose.ES256, "good", claims)}}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "nbf") {
		t.Errorf("a request object with no nbf answered %d %.200s", rec.Code, rec.Body)
	}

	claims["nbf"] = time.Now().Unix()
	claims["response_mode"] = "jwt"
	object := signRequest(t, c.key, jose.ES256, "good", claims)
	pushed := push(url.Values{"request": {object}})
	var out struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &out); err != nil || out.RequestURI == "" {
		t.Fatalf("a good push answered %d %.200s", pushed.Code, pushed.Body)
	}

	// §5.3.1 is "at the PAR endpoint": the same object by value is not a push.
	byValue := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+url.Values{
		"client_id": {c.clientID}, "request": {object}}.Encode(), nil)
	refused := httptest.NewRecorder()
	c.srv.handleAuthorize(refused, byValue)
	if strings.Contains(refused.Header().Get("Location"), "response=") || strings.Contains(refused.Body.String(), `name="password"`) {
		t.Errorf("a request object by value got somewhere: %d %q", refused.Code, refused.Header().Get("Location"))
	}

	arrived := c.byHandle(t, c.signInAndReturnCookie(t), out.RequestURI)
	_, params := carried(t, arrived)
	if got := c.opened(t, params.Get("response"), c.srv.cfg.Issuer); got["code"] == nil || got["state"] != "signed-state" {
		t.Errorf("the response said %v", got)
	}
}
