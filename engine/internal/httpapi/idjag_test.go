package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Cross-app access from each end. The issuing half against a server of ours, the
// accepting half against a grant shaped as §3.1 has it, and between them a test that one
// is what the other wants.

const remoteAS = "https://as.chat.example/"

type idJAGFixture struct {
	*tokenFixture
	idToken string
}

// newIDJAGFixture is a confidential client with an ID token of its own and a live session.
func newIDJAGFixture(t *testing.T) *idJAGFixture {
	t.Helper()
	f := &idJAGFixture{tokenFixture: newTokenFixture(t)}
	ctx := context.Background()
	f.enableExchange(t)
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`, f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	f.srv.SetInstance(instanceID)
	f.allow(t, store.IDJAGAudience{Audience: remoteAS, RemoteClientID: "chat-client", Alg: "ES256",
		Resources: []string{"https://api.chat.example/", "https://files.chat.example/"}, Scopes: []string{"chat.read", "chat.write"}})
	f.idToken = f.signIDToken(t, nil)
	return f
}

func (f *idJAGFixture) allow(t *testing.T, a store.IDJAGAudience) {
	t.Helper()
	// Written directly: this fixture's keys are in memory, and the writer asks the
	// database whether the instance holds one.
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO core.id_jag_audiences
		(client_id, audience, org_id, remote_client_id, resources, scopes, signing_alg)
		VALUES ($1, $2, $3::uuid, $4, $5, $6, $7)`, f.clientID, a.Audience, f.orgID, a.RemoteClientID,
		nonNilScopes(a.Resources), nonNilScopes(a.Scopes), a.Alg); err != nil {
		t.Fatal(err)
	}
}

func nonNilScopes(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// signIDToken is what this server hands a client at sign-in, with whatever a test changes.
func (f *idJAGFixture) signIDToken(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": f.srv.cfg.Issuer, "sub": f.userID, "aud": f.clientID, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix(), "sid": f.sid, "amr": []string{"pwd"}, "acr": "1"}
	if change != nil {
		change(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.srv.cfg.Keys.Active("ES256")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tokens.NewSigner(key).SignRaw(payload, "JWT")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *idJAGFixture) exchange(t *testing.T, subject string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {oauth.GrantTypeTokenExchange}, "requested_token_type": {oauth.TokenTypeIDJAG},
		"audience": {remoteAS}, "subject_token": {subject}, "subject_token_type": {oauth.TokenTypeIDToken},
		"client_id": {f.clientID}, "client_secret": {f.exchangeSecret}}
	for name, values := range extra {
		if values == nil {
			delete(form, name)
			continue
		}
		form[name] = values
	}
	return f.post(t, form)
}

func decodedGrant(t *testing.T, raw string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWS", raw)
	}
	read := func(part string) map[string]any {
		body, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	return read(parts[0]), read(parts[1])
}

func TestAClientGetsAGrantForAnotherServer(t *testing.T) {
	f := newIDJAGFixture(t)
	status, resp := f.exchange(t, f.idToken, url.Values{"resource": {"https://api.chat.example/"}, "scope": {"chat.read"}})
	if status != http.StatusOK {
		t.Fatalf("it answered %d %v", status, resp)
	}
	if resp["issued_token_type"] != oauth.TokenTypeIDJAG || resp["token_type"] != "N_A" || resp["refresh_token"] != nil {
		t.Errorf("the response is %v", resp)
	}
	grant, _ := resp["access_token"].(string)
	header, claims := decodedGrant(t, grant)
	if header["typ"] != "oauth-id-jag+jwt" {
		t.Errorf("typ is %v", header["typ"])
	}
	want := map[string]any{"iss": f.srv.cfg.Issuer, "sub": f.userID, "aud": remoteAS, "client_id": "chat-client",
		"resource": "https://api.chat.example/", "scope": "chat.read", "tenant": f.orgID, "acr": "1"}
	for name, value := range want {
		if claims[name] != value {
			t.Errorf("%s is %v, want %v", name, claims[name], value)
		}
	}
	for _, name := range []string{"jti", "iat", "exp", "email", "auth_time", "amr"} {
		if claims[name] == nil {
			t.Errorf("no %s in %v", name, claims)
		}
	}
	if lifetime := claims["exp"].(float64) - claims["iat"].(float64); lifetime <= 0 || lifetime > 600 {
		t.Errorf("it lasts %v seconds", lifetime)
	}
}

// Each thing §4.3.3 and §4.3.4.3 say to refuse, under the code they say.
func TestWhatDoesNotBuyAGrant(t *testing.T) {
	f := newIDJAGFixture(t)
	other := url.Values{}
	for name, c := range map[string]struct {
		subject string
		extra   url.Values
		code    string
	}{
		"two audiences":        {f.idToken, url.Values{"audience": {remoteAS, "https://other.example/"}}, "invalid_request"},
		"no audience":          {f.idToken, url.Values{"audience": nil}, "invalid_request"},
		"an unknown audience":  {f.idToken, url.Values{"audience": {"https://nobody.example/"}}, "invalid_target"},
		"a resource not there": {f.idToken, url.Values{"resource": {"https://elsewhere.example/"}}, "invalid_target"},
		"a scope not there":    {f.idToken, url.Values{"scope": {"chat.admin"}}, "invalid_scope"},
		"details":              {f.idToken, url.Values{"authorization_details": {"[]"}}, "invalid_authorization_details"},
		"another token type":   {f.idToken, url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}, "invalid_request"},
		"nonsense":             {"nonsense", other, "invalid_request"},
		"expired":              {f.signIDToken(t, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), other, "invalid_request"},
		"for another client":   {f.signIDToken(t, func(c map[string]any) { c["aud"] = "somebody-else" }), other, "invalid_request"},
		"no session":           {f.signIDToken(t, func(c map[string]any) { delete(c, "sid") }), other, "invalid_request"},
		"an ended session":     {f.signIDToken(t, func(c map[string]any) { c["sid"] = "gone" }), other, "invalid_request"},
		"another issuer":       {f.signIDToken(t, func(c map[string]any) { c["iss"] = "https://evil.example" }), other, "invalid_request"},
	} {
		status, resp := f.exchange(t, c.subject, c.extra)
		if status != http.StatusBadRequest || resp["error"] != c.code {
			t.Errorf("%s answered %d %v, want %s", name, status, resp, c.code)
		}
	}
}

// §4.3.3: "A token that the IdP issued for a different purpose, such as an access token,
// an ID-JAG, or a client assertion, MUST NOT be accepted as an Identity Assertion."
func TestOnlyAnIDTokenIsAnIDToken(t *testing.T) {
	f := newIDJAGFixture(t)
	access := f.mintAccessToken(t, "openid")
	_, resp := f.exchange(t, f.idToken, nil)
	grant, _ := resp["access_token"].(string)
	if grant == "" {
		t.Fatalf("no grant: %v", resp)
	}
	key, err := f.srv.cfg.Keys.Active("ES256")
	if err != nil {
		t.Fatal(err)
	}
	// A signed userinfo response is a JWT with this client's aud, and no exp.
	userinfo, err := tokens.NewSigner(key).SignRaw([]byte(`{"iss":"`+f.srv.cfg.Issuer+`","sub":"`+f.userID+`","aud":"`+f.clientID+`"}`), "JWT")
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"an access token": access, "a grant": grant, "signed userinfo": userinfo} {
		if status, resp := f.exchange(t, raw, nil); status != http.StatusBadRequest || resp["error"] != "invalid_request" {
			t.Errorf("%s answered %d %v", name, status, resp)
		}
	}
}

// A sign-in is read now: an ID token still in date says nothing for somebody who left.
func TestAGrantNeedsTheSignInBehindIt(t *testing.T) {
	f := newIDJAGFixture(t)
	if status, resp := f.exchange(t, f.idToken, nil); status != http.StatusOK {
		t.Fatalf("it answered %d %v", status, resp)
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if status, resp := f.exchange(t, f.idToken, nil); status != http.StatusBadRequest || resp["error"] != "invalid_request" {
		t.Errorf("a deactivated person answered %d %v", status, resp)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET revoked_at = now(), revocation_reason = 'logout' WHERE sid = $1`, f.sid); err != nil {
		t.Fatal(err)
	}
	if status, resp := f.exchange(t, f.idToken, nil); status != http.StatusBadRequest || resp["error"] != "invalid_request" {
		t.Errorf("a signed-out session answered %d %v", status, resp)
	}
}

// §4.3.3: "MUST reject a request without client authentication with invalid_client".
func TestAPublicClientGetsNoGrant(t *testing.T) {
	f := newIDJAGFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.clients SET client_type = 'public' WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if status, resp := f.exchange(t, f.idToken, url.Values{"client_secret": nil}); status != http.StatusUnauthorized ||
		resp["error"] != "invalid_client" {
		t.Errorf("it answered %d %v", status, resp)
	}
}

// §4.3.4.3 tells a server nobody knows from one this client may not reach.
func TestAnotherClientsEntryIsAccessDenied(t *testing.T) {
	f := newIDJAGFixture(t)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.id_jag_audiences SET client_id = $2 WHERE client_id = $1`,
		f.clientID, f.otherClient(t)); err != nil {
		t.Fatal(err)
	}
	if status, resp := f.exchange(t, f.idToken, nil); status != http.StatusBadRequest || resp["error"] != "access_denied" {
		t.Errorf("it answered %d %v", status, resp)
	}
}

func (f *idJAGFixture) otherClient(t *testing.T) string {
	t.Helper()
	id := fmt.Sprintf("idjag-other-%d", time.Now().UnixNano())
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type) VALUES ($1, $2::uuid, 'Other', 'public')`,
		id, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, id) })
	return id
}

// The person's word, and the operator's policy, outrank the operator's entry.
func TestAWithdrawnConsentStopsAGrant(t *testing.T) {
	f := newIDJAGFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.consents (user_id, client_id, scopes, withdrawn_at)
		VALUES ($1::uuid, $2, '{}', now())`, f.userID, f.clientID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.consents WHERE user_id = $1::uuid AND client_id = $2`, f.userID, f.clientID)
	})
	if status, resp := f.exchange(t, f.idToken, nil); status != http.StatusBadRequest || resp["error"] != "access_denied" {
		t.Errorf("it answered %d %v", status, resp)
	}
}

func TestDiscoverySaysWhatIsIssuedAndTaken(t *testing.T) {
	f := newIDJAGFixture(t)
	ctx := context.Background()
	md, err := f.srv.buildDiscovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(md.IdentityChainingRequestedTokenTypesSupported) != 1 || md.IdentityChainingRequestedTokenTypesSupported[0] != oauth.TokenTypeIDJAG {
		t.Errorf("with an entry it says %v", md.IdentityChainingRequestedTokenTypesSupported)
	}
	if len(md.AuthorizationGrantProfilesSupported) != 1 || md.AuthorizationGrantProfilesSupported[0] != oauth.GrantProfileIDJAG {
		t.Errorf("profiles are %v", md.AuthorizationGrantProfilesSupported)
	}
	if err := store.RemoveIDJAGAudience(ctx, f.pool, f.clientID, remoteAS); err != nil {
		t.Fatal(err)
	}
	if issues, err := store.AnyIDJAGAudience(ctx, f.pool, f.srv.instanceID); err != nil {
		t.Fatal(err)
	} else if issues {
		// Another test's entry in the shared instance; nothing can be said of this one.
		t.Skip("another entry exists in this instance")
	}
	md, err = f.srv.buildDiscovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(md.IdentityChainingRequestedTokenTypesSupported) != 0 {
		t.Errorf("with no entry it says %v", md.IdentityChainingRequestedTokenTypesSupported)
	}
}

// And the other end, this server as the Resource Authorization Server.

var idJAGSerial atomic.Int64

// idJAG is a grant from the fixture's trusted issuer, signed by its key.
func (f *assertionFixture) idJAG(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": f.issuer, "sub": "workload-1", "aud": f.srv.cfg.Issuer, "client_id": f.clientID,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "scope": "api.read",
		"jti": fmt.Sprintf("grant-%d-%d", now.UnixNano(), idJAGSerial.Add(1))}
	if edit != nil {
		edit(claims)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.signKey},
		(&jose.SignerOptions{}).WithType("oauth-id-jag+jwt").WithHeader("kid", "sk1"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAGrantBuysAnAccessToken(t *testing.T) {
	f := newAssertionFixture(t)
	status, resp := f.grant(t, f.idJAG(t, nil), nil)
	if status != http.StatusOK {
		t.Fatalf("it answered %d %v", status, resp)
	}
	if resp["refresh_token"] != nil {
		t.Errorf("§4.4.4 says a grant is what is presented again: %v", resp["refresh_token"])
	}
	if resp["scope"] != "api.read" {
		t.Errorf("scope is %v", resp["scope"])
	}
}

func TestWhatAGrantMustSay(t *testing.T) {
	f := newAssertionFixture(t)
	for name, edit := range map[string]func(map[string]any){
		"another client":     func(c map[string]any) { c["client_id"] = "somebody-else" },
		"no client":          func(c map[string]any) { delete(c, "client_id") },
		"two audiences":      func(c map[string]any) { c["aud"] = []string{f.srv.cfg.Issuer, "https://other.example"} },
		"the token endpoint": func(c map[string]any) { c["aud"] = f.srv.cfg.Issuer + oidc.PathToken },
		"another audience":   func(c map[string]any) { c["aud"] = "https://other.example" },
		"a stray resource":   func(c map[string]any) { c["resource"] = "https://not-governed-here.example/" },
		"a key to prove":     func(c map[string]any) { c["cnf"] = map[string]any{"jkt": "abc"} },
	} {
		if status, resp := f.grant(t, f.idJAG(t, edit), nil); status != http.StatusBadRequest || resp["error"] != "invalid_grant" {
			t.Errorf("%s answered %d %v", name, status, resp)
		}
	}
}

// §4.4.1: "The access token MUST be restricted" to what the grant names, and the most it
// buys is what the client is registered for.
func TestAGrantBoundsTheToken(t *testing.T) {
	f := newAssertionFixture(t)
	ctx := context.Background()
	if err := store.SetResourceServer(ctx, f.pool, f.orgID, "https://api.here.example/", "API", nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.resource_servers WHERE org_id = $1::uuid`, f.orgID)
	})
	status, resp := f.grant(t, f.idJAG(t, func(c map[string]any) {
		c["resource"] = "https://api.here.example/"
		c["scope"] = "api.read admin"
	}), nil)
	if status != http.StatusOK {
		t.Fatalf("it answered %d %v", status, resp)
	}
	if resp["scope"] != "api.read" {
		t.Errorf("scope is %v: a grant gives no more than the client's registration", resp["scope"])
	}
	token, _ := resp["access_token"].(string)
	_, claims := decodedGrant(t, token)
	aud, _ := json.Marshal(claims["aud"])
	if !strings.Contains(string(aud), "https://api.here.example/") || strings.Contains(string(aud), f.clientID) {
		t.Errorf("the token's aud is %s", aud)
	}
}

// Without the typ a token is held to RFC 7523 alone, and the header cannot be changed on
// a signed grant, so the only way past these rules is a statement the issuer did not make.
func TestAGrantIsDeclaredByItsType(t *testing.T) {
	if !oauth.IsIDJAG(base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"oauth-id-jag+jwt"}`)) + ".e30.x") {
		t.Error("a grant was not seen")
	}
	if oauth.IsIDJAG(base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`)) + ".e30.x") {
		t.Error("a JWT was taken for a grant")
	}
	if oauth.IsIDJAG("nonsense") {
		t.Error("noise was taken for a grant")
	}
}

// What one end issues is what the other takes, the two run as separate instances of the
// same code with only a JWKS between them.
func TestAGrantTravelsFromOneServerToAnother(t *testing.T) {
	idp := newIDJAGFixture(t)
	rs := newAssertionFixture(t)
	// The Resource Authorization Server trusts the IdP, by its keys, for this person.
	key, err := idp.srv.cfg.Keys.Active("ES256")
	if err != nil {
		t.Fatal(err)
	}
	published := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK()}})
	}))
	t.Cleanup(published.Close)
	ctx := context.Background()
	if _, err := rs.pool.Exec(ctx, `UPDATE core.identity_providers SET issuer = $2, jwks_url = $3 WHERE id = $1::uuid`,
		rs.providerID, idp.srv.cfg.Issuer, published.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.pool.Exec(ctx, `UPDATE core.federated_identities SET subject = $2 WHERE provider_id = $1::uuid`,
		rs.providerID, idp.userID); err != nil {
		t.Fatal(err)
	}
	idp.allow(t, store.IDJAGAudience{Audience: rs.srv.cfg.Issuer, RemoteClientID: rs.clientID, Alg: "ES256", Scopes: []string{"api.read"}})
	status, resp := idp.exchange(t, idp.idToken, url.Values{"audience": {rs.srv.cfg.Issuer}, "scope": {"api.read"}})
	if status != http.StatusOK {
		t.Fatalf("issuing answered %d %v", status, resp)
	}
	grant, _ := resp["access_token"].(string)
	status, resp = rs.grant(t, grant, nil)
	if status != http.StatusOK {
		t.Fatalf("redeeming answered %d %v", status, resp)
	}
	token, _ := resp["access_token"].(string)
	claims, err := tokens.VerifyAccessTokenAny(rs.srv.cfg.Keys, []string{rs.srv.cfg.Issuer}, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != rs.userID || claims.ClientID != rs.clientID || claims.Scope != "api.read" {
		t.Errorf("the token is for %s, client %s, scope %q", claims.Subject, claims.ClientID, claims.Scope)
	}
	// §4.4.4 lets a server take each grant once.
	if status, _ := rs.grant(t, grant, nil); status != http.StatusBadRequest {
		t.Errorf("the second use answered %d", status)
	}
}
