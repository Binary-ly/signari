package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
)

// RFC 7523 §2.1, end to end and adversarially.
//
// The grant turns "holds a JWT from a trusted issuer" into "acts as a local
// user", with no browser and no human. Nearly every test here is a refusal,
// because the happy path is one shape and the ways this goes wrong are many --
// and three of them shipped as CVEs in the most deployed competitor during 2026.

const jwtBearerIssuer = "https://platform.test"

type assertionFixture struct {
	srv        *Server
	pool       *pgxpool.Pool
	orgID      string
	userID     string
	providerID string
	clientID   string
	secret     string
	signKey    *rsa.PrivateKey
	jwksServer *httptest.Server
	issuer     string
}

func newAssertionFixture(t *testing.T) *assertionFixture {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	f := &assertionFixture{pool: pool, issuer: jwtBearerIssuer}

	// The trusted issuer's key, published by a JWKS server this test controls.
	f.signKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: f.signKey.Public(), KeyID: "sk1", Algorithm: "RS256", Use: "sig",
	}}}
	f.jwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(f.jwksServer.Close)

	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	ourKeys, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	f.srv, err = New(oidc.Config{
		Issuer: "https://jb-test.example", Keys: ourKeys, AllowInsecureIssuer: true,
	}, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://jb-' || gen_random_uuid() || '.test', 'T') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'j' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle)
		SELECT id, 'j'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')
		FROM o RETURNING org_id::text, id::text`).Scan(&f.orgID, &f.userID); err != nil {
		t.Fatalf("fixture user: %v", err)
	}

	// The trusted provider, opted in to this grant.
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers
			(org_id, slug, display_name, kind, client_id, issuer, jwks_url,
			 enabled, allow_jwt_bearer)
		VALUES ($1::uuid, 'p'||substr(gen_random_uuid()::text,1,8), 'Platform', 'oidc',
		        'unused', $2, $3, true, true)
		RETURNING id::text`, f.orgID, f.issuer, f.jwksServer.URL).Scan(&f.providerID); err != nil {
		t.Fatalf("fixture provider: %v", err)
	}
	// And the link that makes the assertion's subject mean somebody here.
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'workload-1')`,
		f.providerID, f.userID, f.orgID); err != nil {
		t.Fatalf("fixture link: %v", err)
	}

	suffix := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	f.clientID = "jb-" + suffix
	f.secret = "s-" + f.clientID + "-" + strings.Repeat("x", 24)
	hash, ok := clients.HashSecret(f.secret)
	if !ok {
		t.Fatal("hashing the fixture secret")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2::uuid,'T','confidential',$3,
		        ARRAY['authorization_code','urn:ietf:params:oauth:grant-type:jwt-bearer'],
		        ARRAY['api.read','api.write'], false)`,
		f.clientID, f.orgID, hash); err != nil {
		t.Fatalf("fixture client: %v", err)
	}

	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, f.clientID)
		_, _ = pool.Exec(c, `DELETE FROM core.jwt_bearer_replay WHERE provider_id = $1::uuid`, f.providerID)
	})
	return f
}

// assert builds and signs an assertion, applying any overrides.
func (f *assertionFixture) assert(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": f.issuer,
		"sub": "workload-1",
		"aud": "https://jb-test.example",
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "j-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", ""),
	}
	if edit != nil {
		edit(claims)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.signKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "sk1"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// grant posts the assertion to the token endpoint.
func (f *assertionFixture) grant(t *testing.T, assertion string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", oauth.GrantTypeJWTBearer)
	form.Set("assertion", assertion)
	form.Set("client_id", f.clientID)
	form.Set("client_secret", f.secret)
	for k, v := range extra {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.handleToken(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestAValidAssertionMintsATokenForTheLinkedUser(t *testing.T) {
	f := newAssertionFixture(t)
	code, body := f.grant(t, f.assert(t, nil), nil)
	if code != http.StatusOK {
		t.Fatalf("a valid assertion was refused: %d %v", code, body)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("no access token in the response")
	}
	// The token must name the LOCAL user, not the assertion's subject.
	claims, err := tokenClaimsOf(at)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != f.userID {
		t.Errorf("token sub = %v, want the linked local user %s", claims["sub"], f.userID)
	}
	// And no refresh token: that would outlive the assertion.
	if _, ok := body["refresh_token"]; ok {
		t.Error("a refresh token was issued, which outlives the assertion it came from")
	}
}

// a published advisory. Disabling a provider is how an administrator revokes trust. If
// the grant does not honour it, decommissioning does nothing.
func TestADisabledProviderCannotMintTokens(t *testing.T) {
	f := newAssertionFixture(t)
	// Prove it works first, or this test passes for the wrong reason.
	if code, _ := f.grant(t, f.assert(t, nil), nil); code != http.StatusOK {
		t.Fatalf("the fixture does not work before disabling: %d", code)
	}
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.identity_providers SET enabled = false WHERE id = $1::uuid`, f.providerID); err != nil {
		t.Fatal(err)
	}
	code, body := f.grant(t, f.assert(t, nil), nil)
	if code == http.StatusOK {
		t.Fatal("a DISABLED provider still minted a token; disabling it revoked nothing")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

// The opt-in itself. A provider registered for interactive sign-in must not gain
// non-interactive token minting for free.
func TestAProviderNotOptedInCannotMintTokens(t *testing.T) {
	f := newAssertionFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.identity_providers SET allow_jwt_bearer = false WHERE id = $1::uuid`,
		f.providerID); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.grant(t, f.assert(t, nil), nil); code == http.StatusOK {
		t.Fatal("a provider that was never opted in to this grant minted a token")
	}
}

// a published advisory. Deactivating a user must mean it here too.
func TestADeactivatedUserCannotBeImpersonated(t *testing.T) {
	f := newAssertionFixture(t)
	if code, _ := f.grant(t, f.assert(t, nil), nil); code != http.StatusOK {
		t.Fatalf("the fixture does not work before deactivating: %d", code)
	}
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.grant(t, f.assert(t, nil), nil); code == http.StatusOK {
		t.Fatal("an assertion minted a token for a DEACTIVATED user")
	}
}

// RFC 7523 §3.1: an assertion addressed to somebody else must not work here.
func TestAnAssertionForAnotherAudienceIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	a := f.assert(t, func(c map[string]any) { c["aud"] = "https://someone-else.example" })
	if code, _ := f.grant(t, a, nil); code == http.StatusOK {
		t.Fatal("an assertion issued for a different relying party was accepted")
	}
}

// A subject nobody linked is not an account here.
func TestAnUnlinkedSubjectIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	a := f.assert(t, func(c map[string]any) { c["sub"] = "workload-unknown" })
	if code, _ := f.grant(t, a, nil); code == http.StatusOK {
		t.Fatal("an assertion for an unlinked subject minted a token")
	}
}

// Replay. Above what RFC 7523 requires, and the reason is that an assertion is
// otherwise a password for the length of its exp.
func TestTheSameAssertionCannotBeUsedTwice(t *testing.T) {
	f := newAssertionFixture(t)
	a := f.assert(t, nil)
	if code, body := f.grant(t, a, nil); code != http.StatusOK {
		t.Fatalf("first use was refused: %d %v", code, body)
	}
	code, body := f.grant(t, a, nil)
	if code == http.StatusOK {
		t.Fatal("the same assertion was accepted twice")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

// An expired assertion is refused even though everything else about it is right.
func TestAnExpiredAssertionIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	a := f.assert(t, func(c map[string]any) {
		c["exp"] = time.Now().Add(-10 * time.Minute).Unix()
		c["iat"] = time.Now().Add(-20 * time.Minute).Unix()
	})
	if code, _ := f.grant(t, a, nil); code == http.StatusOK {
		t.Fatal("an expired assertion minted a token")
	}
}

// openid is refused with a reason rather than silently dropped, because we did
// not perform this authentication and cannot honestly describe it.
func TestOpenIDIsRefusedWithAReason(t *testing.T) {
	f := newAssertionFixture(t)
	_, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET scopes = ARRAY['openid','api.read'] WHERE client_id = $1`, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	code, body := f.grant(t, f.assert(t, nil), url.Values{"scope": {"openid"}})
	if code == http.StatusOK {
		t.Fatal("the jwt-bearer grant issued an openid token")
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error = %v, want invalid_scope", body["error"])
	}
}

// A client that was never registered for this grant cannot use it, even with a
// perfectly good assertion.
func TestAClientNotRegisteredForTheGrantIsRefused(t *testing.T) {
	f := newAssertionFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET grant_types = ARRAY['authorization_code'] WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	code, body := f.grant(t, f.assert(t, nil), nil)
	if code == http.StatusOK {
		t.Fatal("a client not registered for jwt-bearer used it")
	}
	if body["error"] != "unauthorized_client" {
		t.Errorf("error = %v, want unauthorized_client", body["error"])
	}
}

// tokenClaimsOf decodes an access token's payload WITHOUT verifying it.
//
// Acceptable only because this is a test reading a token this same process just
// minted and signed. Nothing here is deciding anything on the strength of it.
func tokenClaimsOf(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errNotAJWT
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

var errNotAJWT = errors.New("not a three-part JWT")
