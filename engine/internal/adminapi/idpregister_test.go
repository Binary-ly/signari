package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/store"
)

// fakeIssuer is an OIDC provider's discovery document and keys, served over
// TLS, with the Admin API's provider client pointed at it. lying makes the
// document declare another issuer.
func fakeIssuer(t *testing.T, s *Server, lying *bool) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			issuer := srv.URL
			if *lying {
				issuer = "https://somebody-else.example.test"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer,
				"authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
				"userinfo_endpoint": srv.URL + "/userinfo", "jwks_uri": srv.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey,
				KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	s.providerClient = srv.Client
	return srv
}

// An upstream provider of each sort is registered through the Admin API as
// `signari idp add` and `idp add-issuer` register it (6.07): a generic one
// discovered before anything is stored, its secret sealed, a SAML upstream
// with its certificate, an assertion issuer with its keys read and its
// assertions not yet accepted.
func TestAnIdentityProviderIsRegisteredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	lying := false
	srv := fakeIssuer(t, s, &lying)
	org := newDriftMigrationOrg(t, s, false)
	path := "/admin/organizations/" + org + "/identity-providers"
	slug := func(kind string) string { return kind + "-" + org[:8] }
	post := func(body map[string]any, want int) map[string]any {
		t.Helper()
		rec := call(t, s, http.MethodPost, path, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("registering %v answered %d, want %d: %s", body, rec.Code, want, rec.Body.String())
		}
		return out
	}
	stored := func(slug string) bool {
		t.Helper()
		var n int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM core.identity_providers WHERE slug = $1`, slug).
			Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	// A generic provider, discovered, its secret sealed and opened again by
	// what the sign-in loads.
	oidc := map[string]any{"kind": "oidc", "slug": slug("oidc"), "client_id": "signari", "client_secret": "s3cret",
		"issuer": srv.URL, "trust_email_verification": true}
	if out := post(oidc, http.StatusCreated); out["sign_in_path"] != "/login/with/"+slug("oidc") {
		t.Errorf("the generic provider answered %v", out)
	}
	p, err := store.LoadIdentityProvider(ctx, s.db, s.root, slug("oidc"))
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientSecret != "s3cret" || p.AuthorizeOverride != srv.URL+"/authorize" || p.JWKSOverride != srv.URL+"/jwks" ||
		!p.Policy.TrustsEmailVerification || !p.Policy.AllowSignup {
		t.Errorf("the sign-in loads authorize %q, jwks %q, trusts %v, signup %v, secret opened %v", p.AuthorizeOverride,
			p.JWKSOverride, p.Policy.TrustsEmailVerification, p.Policy.AllowSignup, p.ClientSecret == "s3cret")
	}
	var sealed []byte
	if err := s.db.QueryRow(ctx, `SELECT client_secret FROM core.identity_providers WHERE slug = $1`,
		slug("oidc")).Scan(&sealed); err != nil || len(sealed) == 0 || string(sealed) == "s3cret" {
		t.Errorf("the client secret is stored as %q (%v)", sealed, err)
	}
	if out := post(oidc, http.StatusConflict); out["error"] != "already_exists" {
		t.Errorf("a taken slug answered %v", out)
	}
	// A document declaring another issuer is somebody else's, and nothing is
	// stored for it.
	lying = true
	post(map[string]any{"kind": "oidc", "slug": slug("liar"), "client_id": "signari", "issuer": srv.URL},
		http.StatusBadRequest)
	lying = false
	if stored(slug("liar")) {
		t.Error("a provider whose discovery declared another issuer was stored")
	}

	// An assertion issuer: its keys read, assertions off until allowed.
	issuer := map[string]any{"kind": "assertion", "slug": slug("ci"), "issuer": "https://ci.example.test",
		"jwks_url": srv.URL + "/jwks"}
	if out := post(issuer, http.StatusCreated); out["keys"] != float64(1) || out["allow_assertions"] != false {
		t.Errorf("the assertion issuer answered %v", out)
	}
	var assertions, signup bool
	if err := s.db.QueryRow(ctx, `SELECT allow_jwt_bearer, allow_signup FROM core.identity_providers WHERE slug = $1`,
		slug("ci")).Scan(&assertions, &signup); err != nil || assertions || signup {
		t.Errorf("the issuer reads assertions %v, signup %v (%v)", assertions, signup, err)
	}

	// A SAML upstream, believed about addresses unless told otherwise.
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	saml := map[string]any{"kind": "saml", "slug": slug("saml"), "entity_id": "https://idp.example.test/" + org,
		"sso_url": "https://idp.example.test/sso", "certificate": cert}
	if out := post(saml, http.StatusCreated); out["metadata_path"] != "/saml/source/"+slug("saml")+"/metadata" {
		t.Errorf("the SAML upstream answered %v", out)
	}
	var entity, format string
	var trusts bool
	if err := s.db.QueryRow(ctx, `SELECT x.entity_id, x.name_id_format, p.trust_email_verification
		FROM core.saml_sources x JOIN core.identity_providers p ON p.id = x.provider_id WHERE p.slug = $1`,
		slug("saml")).Scan(&entity, &format, &trusts); err != nil || format != "persistent" || !trusts {
		t.Errorf("the SAML upstream reads %q %q trusts %v (%v)", entity, format, trusts, err)
	}

	for name, body := range map[string]map[string]any{
		"a slug that is not a URL segment": {"kind": "github", "slug": "Not A Slug", "client_id": "x"},
		"an unknown kind":                  {"kind": "myspace", "slug": slug("x1"), "client_id": "x"},
		"a provider with no client":        {"kind": "github", "slug": slug("x2")},
		"belief in a named provider":       {"kind": "google", "slug": slug("x3"), "client_id": "x", "trust_email_verification": true},
		"an issuer that signs people in":   {"kind": "assertion", "slug": slug("x4"), "issuer": "https://i.example.test", "jwks_url": srv.URL + "/jwks", "allow_signup": true},
		"a transient NameID":               {"kind": "saml", "slug": slug("x5"), "entity_id": "e", "sso_url": "https://i.example.test", "certificate": cert, "name_id_format": "transient"},
		"a plaintext SSO URL":              {"kind": "saml", "slug": slug("x6"), "entity_id": "e", "sso_url": "http://idp.example.test/sso", "certificate": cert},
		"a certificate that is not one":    {"kind": "saml", "slug": slug("x7"), "entity_id": "e", "sso_url": "https://i.example.test", "certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
		"a clock tolerance past 300":       {"kind": "saml", "slug": slug("x8"), "entity_id": "e", "sso_url": "https://i.example.test", "certificate": cert, "skew_seconds": 301},
	} {
		if out := post(body, http.StatusBadRequest); out["error"] != "invalid_identity_provider" {
			t.Errorf("%s answered %v", name, out)
		}
	}
	for _, x := range []string{"x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"} {
		if stored(slug(x)) {
			t.Errorf("the refused %s was stored", x)
		}
	}
}
