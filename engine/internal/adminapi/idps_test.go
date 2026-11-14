package adminapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/store"
)

// newDriftIdP is an organisation of the test's own with a sign-in provider of
// that kind and a declared attribute named department, and the provider's
// path. A slug is unique across the deployment, so it carries the
// organisation's id.
func newDriftIdP(t *testing.T, s *Server, kind string) (org, slug, path string) {
	t.Helper()
	ctx := context.Background()
	org = newDriftMigrationOrg(t, s, false)
	slug = "drift-" + org[:8]
	if _, err := s.db.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id, scopes)
		VALUES ($1::uuid, $2, 'Drift', $3, 'drift-client', '{openid}')`, org, slug, kind); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO core.user_attribute_schema (org_id, name) VALUES ($1::uuid, 'department')`,
		org); err != nil {
		t.Fatal(err)
	}
	return org, slug, "/admin/organizations/" + org + "/identity-providers/" + slug
}

// newDriftVPVerifier is an organisation of the test's own with a wallet sign-in, and
// its path. redirect_uri, so it needs no key.
func newDriftVPVerifier(t *testing.T, s *Server) (org, slug, path string) {
	t.Helper()
	org = newDriftMigrationOrg(t, s, false)
	slug = "drift-vp-" + org[:8]
	// Validated first, as AddIdentityProvider expects: Validate is what fills the
	// defaults the columns' checks hold it to.
	spec := store.IdentityProviderSpec{Slug: slug, Name: slug, Kind: "oid4vp", VP: &store.VPSpec{
		Prefix: "redirect_uri", VCTValues: []string{"urn:example:pid:1"}, SubjectClaim: `["sub"]`}}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIdentityProvider(context.Background(), s.db, nil, org, spec); err != nil {
		t.Fatal(err)
	}
	return org, slug, "/admin/organizations/" + org + "/identity-providers/" + slug
}

// issuerJWKS is a JWK Set of one fresh public signing key, or with private the key
// itself, which may not be believed.
func issuerJWKS(t *testing.T, private bool) json.RawMessage {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: k.Public(), KeyID: "pid-1", Use: "sig"}
	if private {
		jwk.Key = k
	}
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testCertificates is a CA's certificate and one it issued, each PEM.
func testCertificates(t *testing.T) (root, leaf string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PID Root"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := x509.ParseCertificate(caDER)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "PID Issuer"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}, parent, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
}

// A wallet sign-in is made and told whom to believe through the Admin API, as `idp
// add -kind oid4vp` and `idp vp-issuer` do (12.12).
func TestAWalletSignInIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	org := newDriftMigrationOrg(t, s, false)
	base := "/admin/organizations/" + org + "/identity-providers"
	slug := "vp-" + org[:8]

	rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"kind": "oid4vp", "slug": slug,
		"client_id_prefix": "redirect_uri", "vct_values": []string{"urn:example:pid:1"}, "subject_claim": "sub",
		"email_claim": "email"})
	var made map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if rec.Code != http.StatusCreated || made["sign_in_path"] != "/oid4vp/"+slug+"/start" ||
		made["response_path"] != "/oid4vp/"+slug+"/response" {
		t.Fatalf("made: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"kind": "oid4vp", "slug": slug + "-x",
		"client_id_prefix": "x509_san_dns", "vct_values": []string{"urn:example:pid:1"}, "subject_claim": "sub"}); rec.Code != http.StatusBadRequest {
		t.Errorf("x509_san_dns with no key answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodPost, base, testToken, map[string]any{"kind": "google", "slug": slug + "-g",
		"client_id": "c", "client_secret": "s", "vct_values": []string{"urn:example:pid:1"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a wallet's fields on a google provider answered %d", rec.Code)
	}

	issuers := base + "/" + slug + "/vp-issuers"
	if rec := call(t, s, http.MethodPut, issuers, testToken, map[string]any{"issuer": "https://pid.example",
		"jwks": issuerJWKS(t, false)}); rec.Code != http.StatusOK {
		t.Fatalf("believing an issuer: %d %s", rec.Code, rec.Body)
	}
	v, err := store.LoadVPVerifier(context.Background(), s.db, nil, slug)
	if err != nil || v.Issuers["https://pid.example"] == nil || v.Email == nil {
		t.Fatalf("loaded %+v %v", v, err)
	}
	for name, body := range map[string]map[string]any{
		"a private key":      {"issuer": "https://pid.example", "jwks": issuerJWKS(t, true)},
		"an issuer with a |": {"issuer": "https://pid.example|x", "jwks": issuerJWKS(t, false)},
	} {
		if rec := call(t, s, http.MethodPut, issuers, testToken, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d", name, rec.Code)
		}
	}
	if rec := call(t, s, http.MethodPut, base+"/nobody/vp-issuers", testToken, map[string]any{
		"issuer": "https://pid.example", "jwks": issuerJWKS(t, false)}); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown slug answered %d", rec.Code)
	}

	// The same issuer moved to the keys its metadata publishes: the held keys go,
	// and a second issuer believed that way sits beside it.
	for _, iss := range []string{"https://pid.example", "https://other.example/tenant/7"} {
		if rec := call(t, s, http.MethodPut, issuers, testToken, map[string]any{"issuer": iss,
			"keys_from": "metadata"}); rec.Code != http.StatusOK {
			t.Fatalf("believing %s by its metadata: %d %s", iss, rec.Code, rec.Body)
		}
	}
	v, err = store.LoadVPVerifier(context.Background(), s.db, nil, slug)
	if err != nil || v.Issuers["https://pid.example"] != nil || !v.IssuersFromMetadata["https://pid.example"] ||
		!v.IssuersFromMetadata["https://other.example/tenant/7"] {
		t.Fatalf("after keys_from metadata: pinned %v, from metadata %v, %v", v.Issuers, v.IssuersFromMetadata, err)
	}
	for name, body := range map[string]map[string]any{
		"keys and metadata both":     {"issuer": "https://pid.example", "keys_from": "metadata", "jwks": issuerJWKS(t, false)},
		"an issuer with no metadata": {"issuer": "urn:example:pid", "keys_from": "metadata"},
		"a plain http issuer":        {"issuer": "http://pid.example", "keys_from": "metadata"},
		"an unknown keys_from":       {"issuer": "https://pid.example", "keys_from": "sideways"},
	} {
		if rec := call(t, s, http.MethodPut, issuers, testToken, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d %s", name, rec.Code, rec.Body)
		}
	}

	// Moved to the certificate chain its credentials carry, with the roots it leads to:
	// held as the certificates alone, and nothing else held for it.
	root, leaf := testCertificates(t)
	if rec := call(t, s, http.MethodPut, issuers, testToken, map[string]any{"issuer": "https://pid.example",
		"keys_from": "x5c", "roots": "a comment the file had\n" + root}); rec.Code != http.StatusOK {
		t.Fatalf("believing an issuer by its certificate: %d %s", rec.Code, rec.Body)
	}
	v, err = store.LoadVPVerifier(context.Background(), s.db, nil, slug)
	if err != nil || v.IssuerRoots["https://pid.example"] == nil || v.Issuers["https://pid.example"] != nil ||
		v.IssuersFromMetadata["https://pid.example"] {
		t.Fatalf("after keys_from x5c: %+v %v", v, err)
	}
	var held string
	if err := s.db.QueryRow(context.Background(), `SELECT roots FROM core.vp_trusted_issuers t
		JOIN core.identity_providers p ON p.id = t.provider_id WHERE p.slug = $1 AND t.issuer = $2`,
		slug, "https://pid.example").Scan(&held); err != nil || held != root {
		t.Errorf("held %q, %v", held, err)
	}
	for name, body := range map[string]map[string]any{
		"x5c with keys":                          {"issuer": "https://pid.example", "keys_from": "x5c", "roots": root, "jwks": issuerJWKS(t, false)},
		"x5c with no roots":                      {"issuer": "https://pid.example", "keys_from": "x5c"},
		"a leaf as a root":                       {"issuer": "https://pid.example", "keys_from": "x5c", "roots": leaf},
		"roots on pinned keys":                   {"issuer": "https://pid.example", "jwks": issuerJWKS(t, false), "roots": root},
		"roots on metadata":                      {"issuer": "https://pid.example", "keys_from": "metadata", "roots": root},
		"an issuer that no certificate can name": {"issuer": "pid-issuer", "keys_from": "x5c", "roots": root},
	} {
		if rec := call(t, s, http.MethodPut, issuers, testToken, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d %s", name, rec.Code, rec.Body)
		}
	}
	// And back to pinned keys, which a held issuer keeps.
	if rec := call(t, s, http.MethodPut, issuers, testToken, map[string]any{"issuer": "https://pid.example",
		"jwks": issuerJWKS(t, false)}); rec.Code != http.StatusOK {
		t.Fatalf("pinning again: %d %s", rec.Code, rec.Body)
	}
	if v, err = store.LoadVPVerifier(context.Background(), s.db, nil, slug); err != nil ||
		v.Issuers["https://pid.example"] == nil || v.IssuersFromMetadata["https://pid.example"] ||
		v.IssuerRoots["https://pid.example"] != nil {
		t.Fatalf("after pinning again: pinned %v, from metadata %v, roots %v, %v", v.Issuers, v.IssuersFromMetadata,
			v.IssuerRoots, err)
	}
	if rec := call(t, s, http.MethodDelete, issuers+"?issuer=https://pid.example", testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("no longer believing: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, http.MethodDelete, issuers+"?issuer=https://pid.example", testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("forgetting it twice answered %d", rec.Code)
	}
}

// An upstream provider is taken out of service, allowed its assertions,
// trusted for multi-factor and given an attribute mapping through the Admin
// API as `signari idp` does it (6.07).
func TestAnIdentityProviderIsConfiguredThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, slug, path := newDriftIdP(t, s, "oidc")
	errorOf := func(method, p string, body any, want int) string {
		t.Helper()
		rec := call(t, s, method, p, testToken, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != want {
			t.Errorf("%s %s %v answered %d, want %d: %s", method, p, body, rec.Code, want, rec.Body.String())
		}
		e, _ := out["error"].(string)
		return e
	}
	read := func() (enabled, assertions, trusts, requires bool, amr []string) {
		t.Helper()
		if err := s.db.QueryRow(ctx, `SELECT enabled, allow_jwt_bearer, trust_email_verification, require_verified_email,
			mfa_amr FROM core.identity_providers WHERE slug = $1`, slug).Scan(&enabled, &assertions, &trusts, &requires,
			&amr); err != nil {
			t.Fatal(err)
		}
		return
	}
	if rec := call(t, s, http.MethodPatch, path, testToken, map[string]any{"enabled": false, "allow_assertions": true,
		"trust_email_verification": true, "require_verified_email": false,
		"mfa_amr": []string{"mfa", " otp "}}); rec.Code != http.StatusOK {
		t.Fatalf("changing the provider: %d %s", rec.Code, rec.Body.String())
	}
	if enabled, assertions, trusts, requires, amr := read(); enabled || !assertions || !trusts || requires ||
		strings.Join(amr, ",") != "mfa,otp" {
		t.Errorf("the provider reads enabled %v, assertions %v, trusts %v, requires %v, amr %v",
			enabled, assertions, trusts, requires, amr)
	}
	// One change keeps the others.
	if rec := call(t, s, http.MethodPatch, path, testToken, map[string]any{"enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enabling: %d", rec.Code)
	}
	if enabled, assertions, trusts, requires, amr := read(); !enabled || !assertions || !trusts || requires ||
		len(amr) != 2 {
		t.Errorf("enabling alone left assertions %v, trusts %v, requires %v, amr %v", assertions, trusts, requires, amr)
	}
	if e := errorOf(http.MethodPatch, path, map[string]any{}, http.StatusBadRequest); e != "nothing_to_change" {
		t.Errorf("an empty change answered %q", e)
	}
	// Keeping a provider's tokens is a change on its own, as `idp store-tokens` makes it:
	// it was read as nothing to change, so it could only be made beside another.
	for _, keep := range []bool{false, true} {
		if rec := call(t, s, http.MethodPatch, path, testToken, map[string]any{"store_tokens": keep}); rec.Code != http.StatusOK {
			t.Fatalf("store_tokens %v alone answered %d %s", keep, rec.Code, rec.Body)
		}
		var kept bool
		if err := s.db.QueryRow(ctx, `SELECT store_tokens FROM core.identity_providers WHERE slug = $1`,
			slug).Scan(&kept); err != nil || kept != keep {
			t.Errorf("after store_tokens %v alone the provider keeps %v, %v", keep, kept, err)
		}
	}
	if e := errorOf(http.MethodPatch, "/admin/organizations/"+org+"/identity-providers/elsewhere",
		map[string]any{"enabled": false}, http.StatusNotFound); e != "provider_not_found" {
		t.Errorf("an unknown provider answered %q", e)
	}
	// Another organisation's provider is not this one's.
	_, theirs, _ := newDriftIdP(t, s, "google")
	if e := errorOf(http.MethodPatch, "/admin/organizations/"+org+"/identity-providers/"+theirs,
		map[string]any{"enabled": false}, http.StatusNotFound); e != "provider_not_found" {
		t.Errorf("another organisation's provider answered %q", e)
	}

	maps := path + "/attribute-map"
	if e := errorOf(http.MethodPut, maps, map[string]any{"claim": "dept", "attribute": "cost_centre"},
		http.StatusBadRequest); e != "invalid_identity_provider" {
		t.Errorf("an undeclared attribute answered %q", e)
	}
	if rec := call(t, s, http.MethodPut, maps, testToken, map[string]any{"claim": "dept", "attribute": "department",
		"overwrite": true}); rec.Code != http.StatusOK {
		t.Fatalf("mapping: %d %s", rec.Code, rec.Body.String())
	}
	list := call(t, s, http.MethodGet, "/admin/organizations/"+org+"/identity-providers", testToken, nil)
	if !strings.Contains(list.Body.String(), `"attribute":"department","claim":"dept","max_length":256,"overwrite":true`) {
		t.Errorf("the providers read %s", list.Body.String())
	}
	unmap := maps + "?claim=dept&attribute=department"
	if rec := call(t, s, http.MethodDelete, unmap, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("unmapping: %d %s", rec.Code, rec.Body.String())
	}
	if e := errorOf(http.MethodDelete, unmap, nil, http.StatusNotFound); e != "mapping_not_found" {
		t.Errorf("unmapping it again answered %q", e)
	}

	// A provider that sends no ID token has nothing to read amr from, and a
	// named provider's belief in email_verified is its preset's: either set
	// here would be read by nothing.
	ghOrg, ghSlug, gh := newDriftIdP(t, s, "github")
	if e := errorOf(http.MethodPatch, gh, map[string]any{"mfa_amr": []string{"mfa"}},
		http.StatusBadRequest); e != "invalid_identity_provider" {
		t.Errorf("multi-factor values on a GitHub provider answered %q", e)
	}
	if e := errorOf(http.MethodPatch, gh, map[string]any{"trust_email_verification": true},
		http.StatusBadRequest); e != "invalid_identity_provider" {
		t.Errorf("belief in a GitHub provider's email_verified answered %q", e)
	}
	if err := store.ChangeIdentityProvider(ctx, s.db, ghOrg, ghSlug,
		store.IdentityProviderChange{RequireVerifiedEmail: new(bool)}); err != nil {
		t.Errorf("a GitHub provider's sign-ups: %v", err)
	}
}

// A token narrowed to some applications cannot change how the whole
// organisation signs in through a provider.
func TestANarrowedTokenCannotChangeAnIdentityProvider(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, slug, path := newDriftIdP(t, s, "oidc")
	client := clientIn(t, s, org)
	narrowed, _, err := NewToken(ctx, s.db, "idp-narrowed-"+client, org,
		[]string{ScopeOrganizationsWrite}, nil, []string{client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.admin_tokens WHERE token_hash = $1`, sha256Of(narrowed))
	})
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPatch, path, map[string]any{"trust_email_verification": true}},
		{http.MethodPost, "/admin/organizations/" + org + "/identity-providers",
			map[string]any{"kind": "github", "slug": "narrowed-" + org[:8], "client_id": "x"}},
		{http.MethodPut, path + "/attribute-map", map[string]any{"claim": "dept", "attribute": "department"}},
	} {
		rec := call(t, s, c.method, c.path, narrowed, c.body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "outside_token_objects") {
			t.Errorf("a narrowed token's %s %s answered %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	var trusts bool
	if err := s.db.QueryRow(ctx, `SELECT trust_email_verification FROM core.identity_providers WHERE slug = $1`,
		slug).Scan(&trusts); err != nil || trusts {
		t.Errorf("after the refusal the provider trusts %v (%v)", trusts, err)
	}
}
