package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// testCertificate is a SAML upstream's signing certificate, valid for a day.
func testCertificate(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "upstream"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "upstream"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Upstream identity providers in a configuration file (6.19), each kind: made
// as `signari idp add` makes them, a generic provider's endpoints as written,
// the client secret named by reference and followed, a client id changed only
// with the secret for it, the slug refused when another organisation has it,
// and a pruned provider switched off with its links kept.
func TestIdentityProvidersAreDeclaredWithTheirSecretsByReference(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, root := freshOrg(t, ctx, tx), testRoot(t)
	n := time.Now().UnixNano()
	env := map[string]string{"GH_SECRET": "gh-first", "OIDC_SECRET": "oidc-first"}
	plan := func(org, raw string, prune bool) (*File, *Plan, error) {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.ResolveSecrets(func(r SecretRef) (string, error) {
			if v, ok := env[r.Env]; ok {
				return v, nil
			}
			return "", fmt.Errorf("%s is not set", r.Env)
		}); err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlanWith(ctx, tx, org, f, prune, Options{Root: root})
		return f, p, err
	}
	apply := func(org, raw string, prune bool) *Plan {
		t.Helper()
		f, p, err := plan(org, raw, prune)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cert := strings.ReplaceAll(strings.TrimSpace(testCertificate(t)), "\n", "\n        ")
	file := fmt.Sprintf(`attributes: [{name: team}]
identity_providers:
  - slug: gh-%[1]d
    kind: github
    client_id: gh-client
    client_secret: {env: GH_SECRET}
    require_verified_email: false
    attribute_map: [{claim: company, attribute: team}]
  - slug: corp-%[1]d
    kind: oidc
    client_id: corp-client
    client_secret: {env: OIDC_SECRET}
    issuer: https://login.corp.example.test
    authorize_url: https://login.corp.example.test/authorize
    token_url: https://login.corp.example.test/token
    jwks_url: https://login.corp.example.test/jwks
    mfa_amr: [mfa]
  - slug: adfs-%[1]d
    kind: saml
    saml:
      entity_id: https://adfs.example.test/adfs/services/trust
      sso_url: %[2]s
      certificate: |
        %[3]s
  - slug: ci-%[1]d
    kind: assertion
    issuer: https://ci.example.test
    jwks_url: https://ci.example.test/jwks
    allow_assertions: true
`, n, "%s", cert)
	at := func(sso string) string { return fmt.Sprintf(file, sso) }
	const sso = "https://adfs.example.test/adfs/ls"

	p := apply(org, at(sso), false)
	if !strings.Contains(p.String(), "client secret from $GH_SECRET") || strings.Count(p.String(), "+ identity_provider") != 4 {
		t.Errorf("the creates were planned as\n%s", p)
	}
	rows, err := store.IdentityProviders(ctx, tx, org)
	if err != nil || len(rows) != 4 {
		t.Fatalf("the providers are %+v (%v)", rows, err)
	}
	byKind := keyBy(rows, func(r store.IdentityProviderRow) string { return r.Kind })
	if gh := byKind["github"]; gh.RequireVerifiedEmail || len(gh.AttributeMap) != 1 || !gh.AllowSignup {
		t.Errorf("the GitHub provider is %+v", gh)
	}
	if saml := byKind["saml"]; !saml.TrustEmailVerification {
		t.Error("a SAML upstream was made without believing its addresses, as `idp add` would")
	}
	if ci := byKind["assertion"]; !ci.AllowAssertions || ci.AllowSignup {
		t.Errorf("the assertion issuer is %+v", ci)
	}
	if secret, _ := store.IdentityProviderSecret(ctx, tx, root, org, fmt.Sprintf("gh-%d", n)); secret != "gh-first" {
		t.Errorf("the GitHub provider holds %q", secret)
	}
	if _, p, _ := plan(org, at(sso), false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}

	env["GH_SECRET"] = "gh-rotated"
	if p := apply(org, at(sso), false); !strings.Contains(p.String(), "client_secret") {
		t.Errorf("a rotated secret was planned as\n%s", p)
	}
	if p := apply(org, at("https://adfs.example.test/adfs/ls2"), false); !strings.Contains(p.String(), "saml") {
		t.Errorf("a moved SAML endpoint was planned as\n%s", p)
	}

	// A new client id without the secret for it would send the old secret to
	// whoever the new client is.
	bare := strings.Replace(at(sso), "client_id: corp-client\n    client_secret: {env: OIDC_SECRET}",
		"client_id: another-client", 1)
	if _, _, err := plan(org, bare, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "issued with") {
		t.Errorf("a new client id without its secret answered %v", err)
	}
	id := "another-client"
	if err := store.UpdateIdentityProvider(ctx, tx, root, org, fmt.Sprintf("corp-%d", n),
		store.IdentityProviderUpdate{ClientID: &id}); !errors.Is(err, store.ErrIdPSecretForAnotherClient) {
		t.Errorf("the writer changed the client id without its secret: %v", err)
	}

	exported, err := Export(ctx, tx, org)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "gh-rotated") || strings.Contains(string(out), "client_secret") ||
		!strings.Contains(string(out), "token_url: https://login.corp.example.test/token") {
		t.Errorf("the export reads\n%s", out)
	}
	other := freshOrg(t, ctx, tx)
	body := strings.TrimPrefix(string(out), "version: 1\n")
	if _, _, err := plan(other, body, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "/login/with/") {
		t.Errorf("another organisation's slugs answered %v", err)
	}
	moved := strings.ReplaceAll(body, fmt.Sprintf("-%d", n), fmt.Sprintf("-%d-copy", n))
	apply(other, moved, false)
	if _, p, _ := plan(other, moved, false); !p.Empty() {
		t.Errorf("the export applied elsewhere plans\n%s", p)
	}

	if p := apply(org, "attributes: [{name: team}]\n", true); strings.Count(p.String(), keptProvider) != 4 ||
		p.Destructive() != nil {
		t.Errorf("the pruned plan reads\n%s", p)
	}
	rows, _ = store.IdentityProviders(ctx, tx, org)
	for _, r := range rows {
		if r.Enabled {
			t.Errorf("pruned, %s is still enabled", r.Slug)
		}
	}
	if _, p, _ := plan(org, "attributes: [{name: team}]\n", true); !p.Empty() {
		t.Errorf("pruned again it plans\n%s", p)
	}
}

// What a file may not say about a provider, refused before anything is read.
func TestAProviderTheFileCannotDescribeIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"OIDC with no token endpoint": "identity_providers: [{slug: a, kind: oidc, client_id: c, issuer: 'https://i.test', " +
			"authorize_url: 'https://i.test/a', jwks_url: 'https://i.test/k'}]",
		"SAML with nothing":               "identity_providers: [{slug: a, kind: saml}]",
		"GitHub's amr":                    "identity_providers: [{slug: a, kind: github, client_id: c, mfa_amr: [mfa]}]",
		"belief in Google's verified":     "identity_providers: [{slug: a, kind: google, client_id: c, trust_email_verification: true}]",
		"an assertion issuer's secret":    "identity_providers: [{slug: a, kind: assertion, issuer: 'https://i.test', jwks_url: 'https://i.test/k', client_secret: {env: S}}]",
		"Google's endpoints rewritten":    "identity_providers: [{slug: a, kind: google, client_id: c, token_url: 'https://evil.test/token'}]",
		"a kind nobody has":               "identity_providers: [{slug: a, kind: myspace, client_id: c}]",
		"a mapping twice":                 "identity_providers: [{slug: a, kind: github, client_id: c, attribute_map: [{claim: x, attribute: y}, {claim: x, attribute: y}]}]",
		"the engine's own setting":        "identity_providers: [{slug: a, kind: github, client_id: c, client_secret: {env: SIGNARI_ROOT_KEY_FILE}}]",
		"a named provider with no client": "identity_providers: [{slug: a, kind: github}]",
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
