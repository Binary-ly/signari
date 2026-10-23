package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/store"
)

func testJWKS(t *testing.T, private bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k any = &key.PublicKey
	if private {
		k = key
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k, KeyID: "a1", Algorithm: "ES256"}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func testCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "wallet-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The kinds whose material is public (6.25): authorization details types and
// the clients that may ask for them, a client's other grants kept, another
// organisation's client refused; attesters by their public keys, a private
// one refused; credentials and proof roots; all carried by an export.
func TestThePublicKindsAreDeclaredAndRoundTrip(t *testing.T) {
	ctx, pool, _ := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n := time.Now().UnixNano()
	plan := func(org, raw string, prune bool) (*File, *Plan, error) {
		t.Helper()
		f, err := Parse([]byte("version: 1\n" + raw))
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPlan(ctx, tx, org, f, prune)
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

	org := freshOrg(t, ctx, tx)
	wiki, bank := fmt.Sprintf("wiki-%d", n), fmt.Sprintf("bank-%d", n)
	clients := fmt.Sprintf("clients: [{client_id: %s, redirect_uris: ['https://w.example.test/cb']}, "+
		"{client_id: %s, redirect_uris: ['https://b.example.test/cb']}]\n", wiki, bank)
	types := func(to string) string {
		return clients + fmt.Sprintf("authorization_detail_types:\n"+
			"  - {type: payment, fields: [actions, locations], required: [actions], clients: [%s]}\n"+
			"  - {type: account_read, fields: [datatypes]}\n", to)
	}
	apply(org, types(wiki), false)
	// A grant the file does not govern: account_read names no clients.
	if err := store.AllowClientDetailType(ctx, tx, wiki, "account_read"); err != nil {
		t.Fatal(err)
	}
	if _, p, _ := plan(org, types(wiki), false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}
	apply(org, types(bank), false)
	if got, _ := store.ClientDetailTypes(ctx, tx, wiki); !slices.Equal(got, []string{"account_read"}) {
		t.Errorf("moved to another client, payment left %s holding %v", wiki, got)
	}
	if got, _ := store.ClientDetailTypes(ctx, tx, bank); !slices.Equal(got, []string{"payment"}) {
		t.Errorf("the client given payment holds %v", got)
	}
	other := freshOrg(t, ctx, tx)
	theirs := fmt.Sprintf("theirs-%d", n)
	if _, err := tx.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		client_secret_hash, grant_types, scopes) VALUES ($1, $2::uuid, 'T', 'public', '', '{authorization_code}',
		'{openid}')`, theirs, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plan(org, types(theirs), false); !errors.Is(err, ErrRefused) {
		t.Errorf("a grant to another organisation's client answered %v", err)
	}

	issuer := freshOrg(t, ctx, tx)
	material := fmt.Sprintf(`client_attesters: [{name: android, jwks: %s, description: Play Integrity}]
credential_configurations:
  - {config_id: employee, vct: 'https://example.test/employee', always_claims: [sub], selective_claims: [email],
     lifetime: 720h}
credential_proof_roots:
  - name: wallet-ca
    certificate: %q
`, testJWKS(t, false), testCA(t))
	apply(issuer, material, false)
	if _, p, _ := plan(issuer, material, false); !p.Empty() {
		t.Errorf("applied again it plans\n%s", p)
	}
	if p := apply(issuer, strings.Replace(material, "720h", "24h", 1), false); !strings.Contains(p.String(), "lifetime") {
		t.Errorf("a new lifetime was planned as\n%s", p)
	}
	exported, err := Export(ctx, tx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	copyOrg := freshOrg(t, ctx, tx)
	body := strings.TrimPrefix(string(out), "version: 1\n")
	apply(copyOrg, body, false)
	if _, p, _ := plan(copyOrg, body, false); !p.Empty() {
		t.Errorf("the export applied elsewhere plans\n%s", p)
	}
	if p := apply(issuer, "", true); len(p.Destructive()) != 3 {
		t.Errorf("pruned, the plan reads\n%s", p)
	}

	for name, raw := range map[string]string{
		"a type with no fields":          "authorization_detail_types: [{type: t, fields: []}]",
		"a field RFC 9396 does not name": "authorization_detail_types: [{type: t, fields: [colour]}]",
		"a private attester key":         "client_attesters: [{name: a, jwks: " + testJWKS(t, true) + "}]",
		"a credential asserting nothing": "credential_configurations: [{config_id: c, vct: 'https://x.test/v'}]",
		"a claim the issuer cannot put":  "credential_configurations: [{config_id: c, vct: 'https://x.test/v', always_claims: [salary]}]",
		"a root that is no CA":           fmt.Sprintf("credential_proof_roots: [{name: r, certificate: %q}]", lifecycleLeaf(t)),
	} {
		if _, err := Parse([]byte("version: 1\n" + raw + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// lifecycleLeaf is a certificate that is no CA.
func lifecycleLeaf(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
