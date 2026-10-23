package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/config"
	"signari.dev/engine/internal/migrate"
)

// An organisation's export and deletion (6.11).

// lifecycleCertificate is a SAML upstream's signing certificate, valid for a
// day: registration refuses one that has expired. ca makes it a CA, as a
// credential proof root must be.
func lifecycleCertificate(t *testing.T, ca ...bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	if len(ca) > 0 && ca[0] {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newLifecycleOrg makes an organisation of its own in the shared database.
func newLifecycleOrg(t *testing.T, db *pgx.Conn) (org, slug string) {
	t.Helper()
	ctx := context.Background()
	slug = fmt.Sprintf("life-%d", time.Now().UnixNano())
	if err := db.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, $1, 'Lifecycle' FROM core.instances ORDER BY created_at LIMIT 1
		RETURNING id::text`, slug).Scan(&org); err != nil {
		t.Skipf("no instance to make an organisation in: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.Exec(ctx, `DELETE FROM core.users WHERE org_id::text = $1`, org)
		_, _ = db.Exec(ctx, `DELETE FROM core.clients WHERE org_id::text = $1`, org)
		_, _ = db.Exec(ctx, `DELETE FROM core.organizations WHERE id::text = $1`, org)
	})
	return org, slug
}

func TestAnExportedOrganisationAppliedToAnEmptyDeploymentPlansNothing(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	org, _ := newLifecycleOrg(t, db)
	n := time.Now().UnixNano()
	// The kinds holding a secret seal it, here and in the empty deployment.
	if os.Getenv("SIGNARI_ROOT_KEY") == "" {
		t.Setenv("SIGNARI_ROOT_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}
	t.Setenv("LIFECYCLE_SCIM_TOKEN", fmt.Sprintf("scim-token-%d", n))
	t.Setenv("LIFECYCLE_AD_PASSWORD", fmt.Sprintf("bind-%d", n))
	t.Setenv("LIFECYCLE_DUO_SECRET", fmt.Sprintf("%040d", n))
	cert, ca := lifecycleCertificate(t), lifecycleCertificate(t, true)
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &attesterKey.PublicKey, KeyID: "k1",
		Algorithm: "ES256"}}})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seed, []byte(fmt.Sprintf(`version: 1
groups:
  - name: staff-%[1]d
    display_name: Staff
    description: Everyone who works here
clients:
  - client_id: web-%[1]d
    name: Web
    redirect_uris: [https://web.example.test/cb, https://web.example.test/cb2]
    scopes: [openid, profile, email, hr-%[1]d]
    access_token_ttl: 10m
    first_party: true
    post_logout_redirect_uris: [https://web.example.test/bye]
  - client_id: spa-%[1]d
    name: SPA
    public: true
    redirect_uris: [https://spa.example.test/cb]
    scopes: [openid]
    portal_hidden: true
saml_providers:
  - entity_id: https://sp-%[1]d.example.test/metadata
    name: Wiki
    acs_urls: [https://sp-%[1]d.example.test/acs]
    name_id_format: emailAddress
radius_clients:
  - name: vpn
    network: 10.%[2]d.0.0/24
proxy_hosts:
  - host: grafana-%[1]d.example.test
scopes:
  - name: hr-%[1]d
    display_name: HR
    description: Human resources data
    advertise: true
attributes:
  - name: department
    display_name: Department
    user_readable: true
  - name: badge
    value_type: number
    personal: true
resources:
  - resource: https://api-%[1]d.example.test
    name: API
signup:
  domains: [Example.TEST]
  groups: [staff-%[1]d]
  require_approval: true
claim_mappers:
  - attribute: department
    claim: department
    destination: id_token
    client_id: web-%[1]d
    required_scope: hr-%[1]d
  - attribute: department
    claim: dept
    destination: userinfo
    all_clients: true
prompts:
  - slug: terms-%[1]d
    title: Terms of use
    body: Read and accept them to go on.
    once: true
    fields:
      - {name: accept, type: checkbox, label: I accept, required: true}
access_policy: |
  version: 1
  policies:
    - name: wiki-needs-staff
      when: {client: wiki}
      require: {groups: [staff]}
  tests:
    - name: staff get the wiki
      given: {client: wiki, groups: [staff]}
      expect: allow
    - name: others do not
      given: {client: wiki, groups: []}
      expect: deny
sign_in_flow: |
  version: 1
  flows:
    - name: default-sign-in
      on: authentication
      stages:
        - one_of:
            - {stage: passkey, when: proved_by_passkey}
            - {stage: kerberos, when: proved_by_kerberos}
            - {stage: federated, when: proved_by_federated}
            - {stage: password}
        - {stage: mfa, when: user_has_second_factor}
        - session
      tests:
        - name: password only
          given: {}
          expect: [password, session]
registration: {max_clients: 7}
webauthn_policy: {attestation: direct, timeout_seconds: 120}
uma: {owner_intervention: true}
group_releases:
  - {client_id: web-%[1]d, groups: [staff-%[1]d]}
  - {saml_provider: 'https://sp-%[1]d.example.test/metadata', all_groups: true}
radius_authorizations: [{group: staff-%[1]d, vlan: 20}]
authorization_detail_types:
  - {type: payment, fields: [actions, locations], required: [actions], clients: [web-%[1]d]}
client_attesters: [{name: android, jwks: %[4]s, description: Play}]
credential_configurations:
  - {config_id: employee, vct: 'https://example.test/employee', always_claims: [sub], lifetime: 720h}
credential_proof_roots: [{name: wallet-ca, certificate: %[5]q}]
directory_sources:
  - {slug: ad-%[1]d, kind: ldap, url: 'ldaps://dc-%[1]d.example.test', bind_dn: 'CN=svc,DC=corp,DC=test',
     password: {env: LIFECYCLE_AD_PASSWORD}, base_dn: 'DC=corp,DC=test', flavour: ad,
     group_map: [{remote: 'CN=Engineering,DC=corp,DC=test', group: staff-%[1]d}]}
duo: {client_id: DIABCDEFGHIJKLMNOPQR, secret: {env: LIFECYCLE_DUO_SECRET}, api_host: api-1234abcd.duosecurity.com}
migration_source: {kind: ldap, name: Old directory, url: 'ldaps://old-%[1]d.example.test',
  bind_dn_template: 'uid={username},ou=people,dc=corp,dc=test'}
providers:
  - {hook: authorize, url: 'https://pdp-%[1]d.example.test/', mode: fail_closed, timeout: 3s}
event_subscriptions:
  - {name: siem-%[1]d, url: 'https://siem-%[1]d.example.test/in', event_types: [login.failed]}
scim_targets:
  - {slug: slack-%[1]d, base_url: 'https://scim-%[1]d.example.test/v2', token: {env: LIFECYCLE_SCIM_TOKEN},
     scope_group: staff-%[1]d, dry_run: true}
rac_connections:
  - {slug: build-%[1]d, protocol: ssh, host: build-%[1]d.internal, require_group: staff-%[1]d,
     parameters: {font-size: '12'}}
identity_providers:
  - {slug: gh-%[1]d, kind: github, client_id: gh, attribute_map: [{claim: company, attribute: department}]}
  - {slug: corp-%[1]d, kind: oidc, client_id: corp, issuer: 'https://corp-%[1]d.example.test',
     authorize_url: 'https://corp-%[1]d.example.test/authorize', token_url: 'https://corp-%[1]d.example.test/token',
     jwks_url: 'https://corp-%[1]d.example.test/jwks', mfa_amr: [mfa]}
  - slug: adfs-%[1]d
    kind: saml
    saml:
      entity_id: https://adfs-%[1]d.example.test/trust
      sso_url: https://adfs-%[1]d.example.test/ls
      certificate: %[3]q
`, n, n%250, cert, jwks, ca)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"apply", "-dsn", dsn, "-org", org, "-f", seed}); err != nil {
		t.Fatalf("seeding the organisation: %v", err)
	}

	out := filepath.Join(dir, "export.yaml")
	if err := run([]string{"export", "org", "-dsn", dsn, "-org", org, "-out", out}); err != nil {
		t.Fatalf("export org: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("the export does not parse as a configuration: %v\n%s", err, raw)
	}
	// Planned as `signari plan` plans: the secrets a file names read here, and
	// compared under the root key.
	root, err := rootKey()
	if err != nil {
		t.Fatal(err)
	}
	planWith := func(conn *pgx.Conn, orgID string, file *config.File) *config.Plan {
		t.Helper()
		if err := file.ResolveSecrets(localSecret(seed)); err != nil {
			t.Fatal(err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		p, err := config.BuildPlanWith(ctx, tx, orgID, file, true, config.Options{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	planOf := func(conn *pgx.Conn, orgID string) *config.Plan { return planWith(conn, orgID, f) }
	if p := planOf(db, org); !p.Empty() {
		t.Errorf("the export plans changes against the organisation it came from:\n%s", p)
	}

	// An empty deployment: a database of its own, migrated, with one organisation.
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("signari_exporttest_%d", n)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	scratch := u.String()
	conn, err := pgx.Connect(ctx, scratch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	// As an operator makes one: an instance with its first signing keys, and an
	// organisation in it.
	if os.Getenv("SIGNARI_ROOT_KEY") == "" {
		t.Setenv("SIGNARI_ROOT_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}
	if err := run([]string{"instance", "create", "-dsn", scratch, "-issuer", "https://fresh.example.test"}); err != nil {
		t.Fatalf("instance create: %v", err)
	}
	var fresh string
	if err := conn.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'fresh', 'Fresh' FROM core.instances RETURNING id::text`).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	// The export carries no secret; a provisioning target's token, which the
	// target issued, is named by reference before it applies, as an operator
	// names it, and the plan refuses it otherwise.
	if err := run([]string{"apply", "-dsn", scratch, "-org", fresh, "-f", out}); err == nil ||
		!strings.Contains(err.Error(), "name it by reference") {
		t.Fatalf("the export applied with no token for its target answered %v", err)
	}
	given := strings.NewReplacer("      base_url: ", "      token: {env: LIFECYCLE_SCIM_TOKEN}\n      base_url: ",
		"      bind_dn: ", "      password: {env: LIFECYCLE_AD_PASSWORD}\n      bind_dn: ",
		"\nduo:\n", "\nduo:\n    secret: {env: LIFECYCLE_DUO_SECRET}\n").Replace(string(raw))
	givenRaw := []byte(given)
	givenPath := filepath.Join(dir, "export-given.yaml")
	if err := os.WriteFile(givenPath, givenRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	fGiven, err := config.Parse(givenRaw)
	if err != nil {
		t.Fatal(err)
	}
	if p := planWith(conn, fresh, fGiven); p.Empty() {
		t.Fatal("the export plans nothing against an empty organisation, so it carries nothing")
	}
	if err := run([]string{"apply", "-dsn", scratch, "-org", fresh, "-f", givenPath}); err != nil {
		t.Fatalf("applying the export to an empty deployment: %v", err)
	}
	if p := planWith(conn, fresh, fGiven); !p.Empty() {
		t.Errorf("after applying the export, the empty deployment still plans:\n%s", p)
	}
	// And it holds what the organisation was made from: an export that left a
	// kind out would plan nothing above, against a deployment without it.
	seedRaw, err := os.ReadFile(seed)
	if err != nil {
		t.Fatal(err)
	}
	seedFile, err := config.Parse(seedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if p := planWith(conn, fresh, seedFile); !p.Empty() {
		t.Errorf("the deployment the export was applied to lacks what the organisation was made from:\n%s", p)
	}
}

// A read that fails is reported as what failed (0.30). The plan's read of the
// deployment did not look at a query's error after its rows, so a failure was
// taken for an empty result and the next statement said only that the
// transaction had aborted; an export through the same read would have written
// part of an organisation.
func TestAPlanThatCannotReadTheDeploymentSaysWhy(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	f := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(f, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"plan", "-dsn", dsn, "-org", "not-an-organisation", "-f", f})
	if err == nil || !strings.Contains(err.Error(), "invalid input syntax") {
		t.Errorf("a plan whose read failed answered %v, want the read's own error", err)
	}
}

func TestAnOrganisationIsDeletedOnlySuspendedAndConfirmed(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	org, slug := newLifecycleOrg(t, db)
	var people [2]string
	for i := range people {
		email := fmt.Sprintf("%s-%d@example.test", slug, i)
		if err := db.QueryRow(ctx, `INSERT INTO core.users (org_id, email, user_handle)
			VALUES ($1::uuid, $2, sha256($3::bytea) || sha256($4::bytea)) RETURNING id::text`,
			org, email, email, slug).Scan(&people[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '1 hour')`, slug+"-sid", org, people[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type, enabled)
		VALUES ($1, $2::uuid, 'Doomed', 'public', true)`, slug+"-app", org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'staff', 'Staff')`, org); err != nil {
		t.Fatal(err)
	}
	exists := func() bool {
		var ok bool
		if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.organizations WHERE id::text = $1)`,
			org).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	code := func() string {
		t.Helper()
		c, err := readCensus(ctx, db, org, false)
		if err != nil {
			t.Fatal(err)
		}
		return c.confirmation(org)
	}

	// The first phase says what would go and deletes nothing.
	if err := run([]string{"instance", "org-delete", "-dsn", dsn, "-org", org}); err != nil || !exists() {
		t.Fatalf("the first phase: %v, organisation still there %v", err, exists())
	}
	if err := run([]string{"instance", "org-delete", "-dsn", dsn, "-org", org, "-confirm", code()}); err == nil || !exists() {
		t.Fatal("an active organisation was deleted")
	}
	if err := run([]string{"instance", "org-status", "-dsn", dsn, "-org", org, "-status", "suspended"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"instance", "org-delete", "-dsn", dsn, "-org", org, "-confirm", "not-the-code"}); err == nil || !exists() {
		t.Fatal("a wrong code deleted it")
	}
	stale := code()
	if _, err := db.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'added-since', 'Added')`, org); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"instance", "org-delete", "-dsn", dsn, "-org", org, "-confirm", stale}); err == nil || !exists() {
		t.Fatal("a code read before the organisation changed deleted it")
	}

	if err := run([]string{"instance", "org-delete", "-dsn", dsn, "-org", org, "-confirm", code()}); err != nil {
		t.Fatalf("the confirmed deletion: %v", err)
	}
	if exists() {
		t.Fatal("confirmed, the organisation is still there")
	}
	var users, shredded, sessions int
	if err := db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core.users WHERE id::text = ANY($1)),
		(SELECT count(*) FROM core.subject_keys WHERE subject_id::text = ANY($1) AND erased_at IS NOT NULL),
		(SELECT count(*) FROM core.sessions WHERE sid = $2)`, people[:], slug+"-sid").Scan(&users, &shredded, &sessions); err != nil {
		t.Fatal(err)
	}
	if users != 0 || shredded != 2 || sessions != 0 {
		t.Errorf("after deletion: %d people left, %d erased, %d sessions left", users, shredded, sessions)
	}
	var erased string
	if err := db.QueryRow(ctx, `SELECT detail->>'people_erased' FROM core.audit_events
		WHERE event_type = 'admin.organization_deleted' AND org_id::text = $1`, org).Scan(&erased); err != nil || erased != "2" {
		t.Errorf("the deletion's record: %q (%v)", erased, err)
	}
}
