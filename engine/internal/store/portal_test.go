package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// What the portal must never list.
//
// Every exclusion here is a disclosure if it goes wrong. A machine-to-machine
// client on the portal publishes the organisation's internal service inventory
// to every employee; a disabled client advertises something that will refuse
// them; a hidden one was hidden deliberately. The query is short enough to look
// obviously correct and has four separate conditions, which is exactly the
// shape of thing that quietly loses one during a refactor.
func TestPortalExcludesWhatItMust(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "SET ROLE signari_maintenance"); err != nil {
		t.Fatalf("assuming signari_maintenance: %v", err)
	}

	var orgID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ((SELECT id FROM core.instances ORDER BY created_at LIMIT 1),
		        'portal-test-' || substr(md5(random()::text),1,8), 'Portal Test')
		RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatalf("creating an organisation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.organizations WHERE id = $1::uuid`, orgID)
	})

	// Unique per run. A test that only passes against a clean database is one
	// that fails for whoever runs it second.
	var suffix string
	if err := pool.QueryRow(ctx, `SELECT substr(md5(random()::text),1,8)`).Scan(&suffix); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		clientID   string
		enabled    bool
		hidden     bool
		grants     []string
		wantListed bool
		why        string
	}{
		{"pt-normal-" + suffix, true, false, []string{"authorization_code"}, true,
			"an ordinary browser application"},
		{"pt-disabled-" + suffix, false, false, []string{"authorization_code"}, false,
			"a disabled client would offer a tile that refuses whoever clicks it"},
		{"pt-hidden-" + suffix, true, true, []string{"authorization_code"}, false,
			"portal_hidden was set deliberately"},
		{"pt-machine-" + suffix, true, false, []string{"client_credentials"}, false,
			"a machine-to-machine client cannot start a browser flow, and listing " +
				"it publishes the internal service inventory"},
	}

	for _, c := range cases {
		if _, err := pool.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          client_secret_hash, scopes, grant_types,
			                          enabled, portal_hidden, initiate_login_uri)
			VALUES ($1, $2::uuid, $1, 'confidential', 'x', ARRAY['openid'], $3, $4, $5,
			        'https://example.test/')`,
			c.clientID, orgID, c.grants, c.enabled, c.hidden); err != nil {
			t.Fatalf("inserting %s: %v", c.clientID, err)
		}
	}

	apps, err := ListPortalCandidates(ctx, pool, orgID)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	listed := map[string]bool{}
	for _, a := range apps {
		listed[a.ClientID] = true
	}

	for _, c := range cases {
		if listed[c.clientID] != c.wantListed {
			verb := "was not listed but should be"
			if listed[c.clientID] {
				verb = "was listed and must not be"
			}
			t.Errorf("%s %s: %s", c.clientID, verb, c.why)
		}
	}
}

// TestPortalDoesNotCrossOrganisations is the tenancy check.
//
// A portal that leaked across organisations would show one customer the names
// of another customer's applications, which is the worst possible failure for a
// feature whose entire purpose is listing things by name.
func TestPortalDoesNotCrossOrganisations(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "SET ROLE signari_maintenance"); err != nil {
		t.Fatalf("assuming signari_maintenance: %v", err)
	}

	var suffixB string
	if err := pool.QueryRow(ctx, `SELECT substr(md5(random()::text),1,8)`).Scan(&suffixB); err != nil {
		t.Fatal(err)
	}

	var a, b string
	for _, p := range []*string{&a, &b} {
		if err := pool.QueryRow(ctx, `
			INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ((SELECT id FROM core.instances ORDER BY created_at LIMIT 1),
			        'tenancy-' || substr(md5(random()::text),1,8), 'Tenancy')
			RETURNING id::text`).Scan(p); err != nil {
			t.Fatalf("creating an organisation: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.organizations WHERE id = ANY(ARRAY[$1,$2]::uuid[])`, a, b)
	})

	for i, org := range []string{a, b} {
		id := "pt-tenant-a-" + suffixB
		if i == 1 {
			id = "pt-tenant-b-" + suffixB
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          client_secret_hash, scopes, grant_types, enabled)
			VALUES ($1, $2::uuid, $1, 'confidential', 'x', ARRAY['openid'],
			        ARRAY['authorization_code'], true)`, id, org); err != nil {
			t.Fatalf("inserting %s: %v", id, err)
		}
	}

	apps, err := ListPortalCandidates(ctx, pool, a)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	for _, app := range apps {
		if app.ClientID == "pt-tenant-b-"+suffixB {
			t.Fatal("the portal listed another organisation's application")
		}
	}
}
