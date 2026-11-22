package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// An apply changes what the file names and leaves alone what it does not.
//
// The plan already said so: it reports no change to a client's or a SAML
// provider's name, scopes, name-ID format or `enabled` when the file leaves
// them out. The write did not agree. Any other change to the object rewrote all
// of them from defaults, so an apply that only moved a redirect URI switched
// back on a client an operator had disabled (the lever for cutting off a
// compromised integration), renamed it to its identifier, and reset its
// scopes; a SAML provider went back to `persistent` and enabled.
func TestAnApplyLeavesAloneWhatTheFileDoesNotName(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := fmt.Sprintf("cfg-keep-%d", time.Now().UnixNano())
	entity := "https://sp.test/" + id
	off := false
	apply := func(f *File) *Plan {
		t.Helper()
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}

	apply(&File{
		Clients: []Client{{ClientID: id, Name: "Wiki", RedirectURIs: []string{"https://wiki.test/a"},
			Scopes: []string{"openid", "email"}, Enabled: &off}},
		SAMLProviders: []SAMLProvider{{EntityID: entity, Name: "Intranet",
			ACSURLs: []string{"https://sp.test/acs-a"}, NameID: "emailAddress", Enabled: &off}},
	})

	plan := apply(&File{
		Clients:       []Client{{ClientID: id, RedirectURIs: []string{"https://wiki.test/b"}}},
		SAMLProviders: []SAMLProvider{{EntityID: entity, ACSURLs: []string{"https://sp.test/acs-b"}}},
	})
	for _, c := range plan.Changes {
		if c.Action != "update" || (c.Detail != "redirect_uris" && c.Detail != "acs_urls") {
			t.Errorf("the plan for a redirect and an ACS change also said %+v", c)
		}
	}

	var name, scopes string
	var enabled bool
	if err := tx.QueryRow(ctx, `
		SELECT display_name, array_to_string(scopes, ','), enabled FROM core.clients
		 WHERE client_id = $1`, id).Scan(&name, &scopes, &enabled); err != nil {
		t.Fatal(err)
	}
	if name != "Wiki" || scopes != "openid,email" || enabled {
		t.Errorf("the client is now %q, scopes %s, enabled %v; the file named none of them, "+
			"and the plan said none would change", name, scopes, enabled)
	}
	var redirect string
	if err := tx.QueryRow(ctx, `SELECT string_agg(redirect_uri, ',') FROM core.client_redirect_uris
		WHERE client_id = $1`, id).Scan(&redirect); err != nil || redirect != "https://wiki.test/b" {
		t.Errorf("the redirect URI the file did name is %q (%v)", redirect, err)
	}

	var spName, nameID string
	var spEnabled bool
	if err := tx.QueryRow(ctx, `
		SELECT display_name, name_id_format, enabled FROM core.saml_providers
		 WHERE org_id = $1::uuid AND entity_id = $2`, org, entity).Scan(&spName, &nameID, &spEnabled); err != nil {
		t.Fatal(err)
	}
	if spName != "Intranet" || nameID != "emailAddress" || spEnabled {
		t.Errorf("the SAML provider is now %q, %s, enabled %v; the file named none of them",
			spName, nameID, spEnabled)
	}

	// Another organisation's client_id is refused, and its client is untouched:
	// the plan reads only this organisation's clients, so it planned a create,
	// and the upsert used to rewrite the other tenant's row and redirect URIs.
	var otherOrg string
	if err := tx.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://cfg-other-' || gen_random_uuid() || '.test', 'Other') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Other' FROM i
		RETURNING id::text`).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	theirs := id + "-theirs"
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, scopes)
		VALUES ($1, $2::uuid, 'Their app', 'confidential', 'unset', ARRAY['openid'])`, theirs, otherOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
		VALUES ($1, 'https://theirs.test/cb')`, theirs); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT before_collision`); err != nil {
		t.Fatal(err)
	}
	collide := &File{Clients: []Client{{ClientID: theirs, Name: "Mine", RedirectURIs: []string{"https://attacker.test/cb"}}}}
	cplan, err := BuildPlan(ctx, tx, org, collide, false)
	if err != nil {
		t.Fatal(err)
	}
	applyErr := Apply(ctx, tx, org, collide, cplan)
	if applyErr == nil || !strings.Contains(applyErr.Error(), "another organisation") {
		t.Errorf("declaring another organisation's client_id answered %v", applyErr)
	}
	if applyErr == nil {
		// It went through: read what it did to the other tenant before the
		// savepoint undoes it. (A refusal aborts the transaction, so there is
		// nothing to read until the rollback, and nothing was written.)
		var theirName, theirRedirect string
		if err := tx.QueryRow(ctx, `SELECT c.display_name, string_agg(r.redirect_uri, ',') FROM core.clients c
			JOIN core.client_redirect_uris r USING (client_id) WHERE c.client_id = $1
			GROUP BY c.display_name`, theirs).Scan(&theirName, &theirRedirect); err != nil {
			t.Fatal(err)
		}
		if theirName != "Their app" || theirRedirect != "https://theirs.test/cb" {
			t.Errorf("the other tenant's client became %q redirecting to %s", theirName, theirRedirect)
		}
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_collision`); err != nil {
		t.Fatal(err)
	}

	// Creating still fills in the defaults for what a new object leaves out.
	fresh := id + "-new"
	apply(&File{Clients: []Client{{ClientID: fresh, RedirectURIs: []string{"https://new.test/cb"}}}})
	if err := tx.QueryRow(ctx, `SELECT display_name, array_to_string(scopes, ','), enabled
		FROM core.clients WHERE client_id = $1`, fresh).Scan(&name, &scopes, &enabled); err != nil {
		t.Fatal(err)
	}
	if name != fresh || !strings.Contains(scopes, "openid") || !enabled {
		t.Errorf("a new client with nothing but a redirect is %q, %s, enabled %v", name, scopes, enabled)
	}
}
