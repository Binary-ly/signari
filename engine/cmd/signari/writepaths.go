package main

// The write paths for the configuration this engine reads.
//
// # Why these are collected in one file
//
// Every table and column touched here was added with its reader, its tests and
// its documentation, and with NO WAY FOR AN OPERATOR TO PUT A ROW IN IT. The
// loader ran on every request, found nothing, and returned the default -- so the
// feature was absent in exactly the way that is hardest to notice: no error, no
// warning, and a query plan that says the operator simply has not configured it
// yet.
//
// Ten of them were found at once, which is what makes it a class rather than an
// oversight. `TestEveryGovernedTableHasAWritePath` in internal/docsync now fails
// the build when a table or column the engine reads for a decision has no writer
// outside a migration, so the next one cannot be added the same way.
//
// A reachability guard over FUNCTIONS already existed and passed throughout,
// because each of these loaders genuinely had a call site. A function being
// called is not the same as a capability being reachable, and the difference is
// exactly one table nobody can write to.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// userLocale sets the language a person's security notices are written in.
//
// core.users.locale is read by the notice path to choose a message bundle.
// Empty clears it rather than storing "", so the column means "this person has
// expressed no preference" and the deployment default applies -- a stored empty
// string would be a preference for a locale that does not exist.
func userLocale(ctx context.Context, conn *pgx.Conn, email, tag string) error {
	if email == "" {
		return fmt.Errorf("give -email")
	}
	tag = strings.TrimSpace(tag)

	var stored any
	if tag != "" {
		stored = tag
	}
	tp, err := conn.Exec(ctx, `
		UPDATE core.users SET locale = $2
		WHERE lower(email) = lower($1) OR lower(username) = lower($1)`, email, stored)
	if err != nil {
		// The column carries a shape constraint. A rejected tag is a typo, and
		// saying which one costs nothing.
		if strings.Contains(err.Error(), "users_locale_is_a_tag") {
			return fmt.Errorf("%q is not a BCP 47 language tag. Examples: en, de, pt-BR", tag)
		}
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("no user %q", email)
	}
	if tag == "" {
		fmt.Printf("cleared the locale for %s; notices use the deployment default\n", email)
		return nil
	}
	fmt.Printf("%s will receive security notices in %s\n", email, tag)
	fmt.Println("\n  Only if a bundle for that tag is installed. `signari i18n list` shows which are.")
	return nil
}

// webauthnPolicySet decides which authenticators an organisation accepts.
//
// The two settings are not independent and the database enforces it: an
// allow-list with conveyance `none` is refused, because with no attestation the
// AAGUID is chosen by the authenticator being filtered. Filtering on a value the
// filtered party supplies is not a filter, and the constraint says so rather
// than leaving it to whoever reads the column next.
func webauthnPolicySet(ctx context.Context, conn *pgx.Conn, orgID, conveyance, list string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	switch conveyance {
	case "none", "indirect", "direct", "enterprise":
	default:
		return fmt.Errorf("-attestation must be none, indirect, direct or enterprise, not %q",
			conveyance)
	}

	ids := []string{}
	for _, a := range strings.Split(list, ",") {
		if a = strings.TrimSpace(a); a != "" {
			ids = append(ids, a)
		}
	}
	if len(ids) > 0 && conveyance == "none" {
		return fmt.Errorf("an allow-list needs attestation. With -attestation none the " +
			"authenticator states its own model identifier and nothing vouches for it, " +
			"so the list would admit any device claiming an approved one. Set " +
			"-attestation direct")
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.webauthn_policy (org_id, attestation_conveyance, allowed_aaguids)
		VALUES ($1::uuid, $2, $3::uuid[])
		ON CONFLICT (org_id) DO UPDATE
		   SET attestation_conveyance = EXCLUDED.attestation_conveyance,
		       allowed_aaguids        = EXCLUDED.allowed_aaguids,
		       updated_at             = now()`, orgID, conveyance, ids); err != nil {
		if strings.Contains(err.Error(), "invalid input syntax for type uuid") {
			return fmt.Errorf("an AAGUID must be a uuid, e.g. " +
				"ee882879-721c-4913-9775-3dfcce97072a. Stored as uuids so a malformed " +
				"one is refused here rather than silently never matching")
		}
		return err
	}

	fmt.Printf("attestation conveyance: %s\n", conveyance)
	if len(ids) == 0 {
		fmt.Println("allow-list            : empty -- every authenticator is accepted")
	} else {
		fmt.Printf("allow-list            : %s\n", strings.Join(ids, ", "))
		fmt.Println("\n  Registrations from any other model are now refused for this organisation.")
		fmt.Println("  Existing credentials are NOT re-checked; this governs new enrolments.")
	}
	if conveyance != "none" && len(ids) == 0 {
		// Worth saying plainly. Conveyance alone changes what the browser is
		// asked for and nothing about what is accepted, which is easy to read as
		// enforcement when it is not.
		fmt.Println("\n  Attestation is requested but nothing is enforced without -aaguids.")
	}
	return nil
}

// webauthnPolicyShow prints every organisation's authenticator policy.
func webauthnPolicyShow(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT o.slug, p.attestation_conveyance, p.allowed_aaguids::text[]
		FROM core.webauthn_policy p
		JOIN core.organizations o ON o.id = p.org_id
		ORDER BY o.slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-24s %-14s %s\n", "ORGANISATION", "ATTESTATION", "ALLOWED MODELS")
	var n int
	for rows.Next() {
		var slug, conveyance string
		var ids []string
		if err := rows.Scan(&slug, &conveyance, &ids); err != nil {
			return err
		}
		allowed := "any"
		if len(ids) > 0 {
			allowed = strings.Join(ids, ", ")
		}
		fmt.Printf("%-24s %-14s %s\n", slug, conveyance, allowed)
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n == 0 {
		fmt.Println("\n  None set. Every organisation accepts every authenticator, which is the")
		fmt.Println("  browser default and the privacy-preserving choice.")
	}
	return nil
}

// idpAttributeMap routes a claim from an external provider into a local attribute.
//
// The attribute is referenced by id, not name, so dropping the attribute takes
// the mapping with it. A mapping naming an attribute that no longer exists would
// silently discard every value it carried on each sign-in.
func idpAttributeMap(ctx context.Context, conn *pgx.Conn, slug, claim, attribute string,
	overwrite bool, maxLength int, remove bool) error {

	if slug == "" || claim == "" || attribute == "" {
		return fmt.Errorf("give -slug, -claim and -attribute")
	}

	var providerID, orgID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, org_id::text FROM core.identity_providers WHERE slug = $1`,
		slug).Scan(&providerID, &orgID); err != nil {
		return fmt.Errorf("no identity provider with slug %q", slug)
	}

	var attributeID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.user_attribute_schema
		 WHERE org_id = $1::uuid AND name = $2`, orgID, attribute).Scan(&attributeID); err != nil {
		return fmt.Errorf("that organisation has no attribute named %q. Declare it first "+
			"through the admin API; an attribute carries whether its values are sealed, "+
			"and a mapping cannot decide that for it", attribute)
	}

	if remove {
		tp, err := conn.Exec(ctx, `
			DELETE FROM core.idp_attribute_map
			WHERE provider_id = $1::uuid AND upstream_claim = $2 AND attribute_id = $3::uuid`,
			providerID, claim, attributeID)
		if err != nil {
			return err
		}
		if tp.RowsAffected() == 0 {
			return fmt.Errorf("%s does not map %q to %q", slug, claim, attribute)
		}
		fmt.Printf("%s no longer maps %q into %q\n", slug, claim, attribute)
		return nil
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.idp_attribute_map
		    (provider_id, org_id, upstream_claim, attribute_id, overwrite, max_length)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6)
		ON CONFLICT (provider_id, upstream_claim, attribute_id) DO UPDATE
		   SET overwrite = EXCLUDED.overwrite, max_length = EXCLUDED.max_length`,
		providerID, orgID, claim, attributeID, overwrite, maxLength); err != nil {
		return err
	}

	fmt.Printf("%s: %q -> attribute %q (max %d bytes)\n", slug, claim, attribute, maxLength)
	if overwrite {
		fmt.Println("\n  -overwrite is on: every sign-in replaces whatever is stored, including")
		fmt.Println("  a value an administrator set by hand. That makes the provider the")
		fmt.Println("  system of record for this attribute.")
	} else {
		fmt.Println("\n  A value already present is kept. Turn on -overwrite to make the")
		fmt.Println("  provider authoritative.")
	}
	return nil
}

// dirGroupMap says which local group a directory group grants.
//
// A sync grants nothing that is not mapped here. That is the whole safety
// property: a directory reporting a group named `domain admins` cannot make
// anybody an administrator of this system unless somebody deliberately connected
// the two.
func dirGroupMap(ctx context.Context, conn *pgx.Conn, slug, remote, local string, remove bool) error {
	if slug == "" || remote == "" || local == "" {
		return fmt.Errorf("give -slug (the directory source), -remote-group and -group")
	}

	var sourceID, orgID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, org_id::text FROM core.directory_sources WHERE slug = $1`,
		slug).Scan(&sourceID, &orgID); err != nil {
		return fmt.Errorf("no directory source with slug %q", slug)
	}

	var groupID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, local).Scan(&groupID); err != nil {
		return fmt.Errorf("no group named %q in that organisation; create it with "+
			"`signari group create`", local)
	}

	if remove {
		tp, err := conn.Exec(ctx, `
			DELETE FROM core.directory_group_map
			WHERE source_id = $1::uuid AND remote_group = $2 AND group_id = $3::uuid`,
			sourceID, remote, groupID)
		if err != nil {
			return err
		}
		if tp.RowsAffected() == 0 {
			return fmt.Errorf("%s does not map %q to %q", slug, remote, local)
		}
		fmt.Printf("%s no longer grants %q from %q\n", slug, local, remote)
		fmt.Println("\n  Existing memberships are untouched until the next sync, which will")
		fmt.Println("  now see this group as ungoverned and leave it alone.")
		return nil
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.directory_group_map (source_id, org_id, remote_group, group_id)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid)
		ON CONFLICT (source_id, remote_group, group_id) DO NOTHING`,
		sourceID, orgID, remote, groupID); err != nil {
		return err
	}

	fmt.Printf("%s: directory group %q grants %q\n", slug, remote, local)
	fmt.Println("\n  The next sync reconciles membership of this group from the directory.")
	fmt.Println("  Preview it first -- `signari dir sync -slug " + slug + "` shows the plan")
	fmt.Println("  without applying it, and the removal ceiling refuses a plan that strips")
	fmt.Println("  too many people at once.")
	return nil
}

// radiusAuthorize places a group's members on a VLAN.
//
// RFC 3580 §3.31 bounds a VLAN id to 1-4094 and the column enforces it. A row
// that sets neither a VLAN nor a Filter-Id is refused by the table, because a
// row authorising nothing is a configuration somebody believes is doing
// something.
func radiusAuthorize(ctx context.Context, conn *pgx.Conn, orgID, group string,
	vlan int, filterID string, priority int, remove bool) error {

	if orgID == "" || group == "" {
		return fmt.Errorf("give -org and -group")
	}
	var groupID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, group).Scan(&groupID); err != nil {
		return fmt.Errorf("no group named %q in that organisation", group)
	}

	if remove {
		tp, err := conn.Exec(ctx,
			`DELETE FROM core.radius_group_authorization WHERE group_id = $1::uuid`, groupID)
		if err != nil {
			return err
		}
		if tp.RowsAffected() == 0 {
			return fmt.Errorf("%q carries no RADIUS authorisation", group)
		}
		fmt.Printf("%q no longer carries a VLAN or filter\n", group)
		fmt.Println("\n  Members already connected keep their session until it is re-authorised;")
		fmt.Println("  RADIUS attributes are decided at Access-Accept, not re-evaluated.")
		return nil
	}

	if vlan == 0 && strings.TrimSpace(filterID) == "" {
		return fmt.Errorf("give -vlan, -filter-id or both. A row that authorises nothing " +
			"is a configuration somebody believes is doing something")
	}

	var vlanArg, filterArg any
	if vlan != 0 {
		vlanArg = vlan
	}
	if f := strings.TrimSpace(filterID); f != "" {
		filterArg = f
	}

	if _, err := conn.Exec(ctx, `
		INSERT INTO core.radius_group_authorization
		    (org_id, group_id, vlan_id, filter_id, priority)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
		ON CONFLICT (org_id, group_id) DO UPDATE
		   SET vlan_id = EXCLUDED.vlan_id, filter_id = EXCLUDED.filter_id,
		       priority = EXCLUDED.priority`,
		orgID, groupID, vlanArg, filterArg, priority); err != nil {
		if strings.Contains(err.Error(), "radius_group_authorization_vlan_id_check") {
			return fmt.Errorf("a VLAN id is 12 bits: 1 to 4094 (RFC 3580 section 3.31). "+
				"%d is outside that, and a switch would reject or misread it", vlan)
		}
		return err
	}

	fmt.Printf("group %q:\n", group)
	if vlan != 0 {
		fmt.Printf("  VLAN      : %d\n", vlan)
	}
	if filterArg != nil {
		fmt.Printf("  Filter-Id : %s\n", filterArg)
	}
	fmt.Printf("  priority  : %d\n", priority)
	fmt.Println("\n  Somebody in several authorised groups gets the highest priority, and ties")
	fmt.Println("  break by group id so the same person lands on the same VLAN every time.")
	return nil
}

// providerClaimsSet bounds what a token hook may add.
//
// The allow-list is the whole security model of the hook. Without it an external
// service that returns `{"admin": true}` would put that claim in an access token
// this engine signed, and a resource server has no way to tell it apart from a
// claim the engine decided. The database also refuses protocol claims here, so
// no list can grant `sub`, `iss` or `exp`.
func providerClaimsSet(ctx context.Context, conn *pgx.Conn, orgID, hook, claims string) error {
	if orgID == "" || hook == "" {
		return fmt.Errorf("give -org and -hook")
	}
	list := []string{}
	for _, c := range strings.Split(claims, ",") {
		if c = strings.TrimSpace(c); c != "" {
			list = append(list, c)
		}
	}

	tp, err := conn.Exec(ctx, `
		UPDATE core.providers SET allowed_claims = $3
		WHERE org_id = $1::uuid AND hook = $2`, orgID, hook, list)
	if err != nil {
		if strings.Contains(err.Error(), "providers_claims_are_not_protocol_claims") {
			return fmt.Errorf("a hook may not be allowed to set a protocol claim " +
				"(sub, iss, aud, exp, iat, nbf, jti, nonce, azp, scope, client_id, " +
				"auth_time, acr, amr). Those are decided by the protocol, and letting " +
				"an external service overwrite one is how a token is minted for the " +
				"wrong subject")
		}
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("that organisation has no %q provider; add one with "+
			"`signari provider add`", hook)
	}

	if len(list) == 0 {
		fmt.Printf("%s: allowed claims cleared -- the hook can add nothing\n", hook)
		fmt.Println("\n  It still runs and can still veto. Only its claim output is discarded.")
		return nil
	}
	fmt.Printf("%s may add: %s\n", hook, strings.Join(list, ", "))
	fmt.Println("\n  Anything else it returns is dropped, logged and not signed.")
	return nil
}

// scimScope limits a provisioning target to one group's members.
//
// Without it a target receives every user in the organisation, which is right
// for a company-wide directory and wrong for an application five people use. The
// column is ON DELETE RESTRICT: deleting the group would silently widen the
// target to everybody, and a widening that happens as a side effect of deleting
// something else is not a change anybody would look for.
func scimScope(ctx context.Context, conn *pgx.Conn, slug, group string) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}

	var targetID, orgID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, org_id::text FROM core.scim_targets WHERE slug = $1`,
		slug).Scan(&targetID, &orgID); err != nil {
		return fmt.Errorf("no SCIM target with slug %q", slug)
	}

	if strings.TrimSpace(group) == "" {
		if _, err := conn.Exec(ctx,
			`UPDATE core.scim_targets SET scope_group_id = NULL WHERE id = $1::uuid`,
			targetID); err != nil {
			return err
		}
		fmt.Printf("%s is no longer scoped; every user in the organisation is provisioned\n", slug)
		fmt.Println("\n  Widening a target does NOT deprovision anybody. The next sync adds the")
		fmt.Println("  people who were previously out of scope.")
		return nil
	}

	var groupID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, group).Scan(&groupID); err != nil {
		return fmt.Errorf("no group named %q in that organisation", group)
	}
	if _, err := conn.Exec(ctx,
		`UPDATE core.scim_targets SET scope_group_id = $2::uuid WHERE id = $1::uuid`,
		targetID, groupID); err != nil {
		return err
	}

	fmt.Printf("%s now provisions only members of %q\n", slug, group)
	fmt.Println("\n  People already provisioned who are NOT in that group are handled by the")
	fmt.Println("  target's -on-deactivate setting on the next sync. Preview it first:")
	fmt.Println("    signari scim sync -slug " + slug)
	return nil
}

// scimProvisionGroup creates a group at a target and records that we own it.
//
// The link is what makes every later reconciliation safe. A group at the target
// with no row in core.scim_group_links is somebody else's -- a target's own
// administrators may already maintain "Engineering" -- and matching by name
// would adopt it and begin removing the members they put there.
func scimProvisionGroup(ctx context.Context, conn *pgx.Conn, slug, group string) error {
	if slug == "" || group == "" {
		return fmt.Errorf("give -slug (the SCIM target) and -group")
	}

	t, orgID, err := scimTargetForGroups(ctx, conn, slug)
	if err != nil {
		return err
	}

	var groupID, displayName string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, display_name FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
		orgID, group).Scan(&groupID, &displayName); err != nil {
		return fmt.Errorf("no group named %q in that organisation", group)
	}
	if displayName == "" {
		displayName = group
	}

	var existing string
	err = conn.QueryRow(ctx,
		`SELECT remote_id FROM core.scim_group_links
		 WHERE target_id = $1::uuid AND group_id = $2::uuid`, t.ID, groupID).Scan(&existing)
	if err == nil {
		return fmt.Errorf("%q already exists at %s as %s. Use `signari scim sync` to "+
			"reconcile its members", group, slug, existing)
	}
	if err != pgx.ErrNoRows {
		return err
	}

	// The same client `scim sync` uses, so SIGNARI_SCIM_CA_BUNDLE applies here
	// too. Building a plain http.Client instead — which this did first — means a
	// deployment whose target presents an internal CA can provision users and
	// not groups, and the failure arrives as a TLS error nobody connects to the
	// setting that would have fixed it.
	hc, err := scimHTTPClient()
	if err != nil {
		return err
	}
	client := scim.NewClient(t, hc)
	// externalId carries OUR group id. It is what lets somebody at the far end
	// tell which of their groups this system owns without reading our database,
	// and it survives a rename on either side.
	remoteID, err := client.CreateGroup(ctx, scim.Group{
		DisplayName: displayName,
		ExternalID:  groupID,
	})
	if err != nil {
		return fmt.Errorf("creating %q at %s: %w", displayName, slug, err)
	}

	// Recorded after the target answered, never before. A link written first and
	// a create that then failed would leave us claiming a group that does not
	// exist, and every later reconciliation would fail reading it.
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.scim_group_links (target_id, group_id, org_id, remote_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4)`,
		t.ID, groupID, orgID, remoteID); err != nil {
		return fmt.Errorf("the group was created at %s as %s but the link could not be "+
			"stored (%w). Delete it there and run this again, or the next attempt will "+
			"create a second one", slug, remoteID, err)
	}

	fmt.Printf("created %q at %s as %s\n", displayName, slug, remoteID)
	fmt.Println("\n  It has no members yet. `signari scim sync -slug " + slug + " -apply`")
	fmt.Println("  adds the members who already have an account at that target.")
	return nil
}

// scimDeprovisionGroup deletes a group at a target and forgets it.
//
// Ordered deliberately: delete there, then drop the link. The other order leaves
// a group at the target that nothing here remembers creating, which is
// unreachable by every later command -- the reconciliation only acts on groups
// the link table names.
func scimDeprovisionGroup(ctx context.Context, conn *pgx.Conn, slug, group string) error {
	if slug == "" || group == "" {
		return fmt.Errorf("give -slug (the SCIM target) and -group")
	}

	t, orgID, err := scimTargetForGroups(ctx, conn, slug)
	if err != nil {
		return err
	}

	var groupID, remoteID string
	if err := conn.QueryRow(ctx, `
		SELECT g.id::text, l.remote_id
		FROM core.groups g
		JOIN core.scim_group_links l ON l.group_id = g.id AND l.target_id = $1::uuid
		WHERE g.org_id = $2::uuid AND g.name = $3`,
		t.ID, orgID, group).Scan(&groupID, &remoteID); err != nil {
		return fmt.Errorf("%q is not provisioned to %s", group, slug)
	}

	// The same client `scim sync` uses, so SIGNARI_SCIM_CA_BUNDLE applies here
	// too. Building a plain http.Client instead — which this did first — means a
	// deployment whose target presents an internal CA can provision users and
	// not groups, and the failure arrives as a TLS error nobody connects to the
	// setting that would have fixed it.
	hc, err := scimHTTPClient()
	if err != nil {
		return err
	}
	client := scim.NewClient(t, hc)
	if err := client.DeleteGroup(ctx, remoteID); err != nil {
		return fmt.Errorf("deleting %s at %s: %w. The link is kept, so nothing here has "+
			"forgotten the group -- fix the target and run this again", remoteID, slug, err)
	}

	if _, err := conn.Exec(ctx, `
		DELETE FROM core.scim_group_links
		WHERE target_id = $1::uuid AND group_id = $2::uuid`, t.ID, groupID); err != nil {
		return err
	}

	fmt.Printf("deleted %s (%q) at %s\n", remoteID, group, slug)
	fmt.Println("\n  The local group is untouched. Only the copy at that target is gone.")
	return nil
}

// scimTargetForGroups loads a target by slug, refusing the ones a group command
// cannot act on.
//
// Through store.LoadSCIMTargets, NOT a query of its own. The `token` column
// holds CIPHERTEXT sealed under the root key, and the first version of this
// function selected it directly -- which would have sent the sealed bytes as the
// bearer token and failed with 401 at every target, looking exactly like a
// wrong token rather than a wrong read. One loader, so there is one place that
// knows the column is sealed.
//
// Dry-run is refused rather than silently skipped: `scim sync` previews and this
// does not, so honouring the flag by doing nothing would report success for a
// group that was never created.
func scimTargetForGroups(ctx context.Context, conn *pgx.Conn, slug string) (scim.Target, string, error) {
	var zero scim.Target
	root, err := rootKey()
	if err != nil {
		return zero, "", err
	}
	// LoadSCIMTargets returns only ENABLED targets, so an empty result means
	// either "no such slug" or "disabled". Distinguished here, because "no SCIM
	// target with that slug" sent to somebody who disabled it last week is an
	// hour of looking for a typo that is not there.
	targets, err := store.LoadSCIMTargets(ctx, conn, root, slug)
	if err != nil {
		return zero, "", err
	}
	if len(targets) == 0 {
		var exists bool
		_ = conn.QueryRow(ctx,
			`SELECT true FROM core.scim_targets WHERE slug = $1`, slug).Scan(&exists)
		if exists {
			return zero, "", fmt.Errorf("%s is disabled", slug)
		}
		return zero, "", fmt.Errorf("no SCIM target with slug %q", slug)
	}
	t := targets[0]
	if t.Kind != "" && t.Kind != "scim" {
		return zero, "", fmt.Errorf("%s is a %s target, not a SCIM one; group "+
			"provisioning here speaks SCIM", slug, t.Kind)
	}
	if t.DryRun {
		return zero, "", fmt.Errorf("%s is in dry-run mode, which records without sending. "+
			"A group cannot be created in a mode that sends nothing; take the target out "+
			"of dry-run first", slug)
	}
	return t, t.OrgID, nil
}

// clientSetCIBA chooses how a client receives backchannel authentication results.
//
// This is the command `/register` promises. Dynamic registration accepts only
// `poll` and tells the caller to ask an administrator for ping or push, because
// both have this issuer POST to a URL the client names -- "the IdP will call any
// public address you supply" is a capability to grant deliberately rather than by
// self-service. That refusal was already written; the command it pointed at was
// not, so the instruction could not be followed.
func clientSetCIBA(ctx context.Context, conn *pgx.Conn, clientID, mode, endpoint string) error {
	if clientID == "" {
		return fmt.Errorf("give -client-id")
	}
	switch mode {
	case "poll", "ping", "push":
	default:
		return fmt.Errorf("-delivery must be poll, ping or push, not %q", mode)
	}

	endpoint = strings.TrimSpace(endpoint)
	if mode == "poll" && endpoint != "" {
		return fmt.Errorf("poll mode has the client collect the result itself, so a " +
			"notification endpoint would never be called. Drop -notification-endpoint, " +
			"or choose ping or push")
	}
	if mode != "poll" {
		if endpoint == "" {
			return fmt.Errorf("%s mode needs -notification-endpoint. Without one this "+
				"issuer would accept a backchannel request and have nowhere to deliver "+
				"the result, which is a success nobody receives", mode)
		}
		if !strings.HasPrefix(endpoint, "https://") {
			// CIBA Core 1.0 §7.3 requires an https endpoint. Push carries the
			// tokens themselves, so plaintext here would put them on the wire.
			return fmt.Errorf("the notification endpoint must be https. In push mode it " +
				"receives the tokens themselves, and over plaintext that is the whole " +
				"credential handed to anyone on the path")
		}
	}

	var stored any
	if endpoint != "" {
		stored = endpoint
	}
	tp, err := conn.Exec(ctx, `
		UPDATE core.clients
		   SET backchannel_token_delivery_mode = $2,
		       backchannel_client_notification_endpoint = $3
		 WHERE client_id = $1`, clientID, mode, stored)
	if err != nil {
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("no client %q", clientID)
	}

	fmt.Printf("%s delivers backchannel results by %s\n", clientID, mode)
	if endpoint != "" {
		fmt.Printf("  notification endpoint: %s\n", endpoint)
	}
	if mode == "push" {
		fmt.Println("\n  Push delivers the TOKENS to that endpoint. Anyone who can receive at")
		fmt.Println("  that address receives the credentials, so it must be under the client's")
		fmt.Println("  control and nobody else's.")
	}
	return nil
}

// groupImpersonation grants or revokes the ability to act as another person.
//
// Deliberately here and not in the admin API. `internal/adminapi/groups.go`
// refuses this field on create and on patch, and a test holds it there: a
// `groups:write` token is issued for day-to-day administration, and letting one
// grant impersonation would turn every such token into a way to become anybody.
// Granting it takes database credentials, which is a different and higher bar.
func groupImpersonation(ctx context.Context, conn *pgx.Conn, orgID, group string, grant bool) error {
	if orgID == "" || group == "" {
		return fmt.Errorf("give -org and -group")
	}

	tp, err := conn.Exec(ctx, `
		UPDATE core.groups SET may_impersonate = $3
		WHERE org_id = $1::uuid AND name = $2`, orgID, group, grant)
	if err != nil {
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("no group named %q in that organisation", group)
	}

	if !grant {
		fmt.Printf("%q may no longer impersonate\n", group)
		fmt.Println("\n  Sessions already started under impersonation are not ended by this.")
		fmt.Println("  `signari user sessions -email <them>` shows them.")
		return nil
	}

	var members int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM core.group_members m
		JOIN core.groups g ON g.id = m.group_id
		WHERE g.org_id = $1::uuid AND g.name = $2`, orgID, group).Scan(&members)

	fmt.Printf("%q may now impersonate. %d member(s) hold that power.\n", group, members)
	fmt.Println("\n  Every one of them can obtain a session as any other user in the")
	fmt.Println("  organisation. Each act is written to the audit trail with both")
	fmt.Println("  identities, and the token carries `act` so a resource server can see")
	fmt.Println("  it -- but the power itself is unrestricted. Keep the group small.")
	return nil
}

// instanceSessionLimit bounds how many sessions one person may hold at once.
//
// Zero is unlimited and is the default. `deny` refuses the new sign-in; the
// alternative ends the least recently authenticated session instead, which is
// what a deployment wants when the limit exists to stop shared accounts rather
// than to stop the person working.
func instanceSessionLimit(ctx context.Context, conn *pgx.Conn, orgID string,
	max int, behaviour string) error {

	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	switch behaviour {
	case "deny", "evict_oldest":
	default:
		return fmt.Errorf("-when-exceeded must be deny or evict_oldest, not %q", behaviour)
	}
	if max < 0 {
		return fmt.Errorf("-max-sessions cannot be negative; 0 means unlimited")
	}

	tp, err := conn.Exec(ctx, `
		UPDATE core.organizations
		   SET max_concurrent_sessions = $2, session_limit_behaviour = $3
		 WHERE id = $1::uuid`, orgID, max, behaviour)
	if err != nil {
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("no organisation %s", orgID)
	}

	if max == 0 {
		fmt.Println("concurrent sessions: unlimited")
		return nil
	}
	fmt.Printf("concurrent sessions: %d per person, then %s\n", max, behaviour)
	if behaviour == "deny" {
		fmt.Println("\n  Somebody at the limit cannot sign in until a session expires or is")
		fmt.Println("  revoked. That is a support call on a phone they have lost, so consider")
		fmt.Println("  -when-exceeded evict_oldest unless the limit is a licence term.")
	} else {
		fmt.Println("\n  The oldest session ends silently. Somebody using two devices will be")
		fmt.Println("  signed out of one without being told why.")
	}
	fmt.Println("\n  Existing sessions over the limit are not ended now; the rule applies at")
	fmt.Println("  the next sign-in.")
	return nil
}

// resolveGroupIDs turns group names into ids for object-scoped admin tokens.
//
// Names in, ids stored. A name is what an operator knows and an id is what
// survives a rename, and doing the translation here means a renamed group does
// not quietly widen a token's reach.
func resolveGroupIDs(ctx context.Context, conn *pgx.Conn, orgID, names string) ([]string, error) {
	var out []string
	for _, n := range strings.Split(names, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if orgID == "" {
			return nil, fmt.Errorf("-groups needs -org: a group name is only unique " +
				"within an organisation, and a token limited to a group in an " +
				"unspecified organisation is not limited to anything")
		}
		var id string
		if err := conn.QueryRow(ctx,
			`SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
			orgID, n).Scan(&id); err != nil {
			return nil, fmt.Errorf("no group named %q in that organisation", n)
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}
