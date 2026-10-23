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
// They were found in a batch, which is what makes it a class rather than an
// oversight. `TestEveryTableTheEngineReadsCanBeWritten` and
// `TestEveryColumnTheEngineReadsCanBeWritten` in internal/docsync now fail the
// build when a table or column the engine reads for a decision has no writer
// outside a migration, so the next one cannot be added the same way. What those
// two tests still cannot close is carried in `knownUnwritable`, explicitly, with
// what stays fixed at its default as a result.
//
// A reachability guard over FUNCTIONS already existed and passed throughout,
// because each of these loaders genuinely had a call site. A function being
// called is not the same as a capability being reachable, and the difference is
// exactly one table nobody can write to.
//
// The first version of the table guard matched `core.<table>` only, and 57 of
// the 113 core tables are created unqualified — so it reported clean over half
// the schema, including the SAML attribute release it was written to catch. A
// guard that reports clean over its own subject is worse than no guard: it turns
// an open question into a settled one.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/passkeys"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/scim"
	"signari.dev/engine/internal/store"
)

// oneInOrg resolves a row the operator named by a key that is unique within an
// organisation at most: a slug, a name, an address. With -org it is that
// organisation's row; without, the key must name exactly one row in the whole
// deployment, or the command refuses and asks for -org.
//
// These commands found their row by the key alone. Two organisations each with
// a SCIM target called "slack" had both enabled by one command, and one was
// synced at random by another. Refusing the ambiguous case rather than always
// requiring -org keeps every single-organisation deployment working unchanged.
//
// table and match are this file's constants, never operator input; value and
// orgID are bound parameters.
func oneInOrg(ctx context.Context, conn *pgx.Conn, table, match, value, orgID, what string) (id, org string, err error) {
	rows, err := conn.Query(ctx, fmt.Sprintf(
		`SELECT id::text, org_id::text FROM core.%s WHERE %s AND ($2 = '' OR org_id = $2::uuid) LIMIT 2`,
		table, match), value, orgID)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		if err := rows.Scan(&id, &org); err != nil {
			return "", "", err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	switch {
	case n == 0 && orgID != "":
		return "", "", fmt.Errorf("no %s %q in that organisation", what, value)
	case n == 0:
		return "", "", fmt.Errorf("no %s %q", what, value)
	case n > 1 && orgID != "":
		return "", "", fmt.Errorf("%q names more than one %s in that organisation; "+
			"name it by something unique", value, what)
	case n > 1:
		return "", "", fmt.Errorf("%q names a %s in more than one organisation; give -org "+
			"to say which", value, what)
	}
	return id, org, nil
}

// userLocale sets the language a person's security notices are written in.
//
// core.users.locale is read by the notice path to choose a message bundle.
// Empty clears it rather than storing "", so the column means "this person has
// expressed no preference" and the deployment default applies -- a stored empty
// string would be a preference for a locale that does not exist.
func userLocale(ctx context.Context, conn *pgx.Conn, orgID, email, tag string) error {
	if email == "" {
		return fmt.Errorf("give -email")
	}
	tag = strings.TrimSpace(tag)
	userID, _, err := oneInOrg(ctx, conn, "users",
		"(lower(email) = lower($1) OR lower(username) = lower($1))", email, orgID, "user")
	if err != nil {
		return err
	}

	var stored any
	if tag != "" {
		stored = tag
	}
	tp, err := conn.Exec(ctx, `
		UPDATE core.users SET locale = $2 WHERE id = $1::uuid`, userID, stored)
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
func webauthnPolicySet(ctx context.Context, conn *pgx.Conn, orgID string, want store.WebAuthnPolicy) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	p, err := store.SetWebAuthnPolicy(ctx, tx, orgID, want)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	ids := p.AllowedAAGUIDs
	conveyance := p.Conveyance

	fmt.Printf("attestation conveyance: %s\n", conveyance)
	if p.RefuseCloned {
		fmt.Println("cloned authenticators : refused (a signature counter that did not advance)")
	} else {
		fmt.Println("cloned authenticators : RECORDED AND ADMITTED -- a copied key signs in")
	}
	if p.UserVerification == "required" {
		fmt.Println("user verification     : required -- a passkey sign-in is multi-factor")
	} else {
		fmt.Println("user verification     : preferred -- a key without a PIN or biometric signs in, single-factor")
	}
	fmt.Printf("resident key          : %s\n", p.ResidentKey)
	fmt.Printf("attachment            : %s\n", map[bool]string{true: "any", false: p.Attachment}[p.Attachment == ""])
	fmt.Printf("algorithms            : %s\n", algorithmNames(p.Algorithms))
	fmt.Printf("ceremony timeout      : %ds\n", p.TimeoutSeconds)
	if len(p.Hints) > 0 {
		fmt.Printf("hints                 : %s\n", strings.Join(p.Hints, ", "))
	}
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

// coseAlgorithms names the COSE algorithms a policy may offer.
var coseAlgorithms = []struct {
	name string
	id   int
}{{"ES256", -7}, {"ES384", -35}, {"ES512", -36}, {"RS256", -257}, {"RS384", -258},
	{"RS512", -259}, {"PS256", -37}, {"PS384", -38}, {"PS512", -39}, {"EdDSA", -8}}

// webauthnAlgorithms reads -algorithms: names or COSE numbers, in order.
// Empty is the default, all of them.
func webauthnAlgorithms(s string) ([]int, error) {
	var out []int
	for _, a := range splitList(s) {
		found := false
		for _, c := range coseAlgorithms {
			if strings.EqualFold(a, c.name) || a == strconv.Itoa(c.id) {
				out, found = append(out, c.id), true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("-algorithms: %q is not one of ES256, ES384, ES512, RS256, "+
				"RS384, RS512, PS256, PS384, PS512, EdDSA", a)
		}
	}
	return out, nil
}

func algorithmNames(ids []int) string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		name := strconv.Itoa(id)
		for _, c := range coseAlgorithms {
			if c.id == id {
				name = c.name
			}
		}
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

// webauthnPolicyShow prints every organisation's authenticator policy.
func webauthnPolicyShow(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT o.slug, p.attestation_conveyance, p.allowed_aaguids::text[], p.refuse_cloned,
		       p.user_verification, p.resident_key, p.attachment, p.algorithms, p.timeout_s
		FROM core.webauthn_policy p
		JOIN core.organizations o ON o.id = p.org_id
		ORDER BY o.slug`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("%-24s %-14s %-9s %-10s %-12s %-15s %-18s %-8s %s\n", "ORGANISATION", "ATTESTATION",
		"CLONED", "UV", "RESIDENT KEY", "ATTACHMENT", "ALGORITHMS", "TIMEOUT", "ALLOWED MODELS")
	var n int
	for rows.Next() {
		var slug, conveyance, uv, rk, attach string
		var ids []string
		var algs []int
		var refuse bool
		var timeout int
		if err := rows.Scan(&slug, &conveyance, &ids, &refuse, &uv, &rk, &attach, &algs, &timeout); err != nil {
			return err
		}
		allowed := "any"
		if len(ids) > 0 {
			allowed = strings.Join(ids, ", ")
		}
		cloned := "refused"
		if !refuse {
			cloned = "ADMITTED"
		}
		if attach == "" {
			attach = "any"
		}
		fmt.Printf("%-24s %-14s %-9s %-10s %-12s %-15s %-18s %-8s %s\n", slug, conveyance, cloned, uv, rk,
			attach, algorithmNames(algs), fmt.Sprintf("%ds", timeout), allowed)
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
func dirGroupMap(ctx context.Context, conn *pgx.Conn, givenOrg, slug, remote, local string, remove bool) error {
	if slug == "" || remote == "" || local == "" {
		return fmt.Errorf("give -slug (the directory source), -remote-group and -group")
	}

	sourceID, orgID, err := oneInOrg(ctx, conn, "directory_sources", "slug = $1", slug, givenOrg,
		"directory source")
	if err != nil {
		return err
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
		err := store.RemoveRADIUSAuthorization(ctx, conn, orgID, groupID)
		if errors.Is(err, store.ErrRADIUSNotAuthorised) {
			return fmt.Errorf("%q carries no RADIUS authorisation", group)
		}
		if err != nil {
			return err
		}
		fmt.Printf("%q no longer carries a VLAN or filter\n", group)
		fmt.Println("\n  Members already connected keep their session until it is re-authorised;")
		fmt.Println("  RADIUS attributes are decided at Access-Accept, not re-evaluated.")
		return nil
	}

	switch err := store.SetRADIUSAuthorization(ctx, conn, orgID, groupID, vlan, filterID, priority); {
	case errors.Is(err, store.ErrRADIUSNothingAuthorised):
		return fmt.Errorf("give -vlan, -filter-id or both. A row that authorises nothing " +
			"is a configuration somebody believes is doing something")
	case errors.Is(err, store.ErrVLANRange):
		return fmt.Errorf("a VLAN id is 12 bits: 1 to 4094 (RFC 3580 section 3.31). "+
			"%d is outside that, and a switch would reject or misread it", vlan)
	case err != nil:
		return err
	}

	fmt.Printf("group %q:\n", group)
	if vlan != 0 {
		fmt.Printf("  VLAN      : %d\n", vlan)
	}
	if f := strings.TrimSpace(filterID); f != "" {
		fmt.Printf("  Filter-Id : %s\n", f)
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

	switch err := store.SetProviderClaims(ctx, conn, orgID, provider.Hook(hook), list); {
	case errors.Is(err, store.ErrProtocolClaim):
		return fmt.Errorf("a hook may not be allowed to set a protocol claim " +
			"(sub, iss, aud, exp, iat, nbf, jti, nonce, azp, scope, client_id, " +
			"auth_time, acr, amr). Those are decided by the protocol, and letting " +
			"an external service overwrite one is how a token is minted for the " +
			"wrong subject")
	case errors.Is(err, store.ErrProviderNotRegistered):
		return fmt.Errorf("that organisation has no %q provider; add one with "+
			"`signari provider add`", hook)
	case err != nil:
		return err
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
func scimScope(ctx context.Context, conn *pgx.Conn, givenOrg, slug, group string) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}

	_, orgID, err := oneInOrg(ctx, conn, "scim_targets", "slug = $1", slug, givenOrg,
		"SCIM target")
	if err != nil {
		return err
	}
	if err := store.SetSCIMTargetScope(ctx, conn, orgID, slug, group); err != nil {
		if errors.Is(err, store.ErrScopeGroupUnknown) {
			return fmt.Errorf("no group named %q in that organisation", group)
		}
		return err
	}

	if strings.TrimSpace(group) == "" {
		fmt.Printf("%s is no longer scoped; every user in the organisation is provisioned\n", slug)
		fmt.Println("\n  Widening a target does NOT deprovision anybody. The next sync adds the")
		fmt.Println("  people who were previously out of scope.")
		return nil
	}

	fmt.Printf("%s now provisions only members of %q\n", slug, group)
	fmt.Println("\n  People already provisioned who are NOT in that group are handled by the")
	fmt.Println("  target's -on-deactivate setting (from `signari scim add`) on the next sync.")
	fmt.Println("  Preview it first:")
	fmt.Println("    signari scim sync -slug " + slug)
	return nil
}

// scimProvisionGroup creates a group at a target and records that we own it.
//
// The link is what makes every later reconciliation safe. A group at the target
// with no row in core.scim_group_links is somebody else's -- a target's own
// administrators may already maintain "Engineering" -- and matching by name
// would adopt it and begin removing the members they put there.
func scimProvisionGroup(ctx context.Context, conn *pgx.Conn, givenOrg, slug, group string) error {
	if slug == "" || group == "" {
		return fmt.Errorf("give -slug (the SCIM target) and -group")
	}

	t, err := scimTargetForGroups(ctx, conn, givenOrg, slug)
	if err != nil {
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
	remoteID, err := provision.ProvisionGroup(ctx, conn, t, hc, group)
	switch {
	case errors.Is(err, provision.ErrGroupUnknown):
		return fmt.Errorf("no group named %q in that organisation", group)
	case errors.Is(err, provision.ErrGroupProvisioned):
		return fmt.Errorf("%q already exists at %s as %s. Use `signari scim sync` to "+
			"reconcile its members", group, slug, remoteID)
	case err != nil:
		return err
	}

	fmt.Printf("created %q at %s as %s\n", group, slug, remoteID)
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
func scimDeprovisionGroup(ctx context.Context, conn *pgx.Conn, givenOrg, slug, group string) error {
	if slug == "" || group == "" {
		return fmt.Errorf("give -slug (the SCIM target) and -group")
	}

	t, err := scimTargetForGroups(ctx, conn, givenOrg, slug)
	if err != nil {
		return err
	}
	hc, err := scimHTTPClient()
	if err != nil {
		return err
	}
	remoteID, err := provision.DeprovisionGroup(ctx, conn, t, hc, group)
	if errors.Is(err, provision.ErrGroupNotProvisioned) {
		return fmt.Errorf("%q is not provisioned to %s", group, slug)
	}
	if err != nil {
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
func scimTargetForGroups(ctx context.Context, conn *pgx.Conn, givenOrg, slug string) (scim.Target, error) {
	var zero scim.Target
	root, err := rootKey()
	if err != nil {
		return zero, err
	}
	// The organisation the slug names, when -org is not given: a slug is
	// unique only within one.
	_, orgID, err := oneInOrg(ctx, conn, "scim_targets", "slug = $1", slug, givenOrg, "SCIM target")
	if err != nil {
		return zero, err
	}
	t, err := provision.TargetForGroups(ctx, conn, root, orgID, slug)
	switch {
	case errors.Is(err, provision.ErrTargetDisabled):
		return zero, fmt.Errorf("%s is disabled", slug)
	case errors.Is(err, provision.ErrTargetNotSCIM):
		return zero, fmt.Errorf("%s is not a SCIM target; group provisioning here speaks SCIM", slug)
	case errors.Is(err, provision.ErrTargetDryRun):
		return zero, fmt.Errorf("%s is in dry-run mode, which records without sending. "+
			"A group cannot be created in a mode that sends nothing; take the target out "+
			"of dry-run first", slug)
	}
	return t, err
}

// clientSetPKCE decides whether a client's authorization requests must carry a
// PKCE challenge.
//
// Every client requires it from creation, and before this only `client create`
// could choose otherwise. An imported confidential client whose application
// sends no challenge could therefore be fixed only with an UPDATE by hand. A
// public client cannot opt out: it holds no secret, and PKCE is the only thing
// tying the code to the application that asked for it.
func clientSetPKCE(ctx context.Context, conn *pgx.Conn, clientID string, required bool) error {
	if clientID == "" {
		return fmt.Errorf("give -client-id")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var orgID, kind string
	if err := tx.QueryRow(ctx,
		`SELECT org_id::text, client_type FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&orgID, &kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no client %q", clientID)
		}
		return err
	}
	if !required && kind == "public" {
		return fmt.Errorf("%s is a public client and must require PKCE: it holds no "+
			"secret, so the challenge is the only proof the code reached the "+
			"application that asked for it", clientID)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.clients SET require_pkce = $2, updated_at = now() WHERE client_id = $1`,
		clientID, required); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.client_updated", OrgID: orgID, ClientID: clientID,
		Detail: map[string]any{"require_pkce": required, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.config_version SET version = version + 1, bumped_at = now()
		 WHERE id = true`); err != nil {
		return fmt.Errorf("bumping the configuration version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if required {
		fmt.Printf("%s now refuses an authorization request with no PKCE challenge\n", clientID)
	} else {
		fmt.Printf("%s now accepts an authorization request with no PKCE challenge.\n"+
			"  The challenge binds the code to the application that asked for it, and the\n"+
			"  FAPI 2.0 profile requires one of every client. Keep this only for an\n"+
			"  application that cannot send one, and turn it back on when it can.\n", clientID)
	}
	return nil
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
	// The rules are store.SetClientCIBA's, which the Admin API shares (6.03).
	endpoint = strings.TrimSpace(endpoint)
	if err := store.SetClientCIBA(ctx, conn, clientID, mode, endpoint); err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			return fmt.Errorf("no client %q", clientID)
		}
		return err
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
		fmt.Println("  The Admin API's GET /admin/users/{userID}/sessions shows them.")
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
	case store.SessionLimitDeny, store.SessionLimitEvictOldest:
	default:
		return fmt.Errorf("-when-exceeded must be deny or evict_oldest, not %q", behaviour)
	}
	if max < 0 {
		return fmt.Errorf("-max-sessions cannot be negative; 0 means unlimited")
	}

	// Through the setter the Admin API uses, audited like the other settings.
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	wasMax, was, err := store.SetSessionLimit(ctx, tx, orgID, max, behaviour)
	if errors.Is(err, store.ErrOrganizationNotFound) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.session_limit_set", OrgID: orgID,
		Detail: map[string]any{"max_from": wasMax, "max_to": max, "behaviour_from": was,
			"behaviour_to": behaviour, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
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

// instancePasswordBinds decides whether the protocols that carry only a password
// -- LDAP binds, RADIUS PAP, the LDAP and RADIUS outposts -- may sign in somebody
// the sign-in flow would ask for a second factor (0128).
//
// Audited and version-bumped in the write's transaction, as the admin API does
// it: this is a security setting, and "who let the VPN accept passwords alone,
// and when" is a question the audit trail must be able to answer.
func instancePasswordBinds(ctx context.Context, conn *pgx.Conn, orgID, policy string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	switch policy {
	case store.PasswordBindsAllow, store.PasswordBindsRefuseWhenMFA:
	default:
		return fmt.Errorf("-binds must be %s or %s, not %q",
			store.PasswordBindsAllow, store.PasswordBindsRefuseWhenMFA, policy)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	previous, err := store.SetPasswordBinds(ctx, tx, orgID, policy)
	if errors.Is(err, store.ErrOrganizationNotFound) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.password_only_binds_set", OrgID: orgID,
		Detail: map[string]any{"from": previous, "to": policy, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.config_version SET version = version + 1, bumped_at = now()
		 WHERE id = true`); err != nil {
		return fmt.Errorf("bumping the configuration version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	if policy == store.PasswordBindsAllow {
		fmt.Println("password-only binds: allowed")
		fmt.Println("\n  LDAP binds, RADIUS PAP and outposts accept a correct password from anybody,")
		fmt.Println("  including people the sign-in page would ask for a second factor. A stolen")
		fmt.Println("  password is enough on those protocols. `signari doctor` will say so.")
		return nil
	}
	fmt.Println("password-only binds: refused when the sign-in flow would ask for a second factor")
	fmt.Println("\n  Somebody with a second factor enrolled (or everybody, under an unconditional")
	fmt.Println("  mfa stage) can no longer bind with a password alone. Service accounts that")
	fmt.Println("  bind to the directory need no second factor, or they will be refused too.")
	return nil
}

// userUnlock clears what wrong guesses charged to one person (4.06), as the
// Admin API's DELETE /admin/users/{id}/throttle does.
func userUnlock(ctx context.Context, conn *pgx.Conn, orgID, email string) error {
	if email == "" {
		return fmt.Errorf("give -email (and -org where the address is in more than one)")
	}
	userID, userOrg, err := oneInOrg(ctx, conn, "users",
		"(lower(email) = lower($1) OR lower(username) = lower($1))", email, orgID, "user")
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n, err := store.UnlockAccount(ctx, tx, userID)
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.user_unlocked", OrgID: userOrg, SubjectID: userID,
		Detail: map[string]any{"counts_cleared": n, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the unlock: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if n == 0 {
		fmt.Printf("%s: nothing to clear; no wrong guess is being counted against them\n", email)
		return nil
	}
	fmt.Printf("%s: unlocked (%d count(s) cleared); the next wrong password is charged as before\n", email, n)
	return nil
}

// userApprove activates a self-sign-up waiting for approval (0186), and the
// engine tells the person they can sign in.
func userApprove(ctx context.Context, conn *pgx.Conn, orgID, email string) error {
	if email == "" {
		return fmt.Errorf("give -email (and -org where the address is in more than one)")
	}
	userID, userOrg, err := oneInOrg(ctx, conn, "users",
		"(lower(email) = lower($1) OR lower(username) = lower($1))", email, orgID, "user")
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	approved, err := store.ApproveUser(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !approved {
		return fmt.Errorf("%s is not waiting for approval; only a pending self-sign-up can be approved", email)
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.user_approved", OrgID: userOrg, SubjectID: userID,
		Detail: map[string]any{"via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the approval: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("%s: approved; they can sign in now, and the engine's outbox tells them so\n", email)
	return nil
}

// instanceLoginThrottle sets an organisation's sign-in backoff (0169).
func instanceLoginThrottle(ctx context.Context, conn *pgx.Conn, orgID string, free int, max time.Duration) error {
	if orgID == "" || (free == 0 && max == 0) {
		return fmt.Errorf("give -org and -free-attempts and/or -max-delay")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetLoginThrottle(ctx, tx, orgID, free, max); err != nil {
		if errors.Is(err, store.ErrOrganizationNotFound) {
			return fmt.Errorf("no organisation %s", orgID)
		}
		return err
	}
	var gotFree, gotMax int
	if err := tx.QueryRow(ctx, `SELECT login_free_attempts, login_max_delay_s FROM core.organizations
		WHERE id = $1::uuid`, orgID).Scan(&gotFree, &gotMax); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.login_throttle_set", OrgID: orgID,
		Detail: map[string]any{"free_attempts": gotFree, "max_delay_s": gotMax, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("sign-in delay: %d wrong password(s) free, then 1s doubling to at most %s\n",
		gotFree, time.Duration(gotMax)*time.Second)
	fmt.Println("\n  A delay, not a lockout: a lockout is a button that disables any account")
	fmt.Println("  somebody can name. Each failure counts for an hour.")
	return nil
}

// userRemoveFactor removes one of a person's sign-in methods, as the Admin
// API's DELETE /admin/users/{id}/factors/{kind} does (store.RemoveFactor): the
// method, every session they hold, and a notice to them, which serve's outbox
// worker delivers. For somebody whose phone or key is lost; their next sign-in
// enrols a new one where a flow requires it.
func userRemoveFactor(ctx context.Context, conn *pgx.Conn, orgID, email, kind, factorID string) error {
	if email == "" || kind == "" {
		return fmt.Errorf("give -email and -factor (totp, email_otp, sms_otp, duo, webauthn or recovery)")
	}
	userID, userOrg, err := oneInOrg(ctx, conn, "users",
		"(lower(email) = lower($1) OR lower(username) = lower($1))", email, orgID, "user")
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	got, err := store.RemoveFactor(ctx, tx, userID, kind, factorID)
	switch {
	case errors.Is(err, store.ErrFactorIDRequired):
		return fmt.Errorf("%w: give -factor-id", err)
	case errors.Is(err, store.ErrFactorNotFound):
		return fmt.Errorf("%s has no %s to remove", email, kind)
	case err != nil:
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.factor_removed", OrgID: userOrg, SubjectID: userID,
		Detail: map[string]any{"factor": kind, "removed": got.Removed, "sessions_ended": got.SessionsEnded,
			"notices_queued": got.NoticesQueued, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the removal: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("%s: %s removed (%d); %d session(s) ended. They will be told by email, and by text "+
		"where they have a verified number, once the server's outbox delivers it.\n",
		email, kind, got.Removed, got.SessionsEnded)
	return nil
}

// userPasskeyLink emails a person a single-use link to register a passkey with
// no session, as the Admin API's POST /admin/users/{id}/passkey-link does
// (migration 0176). The token is minted by serve's outbox worker as it sends
// the email, so it is never printed here: whoever runs this cannot use it.
func userPasskeyLink(ctx context.Context, conn *pgx.Conn, orgID, email string, ttl time.Duration) error {
	if email == "" {
		return fmt.Errorf("give -email; -link-expires is how long the link works, 1m to 168h (default 24h)")
	}
	userID, userOrg, err := oneInOrg(ctx, conn, "users",
		"(lower(email) = lower($1) OR lower(username) = lower($1))", email, orgID, "user")
	if err != nil {
		return err
	}
	var status, address string
	if err := conn.QueryRow(ctx, `SELECT status, COALESCE(email, '') FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&status, &address); err != nil {
		return err
	}
	switch {
	case status != "active":
		return fmt.Errorf("%s is %s, and a link for an account that cannot sign in would do nothing", email, status)
	case address == "":
		return fmt.Errorf("%s has no email address to send the link to", email)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	link, err := store.IssuePasskeyLink(ctx, tx, userID, userOrg, ttl)
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.passkey_link_issued", OrgID: userOrg, SubjectID: userID,
		Detail: map[string]any{"link_id": link.ID, "expires_at": link.ExpiresAt.UTC().Format(time.RFC3339),
			"via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the link: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("%s: a link to register one passkey will be emailed to %s once the server's outbox "+
		"delivers it. It works until %s; any earlier link they had no longer works.\n",
		email, address, link.ExpiresAt.UTC().Format("15:04 MST on 2 January 2006"))
	return nil
}

// instanceTOTPPolicy sets what an organisation enrols new authenticator apps
// with (migration 0171). Each credential keeps what it was enrolled with, so
// this changes nothing for anybody already enrolled.
func instanceTOTPPolicy(ctx context.Context, conn *pgx.Conn, orgID string, p mfa.Params) error {
	if orgID == "" {
		return fmt.Errorf("give -org; -totp-algorithm, -totp-digits and -totp-period default to SHA1, 6 and 30s")
	}
	if err := p.Check(); err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetTOTPPolicy(ctx, tx, orgID, store.TOTPPolicy{Algorithm: string(p.Algorithm),
		Digits: p.Digits, Period: p.Period}); err != nil {
		if errors.Is(err, store.ErrOrganizationNotFound) {
			return fmt.Errorf("no organisation %s", orgID)
		}
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.totp_policy_set", OrgID: orgID,
		Detail: map[string]any{"algorithm": string(p.Algorithm), "digits": p.Digits,
			"period_s": int(p.Period / time.Second), "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("new authenticator apps: %s, %d digits, %ds\n", p.Algorithm, p.Digits, int(p.Period/time.Second))
	fmt.Println("\n  Applies to apps enrolled from now on; each one already enrolled keeps what")
	fmt.Println("  it was enrolled with. Not every app computes SHA256 or SHA512, or shows 8")
	fmt.Println("  digits or 60s codes: one that does not shows codes that never match.")
	return nil
}

// instanceSMSNumbers sets whether an organisation keeps SMS numbers or only a
// keyed hash of each (migration 0173).
func instanceSMSNumbers(ctx context.Context, conn *pgx.Conn, orgID, mode string) error {
	if orgID == "" || (mode != "stored" && mode != "hashed") {
		return fmt.Errorf("give -org and -sms-numbers stored or hashed")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetSMSNumbers(ctx, tx, orgID, mode == "hashed"); err != nil {
		if errors.Is(err, store.ErrOrganizationNotFound) {
			return fmt.Errorf("no organisation %s", orgID)
		}
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.sms_numbers_set", OrgID: orgID, Detail: map[string]any{"sms_numbers": mode, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if mode == "hashed" {
		fmt.Println("SMS numbers: hashed. A number enrolled from now on is kept only as a keyed hash;")
		fmt.Println("one already stored is replaced by its hash at the person's next sign-in. The")
		fmt.Println("person then types their number to be sent a code, and is texted no notices.")
		return nil
	}
	fmt.Println("SMS numbers: stored, for numbers enrolled from now on. One kept only as a hash")
	fmt.Println("cannot be read back: it keeps working when typed, until the person enrols again.")
	return nil
}

// hotpSyncWindow is how many presses of a counter-based token assign-otp
// searches for its codes: a token fresh from its vendor, or pressed a few
// times in testing. Two consecutive codes are asked for, so a wrong seed
// matching by chance is out of reach even across this many.
const hotpSyncWindow = 1000

// decodeSeed reads a token seed: base32, or hex after "hex:".
func decodeSeed(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "hex:"); ok {
		raw, err := hex.DecodeString(strings.NewReplacer(" ", "", ":", "").Replace(strings.TrimSpace(rest)))
		if err != nil {
			return nil, fmt.Errorf("the seed is not hex: %w", err)
		}
		if len(raw) < 10 {
			return nil, fmt.Errorf("the seed is %d bytes, too short to be safe", len(raw))
		}
		return raw, nil
	}
	return mfa.DecodeSecret(s)
}

// userAssignOTP makes a hardware OATH token a person's authenticator (4.12),
// from the seed its vendor shipped. The codes it shows now prove the seed is
// the token's: a mistyped or wrong seed would otherwise be stored, and the
// person refused at their next sign-in by a factor nobody can use. For a
// counter-based token they also say where its counter stands.
func userAssignOTP(ctx context.Context, conn *pgx.Conn, orgID, email, seedFile string, hotp bool,
	p mfa.Params, code, next string) error {

	if email == "" || seedFile == "" || code == "" || (hotp && next == "") {
		return fmt.Errorf("give -email, -seed-file and -code (and -next-code with -hotp)")
	}
	if err := p.Check(); err != nil {
		return err
	}
	raw, err := os.ReadFile(seedFile) // #nosec G304 -- the operator names the file
	if err != nil {
		return err
	}
	seed, err := decodeSeed(string(raw))
	if err != nil {
		return err
	}
	userID, userOrg, err := oneInOrg(ctx, conn, "users",
		"(lower(email) = lower($1) OR lower(username) = lower($1))", email, orgID, "user")
	if err != nil {
		return err
	}
	kind, counter := "totp", int64(0)
	if hotp {
		kind = "hotp"
		// From before the first press, so counter 0 is a candidate.
		first, err := p.VerifyHOTP(seed, code, -1, hotpSyncWindow)
		if err == nil {
			counter, err = p.VerifyHOTP(seed, next, first, 1)
		}
		if err != nil {
			return fmt.Errorf("-code then -next-code are not two consecutive codes of this seed among its "+
				"first %d presses (%v); check the seed, -totp-algorithm and -totp-digits", hotpSyncWindow, err)
		}
	} else if counter, err = p.Verify(seed, code, time.Now(), mfa.DefaultSkew, 0); err != nil {
		return fmt.Errorf("-code is not this seed's code now (%v); check the seed, -totp-algorithm, "+
			"-totp-digits, -totp-period and this host's clock", err)
	}
	root, err := rootKey()
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	replaced, err := store.AssignOTPToken(ctx, tx, userID, userOrg, seed, kind, string(p.Algorithm),
		p.Digits, p.Period, counter, root)
	if err != nil {
		return err
	}
	// The holder hears of it on their own channels, as of any factor change.
	if err := store.EnqueueAccountNotice(ctx, tx, store.AccountNotice{UserID: userID,
		Notice: store.NoticeFactorAssigned, Factor: "totp"}); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.otp_token_assigned", OrgID: userOrg, SubjectID: userID,
		Detail: map[string]any{"kind": kind, "algorithm": string(p.Algorithm), "digits": p.Digits,
			"period_s": int(p.Period / time.Second), "replaced": replaced, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the assignment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("%s: a %s token is now their authenticator", email, kind)
	if replaced {
		fmt.Print(", replacing the one they had")
	}
	fmt.Println()
	fmt.Println("\n  Delete the seed file: the seed is sealed in the database now, and a copy")
	fmt.Println("  anywhere else is a second token. The codes given here are spent.")
	return nil
}

// instanceRememberDevice sets how long a remembered device skips the second
// factor (migration 0168); 0 turns the choice off and stops every remembered
// device counting.
func instanceRememberDevice(ctx context.Context, conn *pgx.Conn, orgID string, days int) error {
	if orgID == "" || days < 0 {
		return fmt.Errorf("give -org and -days, 0 to %d", store.MaxRememberDeviceDays)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	previous, err := store.SetRememberDeviceDays(ctx, tx, orgID, days)
	if errors.Is(err, store.ErrOrganizationNotFound) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.remember_device_set", OrgID: orgID,
		Detail: map[string]any{"from_days": previous, "to_days": days, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if days == 0 {
		fmt.Println("remembered devices: off")
		fmt.Println("\n  The code page offers no box, and every device already remembered is asked")
		fmt.Println("  for the second factor again at its next sign-in.")
		return nil
	}
	fmt.Printf("remembered devices: %d days (was %d)\n", days, previous)
	fmt.Println("\n  After a second factor, a person may tick a box so that sign-ins with the")
	fmt.Println("  password on that browser skip the flow's mfa stage, unless the application")
	fmt.Println("  requires multi-factor. Such a session is single-factor. They are listed, and")
	fmt.Println("  forgotten, at /account/devices; signing out everywhere forgets them all.")
	return nil
}

// instanceNewDeviceNotice turns on or off the mail a sign-in from a new device
// sends its person (0187).
func instanceNewDeviceNotice(ctx context.Context, conn *pgx.Conn, orgID, notice string) error {
	if orgID == "" || (notice != "on" && notice != "off") {
		return fmt.Errorf("give -org and -notice on or off")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	previous, err := store.SetNewDeviceNotice(ctx, tx, orgID, notice == "on")
	if errors.Is(err, store.ErrOrganizationNotFound) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.new_device_notice_set", OrgID: orgID,
		Detail: map[string]any{"from": previous, "to": notice == "on", "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if notice == "on" {
		fmt.Println("new-device notices: on\n\n  A sign-in from a browser and system none of the person's sessions of the")
		fmt.Println("  last 90 days came from is mailed to them, with how to act if it was not them.")
		return nil
	}
	fmt.Println("new-device notices: off")
	return nil
}

// instanceOrgStatus suspends or reactivates an organisation (6.09), as PATCH
// /admin/organizations/{orgID} does: refused at every entry point from the
// next request, nothing ended.
func instanceOrgStatus(ctx context.Context, conn *pgx.Conn, orgID, status string) error {
	if orgID == "" || (status != "active" && status != "suspended") {
		return fmt.Errorf("give -org and -status active or suspended")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var was string
	if err := tx.QueryRow(ctx, `SELECT status FROM core.organizations WHERE id = $1::uuid FOR UPDATE`,
		orgID).Scan(&was); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no organisation %s", orgID)
		}
		return err
	}
	if was == status {
		fmt.Println("organisation status: " + status + " (unchanged)")
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET status = $2, updated_at = now() WHERE id = $1::uuid`,
		orgID, status); err != nil {
		return err
	}
	typ := "admin.organization_suspended"
	if status == "active" {
		typ = "admin.organization_reactivated"
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: typ, OrgID: orgID, Detail: map[string]any{"was": was, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if status == "suspended" {
		fmt.Println("organisation status: suspended\n\n  Refused from the next request: sign-in, its sessions, its clients at every")
		fmt.Println("  endpoint, its tokens at userinfo and introspection, LDAP and RADIUS, SCIM, its")
		fmt.Println("  outposts, sign-up, recovery and its own admin tokens. Nothing is ended; a")
		fmt.Println("  session or grant with time left resumes when it is reactivated.")
		return nil
	}
	fmt.Println("organisation status: active")
	return nil
}

// instanceReauthWindow sets how recently a session must have been signed in to
// change the account from /account (migration 0167).
func instanceReauthWindow(ctx context.Context, conn *pgx.Conn, orgID string, window time.Duration) error {
	if orgID == "" || window == 0 {
		return fmt.Errorf("give -org and -window, e.g. -window 10m")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	previous, err := store.SetReauthWindow(ctx, tx, orgID, window)
	if errors.Is(err, store.ErrOrganizationNotFound) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.reauth_window_set", OrgID: orgID,
		Detail: map[string]any{"from_s": int(previous.Seconds()), "to_s": int(window.Seconds()), "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("re-authentication window: %s (was %s)\n", window, previous)
	fmt.Println("\n  Changing the password, the sign-in methods, the sessions or the connected")
	fmt.Println("  applications from /account needs a sign-in this recent; an older session")
	fmt.Println("  is sent to sign in again and brought back to the page.")
	return nil
}

// instanceSessionLifetime sets how long an organisation's sessions last, how
// long unused (5.09), and how long a grant of offline_access lasts (5.10). A
// flag left out keeps what is there.
func instanceSessionLifetime(ctx context.Context, conn *pgx.Conn, orgID string, lifetime, idle,
	offline time.Duration, persistent string) error {
	if orgID == "" || (lifetime == 0 && idle < 0 && offline < 0 && persistent == "") {
		return fmt.Errorf("give -org and any of -lifetime, -idle, -offline and -persistent, " +
			"e.g. -lifetime 12h -idle 30m")
	}
	if persistent != "" && persistent != "on" && persistent != "off" {
		return fmt.Errorf("-persistent is on or off, not %q", persistent)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := store.SessionLifetimesOf(ctx, tx, orgID)
	if errors.Is(err, store.ErrOrganizationNotFound) {
		return fmt.Errorf("no organisation %s", orgID)
	}
	if err != nil {
		return err
	}
	if lifetime == 0 {
		lifetime = current.Lifetime
	}
	if idle < 0 {
		idle = current.Idle
	}
	if offline < 0 {
		offline = current.Offline
	}
	previous, sooner, ended, err := store.SetSessionLifetimes(ctx, tx, orgID, lifetime, idle)
	if err != nil {
		return err
	}
	_, grantsSooner, err := store.SetOfflineLifetime(ctx, tx, orgID, offline)
	if err != nil {
		return err
	}
	stay := current.Persistent
	if persistent != "" {
		stay = persistent == "on"
	}
	if _, err := store.SetPersistentSessions(ctx, tx, orgID, stay); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "org.session_lifetime_set", OrgID: orgID,
		Detail: map[string]any{
			"lifetime_from_s": int(previous.Lifetime.Seconds()), "lifetime_to_s": int(lifetime.Seconds()),
			"idle_from_s": int(previous.Idle.Seconds()), "idle_to_s": int(idle.Seconds()),
			"offline_from_s": int(previous.Offline.Seconds()), "offline_to_s": int(offline.Seconds()),
			"persistent_from": previous.Persistent, "persistent_to": stay,
			"sessions_sooner": sooner, "sessions_ended": ended, "offline_grants_sooner": grantsSooner,
			"via": "cli",
		},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("sessions: %s (was %s)\n", sessionLimits{lifetime, idle}, sessionLimits{previous.Lifetime, previous.Idle})
	fmt.Printf("offline access: %s (was %s)\n", offlineLimit(offline), offlineLimit(previous.Offline))
	fmt.Printf("stay signed in on this device: %s (was %s)\n", onOff(stay), onOff(previous.Persistent))
	if sooner > 0 {
		fmt.Printf("\n  %d live session(s) now end sooner, %d of them already: those are refused from\n"+
			"  now on, and the janitor's next sweep ends them and tells their applications.\n", sooner, ended)
	}
	if grantsSooner > 0 {
		fmt.Printf("\n  %d live offline grant(s) now end sooner.\n", grantsSooner)
	}
	fmt.Println("\n  A session already signed in keeps the lifetime it was signed in with as its")
	fmt.Println("  ceiling; a shorter one, or an idle limit, applies to it at once.")
	return nil
}

func onOff(b bool) string {
	if b {
		return "offered"
	}
	return "not offered"
}

// offlineLimit prints an offline lifetime.
func offlineLimit(d time.Duration) string {
	if d == 0 {
		return "ends with the session it was given in"
	}
	return d.String() + " from when it is given, whether or not the person stays signed in"
}

// sessionLimits prints a lifetime and an idle limit.
type sessionLimits struct{ Lifetime, Idle time.Duration }

func (v sessionLimits) String() string {
	if v.Idle == 0 {
		return v.Lifetime.String() + " from sign-in, no idle limit"
	}
	return v.Lifetime.String() + " from sign-in, " + v.Idle.String() + " unused"
}

// The forward-auth hosts: which applications behind a reverse proxy this
// deployment protects.
//
// Read on every sign-in through /proxy/start -- the redirect back to the
// application is refused unless the host is registered -- and written by
// nothing until these commands. So every deployment of forward auth stopped at
// the sign-in page: the person authenticated and was told the application they
// came from was "not a registered protected host", with no command able to
// register it.

// normaliseProxyHost is store.NormaliseProxyHost, naming the flag.
func normaliseProxyHost(raw string) (string, error) {
	host, err := store.NormaliseProxyHost(raw)
	if err != nil {
		return "", fmt.Errorf("-host: %w", err)
	}
	return host, nil
}

// proxyHostWrite runs one change to a protected host with its audit record and
// configuration version bump, as every other write path does.
func proxyHostWrite(ctx context.Context, conn *pgx.Conn, orgID, host, event string,
	change func(tx pgx.Tx) (int64, error)) error {

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n, err := change(tx)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no protected host %q in organisation %s", host, orgID)
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: event, OrgID: orgID, Detail: map[string]any{"host": host, "via": "cli"},
	}); err != nil {
		return fmt.Errorf("auditing the change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.config_version SET version = version + 1, bumped_at = now()
		 WHERE id = true`); err != nil {
		return fmt.Errorf("bumping the configuration version: %w", err)
	}
	return tx.Commit(ctx)
}

func proxyAddHost(ctx context.Context, conn *pgx.Conn, orgID, raw string) error {
	if orgID == "" {
		return fmt.Errorf("give -org, the organisation whose people may use this application")
	}
	host, err := normaliseProxyHost(raw)
	if err != nil {
		return err
	}
	err = proxyHostWrite(ctx, conn, orgID, host, "proxy.host_added", func(tx pgx.Tx) (int64, error) {
		tag, err := tx.Exec(ctx,
			`INSERT INTO core.proxy_hosts (org_id, host) VALUES ($1::uuid, $2)`, orgID, host)
		if err != nil && strings.Contains(err.Error(), "proxy_hosts_host_key") {
			return 0, fmt.Errorf("%s is already a protected host, in this or another "+
				"organisation; a host is unique across the deployment, because verify "+
				"admits whoever's organisation registered it", host)
		}
		if err != nil && strings.Contains(err.Error(), "duplicate key") {
			return 0, fmt.Errorf("%s is already a protected host in that organisation", host)
		}
		return tag.RowsAffected(), err
	})
	if err != nil {
		return err
	}
	fmt.Printf("protected host %s registered\n", host)
	if domain := os.Getenv("SIGNARI_PROXY_COOKIE_DOMAIN"); domain == "" {
		fmt.Println("\n  SIGNARI_PROXY_COOKIE_DOMAIN is not set in this environment. The serving")
		fmt.Println("  process needs it, set to the domain both this issuer and the host sit")
		fmt.Println("  under, or the browser never sends the proxy cookie back to the host.")
	} else if d := strings.TrimPrefix(strings.ToLower(domain), "."); hostOnly(host) != d &&
		!strings.HasSuffix(hostOnly(host), "."+d) {
		fmt.Printf("\n  %s is not under SIGNARI_PROXY_COOKIE_DOMAIN (%s), so the proxy cookie\n", host, domain)
		fmt.Println("  will never reach it and sign-in will loop. Move one or the other.")
	}
	return nil
}

// hostOnly drops a port from host[:port].
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func proxyListHosts(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `
		SELECT h.host, h.enabled, o.slug
		  FROM core.proxy_hosts h
		  JOIN core.organizations o ON o.id = h.org_id
		 ORDER BY o.slug, h.host`)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	fmt.Printf("\n  %-40s %-10s %s\n", "HOST", "STATE", "ORG")
	for rows.Next() {
		var host, org string
		var enabled bool
		if err := rows.Scan(&host, &enabled, &org); err != nil {
			return err
		}
		n++
		state := "enabled"
		if !enabled {
			state = "disabled"
		}
		fmt.Printf("  %-40s %-10s %s\n", host, state, org)
	}
	if n == 0 {
		fmt.Println("\n  No protected hosts. Forward auth sends nobody back to an application")
		fmt.Println("  until its host is added with `signari proxy add-host`.")
	}
	return rows.Err()
}

func proxySetHostEnabled(ctx context.Context, conn *pgx.Conn, orgID, raw string, enabled bool) error {
	host, err := normaliseProxyHost(raw)
	if err != nil {
		return err
	}
	event := "proxy.host_disabled"
	if enabled {
		event = "proxy.host_enabled"
	}
	if err := proxyHostWrite(ctx, conn, orgID, host, event, func(tx pgx.Tx) (int64, error) {
		tag, err := tx.Exec(ctx, `
			UPDATE core.proxy_hosts SET enabled = $3 WHERE org_id = $1::uuid AND host = $2`,
			orgID, host, enabled)
		return tag.RowsAffected(), err
	}); err != nil {
		return err
	}
	fmt.Printf("protected host %s %s\n", host, map[bool]string{true: "enabled", false: "disabled"}[enabled])
	return nil
}

func proxyRemoveHost(ctx context.Context, conn *pgx.Conn, orgID, raw string) error {
	host, err := normaliseProxyHost(raw)
	if err != nil {
		return err
	}
	if err := proxyHostWrite(ctx, conn, orgID, host, "proxy.host_removed", func(tx pgx.Tx) (int64, error) {
		tag, err := tx.Exec(ctx,
			`DELETE FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, orgID, host)
		return tag.RowsAffected(), err
	}); err != nil {
		return err
	}
	fmt.Printf("protected host %s removed\n", host)
	return nil
}

// samlAttributeRelease declares which local attribute a SAML attribute carries.
//
// This is M34, and the column it writes has a comment recording that it was dead
// for months: `core.saml_providers.attributes` was read by nothing, so an
// operator could configure a release, see the column hold exactly what they had
// asked for, and receive assertions carrying none of it. The reader was then
// written -- and still nothing could put a value there, which is the same
// failure standing on its other foot.
//
// A disclosure control that silently releases nothing looks like success. One
// that silently releases everything looks like success too. Both are why this is
// an explicit map rather than a wildcard.
func samlAttributeRelease(ctx context.Context, conn *pgx.Conn, entityID, samlName,
	attribute string, remove bool) error {

	if entityID == "" || samlName == "" {
		return fmt.Errorf("give -entity-id (the service provider) and -claim (the SAML " +
			"attribute name it expects, e.g. http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress)")
	}

	var providerID, orgID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, org_id::text FROM core.saml_providers WHERE entity_id = $1`,
		entityID).Scan(&providerID, &orgID); err != nil {
		return fmt.Errorf("no SAML service provider with entity id %q", entityID)
	}

	if remove {
		tp, err := conn.Exec(ctx,
			`UPDATE core.saml_providers SET attributes = attributes - $2 WHERE id = $1::uuid`,
			providerID, samlName)
		if err != nil {
			return err
		}
		if tp.RowsAffected() == 0 {
			return fmt.Errorf("no such provider")
		}
		fmt.Printf("%s no longer releases %q\n", entityID, samlName)
		return nil
	}

	if attribute == "" {
		return fmt.Errorf("give -attribute, the local user attribute whose value is released")
	}
	// The local attribute must exist. Naming one that does not would store a
	// release that resolves to nothing on every assertion -- the exact silence
	// this command exists to end.
	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT true FROM core.user_attribute_schema WHERE org_id = $1::uuid AND name = $2`,
		orgID, attribute).Scan(&exists); err != nil {
		return fmt.Errorf("that organisation has no attribute named %q; declare it "+
			"before releasing it", attribute)
	}

	if _, err := conn.Exec(ctx, `
		UPDATE core.saml_providers
		   SET attributes = attributes || jsonb_build_object($2::text, $3::text)
		 WHERE id = $1::uuid`, providerID, samlName, attribute); err != nil {
		return err
	}

	fmt.Printf("%s releases %q from attribute %q\n", entityID, samlName, attribute)
	fmt.Println("\n  Released in every assertion to this provider, for every user who has a")
	fmt.Println("  value. A user with none simply carries no such attribute -- an empty one")
	fmt.Println("  would assert that the value IS empty, which is a different claim.")
	return nil
}

// samlSigning chooses what is signed and how long an assertion lives.
//
// The schema refuses signing neither: an unsigned assertion inside an unsigned
// response is a document anyone can write. There is no configuration in which
// that is what somebody meant.
//
// A nil flag is one not given and leaves its setting alone. Both used to be
// written every time, so changing only the lifetime turned Response signing off
// again, and a provider that requires it refused every sign-in after.
//
// The signature algorithm is refused when no active key of its kind exists,
// because every sign-in to that provider would then fail at signing.
func samlSigning(ctx context.Context, conn *pgx.Conn, entityID string,
	assertions, responses *bool, lifetime int, signatureAlg string) error {

	if entityID == "" {
		return fmt.Errorf("give -entity-id")
	}
	keyAlg := map[string]string{
		saml.SignatureAlgRSASHA256: "RS256", saml.SignatureAlgECDSASHA256: "ES256"}[signatureAlg]
	if signatureAlg != "" && keyAlg == "" {
		return fmt.Errorf("-signature-alg is rsa-sha256 or ecdsa-sha256, not %q", signatureAlg)
	}
	var signA, signR bool
	if err := conn.QueryRow(ctx, `
		SELECT sign_assertions, sign_responses FROM core.saml_providers
		WHERE entity_id = $1`, entityID).Scan(&signA, &signR); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no SAML service provider with entity id %q", entityID)
		}
		return err
	}
	var algArg any
	if keyAlg != "" {
		// In the provider's own instance: that is the key set its sign-ins use.
		var active bool
		if err := conn.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM core.signing_keys k
			                 JOIN core.organizations o ON o.instance_id = k.instance_id
			                 JOIN core.saml_providers p ON p.org_id = o.id
			               WHERE p.entity_id = $2 AND k.algorithm = $1
			                 AND k.state = 'active' AND k.purpose = 'oidc')`,
			keyAlg, entityID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("-signature-alg %s signs with the active %s key and there is "+
				"none; every sign-in to %s would fail. Add one first: `signari keys rotate -alg %s`",
				signatureAlg, keyAlg, entityID, keyAlg)
		}
		algArg = signatureAlg
	}
	if assertions != nil {
		signA = *assertions
	}
	if responses != nil {
		signR = *responses
	}
	if !signA && !signR {
		return fmt.Errorf("-sign-assertions and -sign-responses cannot both be off: an " +
			"unsigned assertion inside an unsigned response is a document anyone can " +
			"write, and the service provider has nothing to check")
	}

	// 0 means "leave it alone", so a caller changing only the signing flags does
	// not silently reset a lifetime somebody chose.
	var lifeArg any
	if lifetime != 0 {
		if lifetime < 30 || lifetime > 3600 {
			return fmt.Errorf("-assertion-lifetime is 30 to 3600 seconds; %d is outside "+
				"that. Short because an assertion is a bearer credential, and long enough "+
				"to survive clock skew", lifetime)
		}
		lifeArg = lifetime
	}

	var alg string
	if err := conn.QueryRow(ctx, `
		UPDATE core.saml_providers
		   SET sign_assertions = $2, sign_responses = $3,
		       lifetime_seconds = COALESCE($4::int, lifetime_seconds),
		       signature_alg = COALESCE($5::text, signature_alg)
		 WHERE entity_id = $1
		 RETURNING signature_alg`, entityID, signA, signR, lifeArg, algArg).Scan(&alg); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no SAML service provider with entity id %q", entityID)
		}
		return err
	}

	fmt.Printf("%s:\n  sign assertions : %t\n  sign responses  : %t\n  signature       : %s\n",
		entityID, signA, signR, alg)
	if lifeArg != nil {
		fmt.Printf("  lifetime        : %ds\n", lifetime)
	}
	if algArg != nil {
		fmt.Printf("\n  The provider checks signatures against the certificates in its copy of\n"+
			"  the metadata, which are now the %s ones. Give it /saml/metadata?sp=%s\n"+
			"  before its next sign-in, or every one of them is refused.\n",
			keyAlg, url.QueryEscape(entityID))
	}
	return nil
}

// samlGroupRelease says which groups a service provider is told about.
//
// An allow-list, matching `client group release` for OIDC clients and for the
// same reason: group membership is authorization data. A provider that receives
// every group learns the shape of the organisation, and one that receives a
// group it was never meant to see can act on it.
func samlGroupRelease(ctx context.Context, conn *pgx.Conn, entityID, attrName,
	only string, remove bool) error {

	if entityID == "" {
		return fmt.Errorf("give -entity-id")
	}
	var providerID, orgID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, org_id::text FROM core.saml_providers WHERE entity_id = $1`,
		entityID).Scan(&providerID, &orgID); err != nil {
		return fmt.Errorf("no SAML service provider with entity id %q", entityID)
	}

	if remove {
		tp, err := conn.Exec(ctx,
			`DELETE FROM core.saml_group_release WHERE provider_id = $1::uuid`, providerID)
		if err != nil {
			return err
		}
		if tp.RowsAffected() == 0 {
			return fmt.Errorf("%s releases no groups already", entityID)
		}
		fmt.Printf("%s no longer receives group membership\n", entityID)
		return nil
	}

	names := []string{}
	for _, g := range strings.Split(only, ",") {
		if g = strings.TrimSpace(g); g != "" {
			names = append(names, g)
		}
	}
	// Every named group must exist. A typo would silently release nothing, and
	// an allow-list that quietly matches no group is indistinguishable from one
	// that is working.
	for _, n := range names {
		var ok bool
		if err := conn.QueryRow(ctx,
			`SELECT true FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
			orgID, n).Scan(&ok); err != nil {
			return fmt.Errorf("no group named %q in that organisation", n)
		}
	}

	name := strings.TrimSpace(attrName)
	if name == "" {
		name = "groups"
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO core.saml_group_release (provider_id, org_id, attribute_name, only_groups)
		VALUES ($1::uuid, $2::uuid, $3, $4)
		ON CONFLICT (provider_id) DO UPDATE
		   SET attribute_name = EXCLUDED.attribute_name,
		       only_groups    = EXCLUDED.only_groups`,
		providerID, orgID, name, names); err != nil {
		return err
	}

	fmt.Printf("%s receives group membership as %q\n", entityID, name)
	if len(names) == 0 {
		fmt.Println("\n  -only was empty, so EVERY group this user belongs to is released.")
		fmt.Println("  Name the groups explicitly unless the provider genuinely needs all of them.")
	} else {
		fmt.Printf("  releasing only: %s\n", strings.Join(names, ", "))
	}
	return nil
}

// idpVerifiedEmail decides whether to believe a provider's email_verified claim.
//
// Believing it is trusting a third party's word that somebody controls an
// address, and that word is what account linking is decided on. A provider that
// lets anybody set an unverified address and reports it as verified turns this
// into account takeover by registration.
func idpVerifiedEmail(ctx context.Context, conn *pgx.Conn, slug string, trust bool) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	tp, err := conn.Exec(ctx,
		`UPDATE core.identity_providers SET require_verified_email = $2 WHERE slug = $1`,
		slug, !trust)
	if err != nil {
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("no identity provider with slug %q", slug)
	}

	if trust {
		fmt.Printf("%s: this engine believes the provider's email_verified claim\n", slug)
		fmt.Println("\n  Accounts are linked by address on that basis. Only do this for a")
		fmt.Println("  provider that verifies addresses itself and will not report an")
		fmt.Println("  unverified one as verified.")
		return nil
	}
	fmt.Printf("%s: an address from this provider is verified here, not taken on trust\n", slug)
	return nil
}

// idpTrustMFA says which upstream amr and acr values count as multi-factor for
// a provider (0152). Both lists are written as given; empty trusts nothing.
func idpTrustMFA(ctx context.Context, conn *pgx.Conn, slug, amr, acr string) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	amrs, acrs := splitList(amr), splitList(acr)
	var kind string
	if err := conn.QueryRow(ctx, `SELECT kind FROM core.identity_providers WHERE slug = $1`,
		slug).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no identity provider with slug %q", slug)
		}
		return err
	}
	// Only a verified ID token is read for these claims. GitHub sends none and a
	// SAML upstream sends an assertion, so a list set on either would be a
	// setting nothing enforces, which an operator would believe had worked.
	if (kind == "github" || kind == "saml") && len(amrs)+len(acrs) > 0 {
		return fmt.Errorf("%s is a %s provider, which sends no ID token for an amr or acr to be read from", slug, kind)
	}
	tp, err := conn.Exec(ctx,
		`UPDATE core.identity_providers SET mfa_amr = $2, mfa_acr = $3 WHERE slug = $1`,
		slug, amrs, acrs)
	if err != nil {
		return err
	}
	if tp.RowsAffected() == 0 {
		return fmt.Errorf("no identity provider with slug %q", slug)
	}
	if len(amrs)+len(acrs) == 0 {
		fmt.Printf("%s: no upstream claim counts as multi-factor; a sign-in through it is `fed` alone\n", slug)
		return nil
	}
	fmt.Printf("%s: a verified ID token with amr in [%s] or acr in [%s] signs in as multi-factor\n",
		slug, strings.Join(amrs, ", "), strings.Join(acrs, ", "))
	fmt.Println("\n  The provider's word is taken for it: trust a value only from a provider")
	fmt.Println("  that sets it when, and only when, it checked a second factor itself.")
	return nil
}

// idpSetEnabled takes an upstream provider out of service, or puts it back.
//
// Disabling is what an operator does when the upstream is compromised or being
// retired: from the next request its sign-in and link buttons are gone, its
// callback refuses, and its SAML and jwt-bearer assertions are refused. The
// provider, its settings and every account's link to it are kept, so enabling
// it again restores exactly what was there. Deleting it would take the links
// with it.
func idpSetEnabled(ctx context.Context, conn *pgx.Conn, slug string, enabled bool) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	if _, err := store.SetIdentityProviderEnabled(ctx, conn, slug, enabled); err != nil {
		if errors.Is(err, store.ErrProviderUnknown) {
			return fmt.Errorf("no identity provider with slug %q; `signari idp list` shows "+
				"the registered ones", slug)
		}
		return err
	}
	if enabled {
		fmt.Printf("%s is enabled: sign-in, linking and its assertions are accepted again\n", slug)
		return nil
	}
	fmt.Printf("%s is disabled: its sign-in and link routes, and its SAML and jwt-bearer\n", slug)
	fmt.Println("assertions, are refused from the next request. Links to it are kept.")
	fmt.Println("\n  Sessions already signed in through it are NOT ended. To end one")
	fmt.Println("  person's now: PATCH /admin/users/<id> {\"active\": false} (then re-activate).")
	return nil
}

// idpLink attaches an upstream subject to a person in the provider's
// organisation (2.60), which is what the jwt-bearer grant resolves an
// assertion's `sub` against. A key-publishing issuer (`idp add-issuer`) is never
// a sign-in option, so no sign-in can create its links, and before this nothing
// could: the documented workload set-up minted nothing without SQL.
func idpLink(ctx context.Context, conn *pgx.Conn, slug, subject, email string) error {
	if slug == "" || subject == "" || email == "" {
		return fmt.Errorf("idp link needs -slug, -subject and -email (the person the subject acts as)")
	}
	var providerID, orgID string
	if err := conn.QueryRow(ctx, `SELECT id::text, org_id::text FROM core.identity_providers WHERE slug = $1`,
		slug).Scan(&providerID, &orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("no identity provider with slug %q; `signari idp list` shows them", slug)
		}
		return err
	}
	userID, err := store.FindLocalUserByEmail(ctx, conn, orgID, email)
	if err != nil {
		return err
	}
	if userID == "" {
		return fmt.Errorf("no person with the address %s in that provider's organisation", email)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.LinkFederatedIdentity(ctx, tx, providerID, userID, orgID,
		federation.ExternalIdentity{Subject: subject}, false); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("%s at %s now acts as %s: its assertions mint tokens for that account\n", subject, slug, email)
	fmt.Println("through any client paired with this issuer and registered for jwt-bearer.")
	return nil
}

// idpUnlink detaches one. The next assertion naming it is refused; the grant
// issues no refresh token, so nothing outlives it.
func idpUnlink(ctx context.Context, conn *pgx.Conn, slug, subject string) error {
	if slug == "" || subject == "" {
		return fmt.Errorf("idp unlink needs -slug and -subject")
	}
	tag, err := conn.Exec(ctx, `
		DELETE FROM core.federated_identities f USING core.identity_providers p
		WHERE p.id = f.provider_id AND p.slug = $1 AND f.subject = $2`, slug, subject)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s has no link for subject %q", slug, subject)
	}
	fmt.Printf("%s at %s is unlinked: its next assertion is refused\n", subject, slug)
	return nil
}

// idpLinks lists a provider's subjects and the people they act as.
func idpLinks(ctx context.Context, conn *pgx.Conn, slug string) error {
	if slug == "" {
		return fmt.Errorf("idp links needs -slug")
	}
	rows, err := conn.Query(ctx, `
		SELECT f.subject, COALESCE(u.email, u.username, u.id::text), u.status
		FROM core.federated_identities f
		JOIN core.identity_providers p ON p.id = f.provider_id
		JOIN core.users u ON u.id = f.user_id
		WHERE p.slug = $1 ORDER BY f.subject`, slug)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var sub, who, status string
		if err := rows.Scan(&sub, &who, &status); err != nil {
			return err
		}
		n++
		fmt.Printf("%s  %s  %s\n", sub, who, status)
	}
	if n == 0 {
		fmt.Printf("%s has no links\n", slug)
	}
	return rows.Err()
}

// cliOperator names who ran this command, as its audit record does: the
// operating-system account and the host, which is what an investigation can
// follow, since the CLI holds a database credential and no person's.
func cliOperator() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return name + "@" + host
}

// dirList shows an organisation's directory sources and what their last sync
// did. The sync recorded its time, its counts and its error on every run, and
// there was no command to read them: an operator could add, sync and tune a
// source, and could not see whether its last run had worked.
func dirList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	rows, err := conn.Query(ctx, `
		SELECT slug, kind, enabled, dry_run, on_missing, max_deactivate_percent,
		       COALESCE(to_char(last_sync_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI UTC'), 'never'),
		       COALESCE(last_created, 0), COALESCE(last_updated, 0), COALESCE(last_deactivated, 0),
		       COALESCE(last_error, '')
		  FROM core.directory_sources WHERE org_id = $1::uuid ORDER BY slug`, orgID)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var slug, kind, onMissing, last, lastErr string
		var enabled, dry bool
		var ceiling, created, updated, deactivated int
		if err := rows.Scan(&slug, &kind, &enabled, &dry, &onMissing, &ceiling, &last,
			&created, &updated, &deactivated, &lastErr); err != nil {
			return err
		}
		state := "enabled"
		switch {
		case !enabled:
			state = "disabled"
		case dry:
			state = "dry run"
		}
		fmt.Printf("%s  (%s, %s, missing people: %s, at most %d%% deactivated per sync)\n",
			slug, kind, state, onMissing, ceiling)
		fmt.Printf("  last sync: %s", last)
		if last != "never" {
			fmt.Printf(" -- %d created, %d updated, %d deactivated", created, updated, deactivated)
		}
		fmt.Println()
		if lastErr != "" {
			fmt.Printf("  last error: %s\n", lastErr)
		}
		n++
	}
	if n == 0 {
		fmt.Println("no directory sources")
	}
	return rows.Err()
}

// inviteRevoke closes an open invitation, so its link stops working at once.
func inviteRevoke(ctx context.Context, conn *pgx.Conn, orgID, id string) error {
	if orgID == "" || id == "" {
		return fmt.Errorf("give -org and -invitation (the id `signari invite list` shows)")
	}
	if err := store.RevokeInvitation(ctx, conn, orgID, id); err != nil {
		if errors.Is(err, store.ErrInvitationNotRevocable) {
			return fmt.Errorf("%w; `signari invite list -org %s` shows which are open", err, orgID)
		}
		return err
	}
	fmt.Printf("invitation %s is revoked: its link no longer creates an account\n", id)
	return nil
}

// scimSourceSetEnabled takes an inbound SCIM source out of service, or puts it
// back. Disabled, its bearer token is refused from the next request.
func scimSourceSetEnabled(ctx context.Context, conn *pgx.Conn, orgID, slug string, enabled bool) error {
	if orgID == "" || slug == "" {
		return fmt.Errorf("give -org and -slug")
	}
	if err := store.SetSCIMSourceEnabled(ctx, conn, orgID, slug, enabled); err != nil {
		if errors.Is(err, store.ErrSCIMSourceUnknown) {
			return fmt.Errorf("%w; `signari scim-source list` shows the registered ones", err)
		}
		return err
	}
	if enabled {
		fmt.Printf("%s is enabled: its token provisions again\n", slug)
		return nil
	}
	fmt.Printf("%s is disabled: its token is refused from the next request. Links and\n", slug)
	fmt.Println("settings are kept, and the accounts it provisioned are left as they are.")
	return nil
}

// instanceRelatedOrigins sets the further origins a passkey under the
// instance's RP ID may be used from (WebAuthn §5.11, migration 0175), and
// prints the document a browser checks them against. The engine serves it at
// /.well-known/webauthn when the RP ID is its own host; otherwise it must be
// hosted at https://<rp_id>/.well-known/webauthn, or no browser allows them.
func instanceRelatedOrigins(ctx context.Context, conn *pgx.Conn, issuer string, origins []string) error {
	if issuer == "" {
		return fmt.Errorf("give -issuer; -related-origins lists the origins, and empty clears them")
	}
	var rpID *string
	var host, instanceID string
	if err := conn.QueryRow(ctx, `SELECT id::text, rp_id, issuer FROM core.instances WHERE issuer = $1`,
		issuer).Scan(&instanceID, &rpID, &host); err != nil {
		return fmt.Errorf("no instance with issuer %q", issuer)
	}
	// Each origin checked, and the RP ID required, by the writer the Admin API
	// shares.
	err := store.SetRelatedOrigins(ctx, conn, instanceID, origins, passkeys.CheckRelatedOrigin)
	if errors.Is(err, store.ErrNoRPID) {
		return fmt.Errorf("the instance has no RP ID yet; set it with `signari instance webauthn` first")
	}
	if err != nil {
		return err
	}
	if len(origins) == 0 {
		fmt.Println("related origins: none; a passkey is used only under its RP ID")
		return nil
	}
	doc, err := json.MarshalIndent(map[string]any{"origins": origins}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("related origins for RP ID %s:\n%s\n", *rpID, doc)
	if u, err := url.Parse(host); err != nil || !strings.EqualFold(u.Hostname(), *rpID) {
		fmt.Printf("\n  The RP ID is not this server's host, so it does not serve that document.\n"+
			"  Host it as application/json at https://%s/.well-known/webauthn, or no\n"+
			"  browser will allow these origins.\n", *rpID)
	}
	return nil
}

// instanceWebAuthn sets the Relying Party identity passkeys are bound to.
//
// # Nothing could set this, so passkeys were unavailable everywhere
//
// `internal/passkeys` refuses to build a relying party without it — "this
// instance has no rp_id set; passkeys are unavailable until it is" — and no
// command, API or console field wrote the column. Every deployment therefore had
// passkeys switched off by a value nobody could supply, including the
// authenticator policy and attestation work that sits on top of it.
//
// # Why the value is checked here as well as at use
//
// The RP ID is the scope a credential is bound to. A credential created under
// `example.com` works for `login.example.com`; one created under
// `login.example.com` does NOT work for `example.com`, and changing the value
// later invalidates every credential registered under the old one. So the shape
// is checked before it is stored rather than only when somebody tries to sign
// in, and widening is called out rather than silently accepted.
func instanceWebAuthn(ctx context.Context, conn *pgx.Conn, issuer, id, displayName string) error {
	if issuer == "" || id == "" {
		return fmt.Errorf("give -issuer and -rp-id")
	}
	// The rules are store.CheckRPID's, which the Admin API shares: a bare
	// registrable domain, never an address, a scheme, a port or a path.
	if err := store.CheckRPID(id); err != nil {
		return fmt.Errorf("-rp-id: %w", err)
	}

	var current, currentName *string
	var host, instanceID string
	if err := conn.QueryRow(ctx,
		`SELECT id::text, rp_id, rp_display_name, issuer FROM core.instances WHERE issuer = $1`,
		issuer).Scan(&instanceID, &current, &currentName, &host); err != nil {
		return fmt.Errorf("no instance with issuer %q", issuer)
	}

	name := strings.TrimSpace(displayName)
	if name == "" && currentName != nil {
		name = *currentName
	}
	if name == "" {
		// Shown by the authenticator when somebody is asked to confirm. Falling
		// back to the RP ID is better than an empty prompt, which reads to the
		// person as an unidentified site asking for their key.
		name = id
	}

	if err := store.SetInstanceRPID(ctx, conn, instanceID, id, name); err != nil {
		return err
	}

	fmt.Printf("%s\n  rp_id        : %s\n  display name : %s\n", issuer, id, name)
	if current != nil && *current != "" && *current != id {
		fmt.Printf("\n  CHANGED from %q. Every passkey registered under the old value is\n", *current)
		fmt.Println("  now unusable -- a credential is bound to the RP ID it was created")
		fmt.Println("  under, and this is not reversible for anybody who has already enrolled.")
		fmt.Println("  They will need to register again.")
		return nil
	}
	fmt.Println("\n  Passkeys are now available for this instance. The RP ID must be the")
	fmt.Println("  registrable domain or a parent of every host that serves sign-in: a")
	fmt.Println("  credential made under example.com works on login.example.com, and one")
	fmt.Println("  made under login.example.com does not work on example.com.")
	return nil
}

// scimSetEnabled takes a provisioning target in or out of service.
//
// Disabling is what an operator wants when a target is down or being migrated:
// the configuration, the links and the remote ids are all kept, and the next
// sync simply skips it. Deleting the target would take the links with it, and
// the accounts at the far end would then be unreachable rather than merely
// unmanaged.
func scimSetEnabled(ctx context.Context, conn *pgx.Conn, orgID, slug string, enabled bool) error {
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	_, org, err := oneInOrg(ctx, conn, "scim_targets", "slug = $1", slug, orgID, "SCIM target")
	if err != nil {
		return err
	}
	if err := store.SetSCIMTargetEnabled(ctx, conn, org, slug, enabled); err != nil {
		return err
	}
	if enabled {
		fmt.Printf("%s is enabled; the next sync includes it\n", slug)
		return nil
	}
	fmt.Printf("%s is disabled; syncs skip it and its links are kept\n", slug)
	fmt.Println("\n  Nothing is deprovisioned. People deactivated here while the target is")
	fmt.Println("  disabled keep their access there until it is enabled and synced.")
	return nil
}

// dirSet changes how a directory sync behaves.
//
// `max_deactivate_percent` is the one that matters. It is the ceiling the whole
// planner is built around -- a fetch that fails part-way, a filter that matches
// too little, an upstream outage all look identical to "everybody left the
// company", and the ceiling is what stops the reconciler acting on that. It had
// a sensible default and no way to change it, so an operator who found 20% wrong
// for their organisation had no move at all.
func dirSet(ctx context.Context, conn *pgx.Conn, orgID, slug, onMissing string, maxPercent int,
	fs *flag.FlagSet, enabled, dryRun, fetchGroups bool, groupAttr string) error {

	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	sourceID, _, err := oneInOrg(ctx, conn, "directory_sources", "slug = $1", slug, orgID,
		"directory source")
	if err != nil {
		return err
	}

	// Only the flags actually supplied are applied. Without this, changing
	// -on-missing would silently reset -max-deactivate to its default, which on
	// this particular setting means quietly widening a safety ceiling.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	var changes []string
	if set["on-missing"] {
		switch onMissing {
		case "report", "deactivate":
		default:
			return fmt.Errorf("-on-missing must be report or deactivate, not %q", onMissing)
		}
		changes = append(changes, "on-missing")
	}
	if set["max-deactivate"] && (maxPercent < 0 || maxPercent > 100) {
		return fmt.Errorf("-max-deactivate is a percentage, 0 to 100")
	}
	if set["max-deactivate"] {
		changes = append(changes, "max-deactivate")
	}
	if set["enabled"] {
		changes = append(changes, "enabled")
	}
	if set["dry-run"] {
		changes = append(changes, "dry-run")
	}
	// Group sync (2.02): whether memberships are fetched, and for LDAP from
	// which attribute; empty returns it to memberOf.
	if set["fetch-groups"] {
		changes = append(changes, "fetch-groups")
	}
	if set["group-attribute"] {
		changes = append(changes, "group-attribute")
	}
	if len(changes) == 0 {
		return fmt.Errorf("give at least one of -on-missing, -max-deactivate, -enabled, " +
			"-dry-run, -fetch-groups or -group-attribute")
	}
	if set["fetch-groups"] || set["group-attribute"] {
		var fetchArg any
		if set["fetch-groups"] {
			fetchArg = fetchGroups
		}
		if _, err := conn.Exec(ctx, `
			UPDATE core.directory_sources
			   SET fetch_groups         = COALESCE($2::boolean, fetch_groups),
			       ldap_group_attribute = CASE WHEN $3 THEN NULLIF($4::text, '') ELSE ldap_group_attribute END
			 WHERE id = $1::uuid`, sourceID, fetchArg, set["group-attribute"], groupAttr); err != nil {
			if strings.Contains(err.Error(), "ldap_group_attribute") {
				return fmt.Errorf("-group-attribute is an attribute name, such as memberOf")
			}
			return err
		}
	}

	var onMissingArg, maxArg, enabledArg, dryArg any
	if set["on-missing"] {
		onMissingArg = onMissing
	}
	if set["max-deactivate"] {
		maxArg = maxPercent
	}
	if set["enabled"] {
		enabledArg = enabled
	}
	if set["dry-run"] {
		dryArg = dryRun
	}

	if _, err := conn.Exec(ctx, `
		UPDATE core.directory_sources
		   SET on_missing             = COALESCE($2::text, on_missing),
		       max_deactivate_percent = COALESCE($3::int, max_deactivate_percent),
		       enabled                = COALESCE($4::boolean, enabled),
		       dry_run                = COALESCE($5::boolean, dry_run)
		 WHERE id = $1::uuid`, sourceID, onMissingArg, maxArg, enabledArg, dryArg); err != nil {
		if strings.Contains(err.Error(), "on_missing") {
			return fmt.Errorf("-on-missing must be report or deactivate")
		}
		return err
	}

	var om string
	var mp int
	var en, dr, fg bool
	var ga string
	_ = conn.QueryRow(ctx, `
		SELECT on_missing, max_deactivate_percent, enabled, dry_run, fetch_groups,
		       COALESCE(ldap_group_attribute, 'memberOf')
		FROM core.directory_sources WHERE id = $1::uuid`, sourceID).Scan(&om, &mp, &en, &dr, &fg, &ga)

	fmt.Printf("%s:\n  enabled        : %t\n  dry run        : %t\n"+
		"  on missing     : %s\n  max deactivate : %d%%\n  fetch groups   : %t\n",
		slug, en, dr, om, mp, fg)
	if fg {
		fmt.Printf("  group attribute: %s (ldap)\n", ga)
	}
	if om == "deactivate" {
		fmt.Println("\n  People the directory stops returning will be DEACTIVATED here. Preview")
		fmt.Println("  every run first -- `signari dir sync -slug " + slug + "` shows the plan")
		fmt.Printf("  and refuses it whole if it would deactivate more than %d%%.\n", mp)
	}
	if mp == 100 {
		fmt.Println("\n  A 100% ceiling refuses nothing. A single bad fetch can then deactivate")
		fmt.Println("  the entire organisation, which is the failure this setting exists for.")
	}
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

// outpostSetEnabled takes an outpost out of service, or puts it back (2.29).
// The only way to stop one was deleting it, and nothing deleted it either.
// Disabled, its token is refused from the outpost's next request to the core.
func outpostSetEnabled(ctx context.Context, conn *pgx.Conn, orgID, name string, enabled bool) error {
	if orgID == "" || name == "" {
		return fmt.Errorf("give -org and -name")
	}
	if err := store.SetOutpostEnabled(ctx, conn, orgID, name, enabled); err != nil {
		return outpostError(err, name, "", "")
	}
	if enabled {
		fmt.Printf("outpost %s is enabled: the core answers its token again\n", name)
		return nil
	}
	fmt.Printf("outpost %s is disabled: the core refuses its token from its next request, so\n", name)
	fmt.Println("it can no longer authenticate anybody. Its settings are kept.")
	return nil
}

// promptSetEnabled switches a sign-in prompt off, or back on (2.29). Off, it is
// neither asked nor answerable; the answers already given are kept.
func promptSetEnabled(ctx context.Context, conn *pgx.Conn, orgID, slug string, enabled bool) error {
	if orgID == "" || slug == "" {
		return fmt.Errorf("give -org and -slug")
	}
	found, err := store.SetPromptEnabled(ctx, conn, orgID, slug, enabled)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no prompt %q in that organisation; `signari prompt list` shows them", slug)
	}
	if enabled {
		fmt.Printf("prompt %s is enabled: it is asked at the next sign-in it applies to\n", slug)
		return nil
	}
	fmt.Printf("prompt %s is disabled: it is no longer asked, and the answers given are kept\n", slug)
	return nil
}

// racSetEnabled takes a remote-access connection out of service, or puts it
// back (2.29). Disabled, it is neither listed nor connectable from the next
// request; a session already open runs until it closes.
func racSetEnabled(ctx context.Context, conn *pgx.Conn, orgID, slug string, enabled bool) error {
	orgID, err := resolveOrg(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	if err := store.SetRACEnabled(ctx, conn, orgID, slug, enabled); err != nil {
		return racError(err, slug)
	}
	if enabled {
		fmt.Printf("%s is enabled: it is listed and connectable again\n", slug)
		return nil
	}
	fmt.Printf("%s is disabled: it is neither listed nor connectable from the next request.\n", slug)
	fmt.Println("A session already open runs until it closes.")
	return nil
}

// racError says a refused remote-access write in the command's own terms.
func racError(err error, slug string) error {
	if errors.Is(err, store.ErrRACUnknown) {
		return fmt.Errorf("no remote-access connection %q in that organisation; `signari rac list` shows them", slug)
	}
	return err
}

// racReservedParameters says which flag sets each of store.RACReservedParameters,
// the guacd parameters a connection's own settings supply; the store refuses
// them too, and a test keeps the two lists the same.
var racReservedParameters = map[string]string{
	"hostname":              "-host",
	"port":                  "-port",
	"username":              "-login, which is sealed",
	"password":              "-password, which is sealed",
	"private-key":           "nothing yet: a credential is sealed, never a parameter",
	"passphrase":            "nothing yet: a credential is sealed, never a parameter",
	"recording-path":        "-recording-path",
	"create-recording-path": "-recording-path",
}

// racSetParameters replaces a connection's guacd parameters (2.29): `security`,
// `ignore-cert`, `color-depth` and the rest the protocol takes. Nothing could
// set them, so every connection ran with guacd's defaults. Empty clears them.
// guacd refuses a name it does not take for the protocol at the next connect,
// by name, which is where the protocol's own list is known.
func racSetParameters(ctx context.Context, conn *pgx.Conn, orgID, slug, raw string) error {
	orgID, err := resolveOrg(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if slug == "" {
		return fmt.Errorf("give -slug")
	}
	params := map[string]string{}
	for _, pair := range splitList(raw) {
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return fmt.Errorf("-rac-params takes name=value pairs separated by commas; %q is not one", pair)
		}
		if instead, reserved := racReservedParameters[k]; reserved {
			return fmt.Errorf("%s is not a parameter: it is set with %s", k, instead)
		}
		if _, dup := params[k]; dup {
			return fmt.Errorf("-rac-params names %s twice", k)
		}
		params[k] = strings.TrimSpace(v)
	}
	if err := store.SetRACParameters(ctx, conn, orgID, slug, params); err != nil {
		return racError(err, slug)
	}
	if len(params) == 0 {
		fmt.Printf("%s: no parameters; guacd's defaults apply\n", slug)
		return nil
	}
	names := make([]string, 0, len(params))
	for k := range params {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Printf("%s: %s, from the next connection\n", slug, strings.Join(names, ", "))
	return nil
}

// migrationSourceAdd configures the provider an organisation is migrating off
// (2.01): an OAuth provider's password grant, or the LDAP directory itself.
// Nothing could create one, so delegated verification could not be switched
// on. The source is created disabled, and a replaced one keeps its state.
func migrationSourceAdd(ctx context.Context, conn *pgx.Conn, orgID, kind, name, tokenEndpoint, ldapURL,
	clientID, secret, scope, template string, startTLS bool, caPath string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	c := store.MigrationSourceConfig{DisplayName: name, ClientID: clientID, ClientSecret: secret, Scope: scope}
	switch kind {
	case "oidc", "oidc_password":
		c.Kind, c.URL = "oidc_password", tokenEndpoint
		if ldapURL != "" || template != "" || caPath != "" {
			return fmt.Errorf("-ldap-url, -bind-dn-template and -ldap-ca are for -kind ldap")
		}
	case "ldap":
		c.Kind, c.URL, c.BindDNTemplate, c.StartTLS = "ldap", ldapURL, template, startTLS
		if tokenEndpoint != "" {
			return fmt.Errorf("-token-endpoint is for -kind oidc_password")
		}
		if caPath != "" {
			raw, err := os.ReadFile(caPath) // #nosec G304 -- the operator names the file
			if err != nil {
				return err
			}
			c.CAPEM = string(raw)
		}
	default:
		return fmt.Errorf("-kind is oidc_password or ldap for a migration source")
	}
	var root *keys.RootKey
	if secret != "" {
		var err error
		if root, err = rootKey(); err != nil {
			return err
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.SetMigrationSource(ctx, tx, root, orgID, c); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return migrationSourceShow(ctx, conn, orgID)
}

// migrationSourceSetEnabled switches delegated verification on or off.
func migrationSourceSetEnabled(ctx context.Context, conn *pgx.Conn, orgID string, enabled bool) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetMigrationSourceEnabled(ctx, tx, orgID, enabled); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return migrationSourceShow(ctx, conn, orgID)
}

// migrationSourceRemove deletes the source.
func migrationSourceRemove(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.RemoveMigrationSource(ctx, tx, orgID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("migration source removed. People still pending cannot sign in with a password")
	fmt.Println("until they reset it or a source is configured again.")
	return nil
}

// migrationSourceShow reports the source and how the cutover is going.
func migrationSourceShow(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("give -org")
	}
	s, err := store.MigrationSourceOf(ctx, conn, orgID)
	if err != nil {
		return err
	}
	state := "disabled"
	if s.Enabled {
		state = "ENABLED"
	}
	fmt.Printf("migration source %q (%s), %s\n  url      : %s\n", s.DisplayName, s.Kind, state, s.URL)
	if s.Kind == "ldap" {
		fmt.Printf("  bind dn  : %s\n  starttls : %v\n  own CA   : %v\n", s.BindDNTemplate, s.StartTLS, s.HasCA)
	} else {
		fmt.Printf("  client   : %s (secret %v)\n  scope    : %s\n", s.ClientID, s.HasSecret, s.Scope)
	}
	fmt.Printf("  people   : %d pending, %d migrated through it\n", s.Pending, s.Migrated)
	fmt.Printf("  verified : %d accepted, %d refused or unreachable", s.Successes, s.Failures)
	if s.LastError != "" {
		fmt.Printf("; last: %s", s.LastError)
	}
	fmt.Println()
	if s.Enabled {
		fmt.Println("\n  While enabled, the password a pending person types is sent to this source to be")
		fmt.Println("  checked, and kept here as a hash when it is accepted.")
	} else {
		fmt.Println("\n  `signari migration-source enable` starts verifying against it.")
	}
	return nil
}

// ssfSetStatus pauses, disables or re-enables a client's Shared Signals stream
// (2.29), telling the receiver as SSF 1.0 requires; store.SetStreamStatus says
// what each change sends and keeps.
func ssfSetStatus(ctx context.Context, conn *pgx.Conn, orgID, clientID, status, reason string) error {
	if orgID == "" || clientID == "" || status == "" {
		return fmt.Errorf("give -org, -client-id and -status (enabled, paused or disabled)")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	prev, err := store.SetStreamStatus(ctx, tx, orgID, clientID, status, reason)
	if err != nil {
		if errors.Is(err, store.ErrStreamUnknown) {
			return fmt.Errorf("%w; `signari ssf list` shows the streams", err)
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	switch {
	case prev == status:
		fmt.Printf("%s's stream is already %s; nothing changed or was sent\n", clientID, status)
	case status == "paused":
		fmt.Printf("%s's stream is paused. The receiver is sent a stream-updated event saying so;\n", clientID)
		fmt.Println("events from now on are held, and sent when the stream is enabled again.")
	case status == "disabled":
		fmt.Printf("%s's stream is disabled. Nothing is sent or held from now on, and the events it\n", clientID)
		fmt.Println("held are discarded.")
	default:
		fmt.Printf("%s's stream is enabled. The receiver is sent a stream-updated event, then\n", clientID)
		fmt.Println("anything held while it was paused.")
	}
	return nil
}

// registrationRevoke stops a dynamic-registration token before it is spent or
// expires (2.29): a leaked one could only be waited out. Chosen by -token-id,
// or by -name when one live token has it.
func registrationRevoke(ctx context.Context, conn *pgx.Conn, orgID, name, tokenID string) error {
	if orgID == "" || (name == "") == (tokenID == "") {
		return fmt.Errorf("give -org, and -name or -token-id (one of them)")
	}
	rows, err := conn.Query(ctx, `SELECT id::text FROM core.registration_tokens
		WHERE org_id = $1::uuid AND revoked_at IS NULL
		  AND (($2 <> '' AND name = $2) OR ($3 <> '' AND id::text = $3))`, orgID, name, tokenID)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	switch {
	case len(ids) == 0:
		return fmt.Errorf("no unrevoked registration token matches in that organisation")
	case len(ids) > 1:
		return fmt.Errorf("%d unrevoked tokens are named %q (%s); choose one with -token-id",
			len(ids), name, strings.Join(ids, ", "))
	}
	if _, err := store.RevokeRegistrationToken(ctx, conn, orgID, ids[0]); err != nil {
		return err
	}
	fmt.Printf("registration token %s is revoked: /oauth2/register refuses it from the next request\n", ids[0])
	return nil
}

// resourceAdd registers a resource server an organisation's tokens may be
// audienced to (1.87). Until one is, every `resource` a client asks for is
// refused with invalid_target.
func resourceAdd(ctx context.Context, conn *pgx.Conn, orgID, resource, name string) error {
	if orgID == "" || resource == "" {
		return fmt.Errorf("resource add needs -org and -resource")
	}
	if err := store.SetResourceServer(ctx, conn, orgID, resource, name); err != nil {
		return err
	}
	fmt.Printf("registered %s: clients of this organisation may now ask for tokens audienced to it\n", resource)
	return nil
}

// resourceList shows the registered resource servers of one organisation.
func resourceList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("resource list needs -org")
	}
	rs, err := store.ResourceServers(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		fmt.Println("no resource servers: every resource indicator is refused")
		return nil
	}
	for _, r := range rs {
		fmt.Printf("%s  %s\n", r.Resource, r.Name)
	}
	return nil
}

// resourceRemove withdraws one. Tokens for it are refused from the next
// request, refreshes of tokens already issued included.
func resourceRemove(ctx context.Context, conn *pgx.Conn, orgID, resource string) error {
	if orgID == "" || resource == "" {
		return fmt.Errorf("resource remove needs -org and -resource")
	}
	if err := store.RemoveResourceServer(ctx, conn, orgID, resource); err != nil {
		if errors.Is(err, store.ErrResourceServerUnknown) {
			return fmt.Errorf("%s is not registered in that organisation; `signari resource list` shows them", resource)
		}
		return err
	}
	fmt.Printf("removed %s: no new token is audienced to it, and refreshes asking for it are refused\n", resource)
	return nil
}
