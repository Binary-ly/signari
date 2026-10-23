// Package importer reads a realm export from another identity provider and
// creates the equivalent users and clients here.
//
// The point is that an import is boring. Everything it produces goes through the
// same code paths as anything else: users get a password hash the normal
// verifier understands, clients get their existing id and secret so downstream
// applications keep working, and the first successful sign-in upgrades the hash
// to Argon2id like any other foreign format.
//
// Two rules, both learned from how imports actually go wrong:
//
//  1. IDEMPOTENT. Re-running must not duplicate anyone. Imports are re-run --
//     after a partial failure, after a dry run, after someone finds one more
//     realm -- and an importer that duplicates users on the second pass is one
//     nobody dares use twice.
//  2. REPORT, DO NOT GUESS. A user with an unsupported credential type is
//     skipped and named, not imported without a password. Silently creating an
//     account nobody can sign in to is worse than refusing it. Everything else
//     the realm holds and this does not carry is named too (Result.Dropped),
//     so the list of what to redo by hand is complete rather than whatever an
//     operator happened to notice was missing.
package importer

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// KeycloakRealm is the subset of a realm export this reads. Deliberately
// partial: a realm export has hundreds of fields, and parsing ones we cannot act
// on would only invite the impression that we honoured them.
type KeycloakRealm struct {
	Realm   string           `json:"realm"`
	Users   []keycloakUser   `json:"users"`
	Clients []keycloakClient `json:"clients"`
	// Groups is the realm's group tree; a user names theirs by path.
	Groups []keycloakGroup `json:"groups"`
	Roles  struct {
		Realm []keycloakRole `json:"realm"`
	} `json:"roles"`
	// The relying party IDs passkeys were registered under
	// (RealmRepresentation.java:138,153). Empty, Keycloak used the host name,
	// which the export does not record, so the passkeys cannot be carried.
	WebAuthnRPID             string `json:"webAuthnPolicyRpId"`
	WebAuthnPasswordlessRPID string `json:"webAuthnPolicyPasswordlessRpId"`
}

type keycloakUser struct {
	Username            string               `json:"username"`
	Email               string               `json:"email"`
	FirstName           string               `json:"firstName"`
	LastName            string               `json:"lastName"`
	Enabled             bool                 `json:"enabled"`
	EmailVerified       bool                 `json:"emailVerified"`
	Credentials         []keycloakCredential `json:"credentials"`
	Groups              []string             `json:"groups"`
	RealmRoles          []string             `json:"realmRoles"`
	ClientRoles         map[string][]string  `json:"clientRoles"`
	FederatedIdentities []keycloakLink       `json:"federatedIdentities"`
	Attributes          map[string][]string  `json:"attributes"`
}

type keycloakCredential struct {
	Type           string `json:"type"`
	UserLabel      string `json:"userLabel"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
}

// keycloakLink is a federated identity (FederatedIdentityRepresentation.java:25-27).
type keycloakLink struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId"`
	UserName         string `json:"userName"`
}

// keycloakGroup is one group and those under it (GroupRepresentation.java:35-46).
type keycloakGroup struct {
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	SubGroups   []keycloakGroup     `json:"subGroups"`
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
	Attributes  map[string][]string `json:"attributes"`
}

type keycloakRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
}

type keycloakClient struct {
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name"`
	Protocol                  string            `json:"protocol"`
	Secret                    string            `json:"secret"`
	Enabled                   bool              `json:"enabled"`
	PublicClient              bool              `json:"publicClient"`
	BearerOnly                bool              `json:"bearerOnly"`
	RedirectURIs              []string          `json:"redirectUris"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ServiceAccountEnabled     bool              `json:"serviceAccountsEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	Attributes                map[string]string `json:"attributes"`
	ProtocolMappers           []struct {
		Name           string `json:"name"`
		ProtocolMapper string `json:"protocolMapper"`
	} `json:"protocolMappers"`
}

// Result is what happened, in enough detail to act on.
type Result struct {
	UsersCreated   int
	UsersUpdated   int
	UsersSkipped   []string
	ClientsCreated int
	ClientsSkipped []string
	// ClientsNowRequiringPKCE are confidential clients using the browser flow.
	// Every imported client requires PKCE, as every client created here does,
	// and an application that sends no code_challenge stops at the first
	// sign-in after cutover. Listed so the operator can check each one, and opt
	// out with `client set-pkce` the ones that cannot send it.
	ClientsNowRequiringPKCE []string

	GroupsCreated        int
	Memberships          int
	OTPImported          int
	PasskeysImported     int
	LinksImported        int
	AttributesImported   int
	SAMLProvidersCreated int
	// Renamed are names that changed coming across, so nothing is renamed
	// without saying: a group's path, which names here cannot hold.
	Renamed []string
	// Dropped is everything the realm holds that was not carried, and why.
	Dropped []string
	// BuiltIns are what Keycloak makes in every realm, left behind by design.
	BuiltIns []string
}

// keycloakBuiltInClients are the clients Keycloak creates in every realm
// (Constants.java:33-40, at the pinned 783ca364).
var keycloakBuiltInClients = []string{"security-admin-console", "admin-cli", "account", "account-console",
	"broker", "realm-management", "admin-permissions"}

// keycloakBuiltInRole reports a role Keycloak gives every realm
// (Constants.java:51-55): offline_access, uma_authorization and the
// default-roles-<realm> composite.
func keycloakBuiltInRole(name string) bool {
	return name == "offline_access" || name == "uma_authorization" || strings.HasPrefix(name, "default-roles")
}

// Parse reads a realm export.
func Parse(r io.Reader) (*KeycloakRealm, error) {
	var realm KeycloakRealm
	// Unknown fields are ignored rather than rejected: a realm export from a
	// different Keycloak version has fields we have never heard of, and refusing
	// the whole file over one of them would make this useless in practice.
	if err := json.NewDecoder(r).Decode(&realm); err != nil {
		return nil, fmt.Errorf("importer: reading realm export: %w", err)
	}
	if realm.Realm == "" && len(realm.Users) == 0 && len(realm.Clients) == 0 {
		return nil, fmt.Errorf("importer: this does not look like a Keycloak realm export")
	}
	return &realm, nil
}

// Options are what an import needs besides the realm.
type Options struct {
	// Hasher hashes the client secrets an import keeps.
	Hasher *passwords.Hasher
	// Root seals the OTP seeds and the personal attributes brought across,
	// under each person's own key. Without it they are left behind, and named.
	Root *keys.RootKey
}

// Import is ImportWith given only the hasher.
func Import(ctx context.Context, tx pgx.Tx, orgID string, realm *KeycloakRealm,
	hasher *passwords.Hasher) (*Result, error) {
	return ImportWith(ctx, tx, orgID, realm, Options{Hasher: hasher})
}

// ImportWith creates users, groups and clients from a parsed realm.
//
// Runs in ONE transaction: a half-imported realm is the worst outcome, because
// nobody can tell which half, and the natural response -- run it again -- is
// exactly what an idempotent importer is for but a partial one punishes.
//
// A dry run is the same import in a transaction the caller rolls back, so its
// report is what the import would do: it once counted every user as created
// without asking who existed, and reported nothing of what it would drop.
func ImportWith(ctx context.Context, tx pgx.Tx, orgID string, realm *KeycloakRealm, opts Options) (*Result, error) {
	res := &Result{}
	groups, err := importKeycloakGroups(ctx, tx, orgID, realm, res)
	if err != nil {
		return nil, err
	}
	roles, err := importKeycloakRoles(ctx, tx, orgID, realm, res)
	if err != nil {
		return nil, err
	}
	providers := map[string]bool{}
	unlinked := map[string]int{}
	clientRoles := map[string]int{}
	attributes := map[string]int{}

	for _, u := range realm.Users {
		identifier := u.Email
		if identifier == "" {
			identifier = u.Username
		}
		if identifier == "" {
			res.UsersSkipped = append(res.UsersSkipped, "(a user with no username or email)")
			continue
		}
		if !u.Enabled {
			// Disabled in Keycloak means disabled here. Importing them as active
			// would silently re-enable accounts somebody deliberately turned off.
			res.UsersSkipped = append(res.UsersSkipped, identifier+" (disabled in the realm)")
			continue
		}

		// A person signs in with a password, or through a provider this
		// organisation has: either is an account somebody can use.
		var links []keycloakLink
		for _, l := range u.FederatedIdentities {
			known, seen := providers[l.IdentityProvider]
			if !seen {
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.identity_providers
					WHERE org_id = $1::uuid AND slug = $2)`, orgID, l.IdentityProvider).Scan(&known); err != nil {
					return nil, fmt.Errorf("importer: looking for provider %s: %w", l.IdentityProvider, err)
				}
				providers[l.IdentityProvider] = known
			}
			if known {
				links = append(links, l)
			} else {
				unlinked[l.IdentityProvider]++
			}
		}
		hash, ok := keycloakPasswordHash(u)
		if !ok && len(links) == 0 {
			// Named, not silently imported without a credential: an account
			// nobody can sign in to is worse than one that was refused.
			res.UsersSkipped = append(res.UsersSkipped,
				identifier+" (no importable password and no link to a provider registered here; they must "+
					"use recovery or delegated sign-in)")
			continue
		}
		if ok {
			// The same question sign-in will ask. A credential whose iteration
			// count is over the ceiling was imported and then refused at every
			// attempt, which is the account nobody can sign in to, created anyway.
			if err := passwords.CostRefusal(hash); err != nil {
				res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf(
					"%s (its password hash costs more than this server verifies: %v; they must "+
						"use recovery or delegated sign-in)", identifier, err))
				continue
			}
		}

		// The username is unique here too, and the email match below cannot see
		// it. An account holding it under another address is somebody else,
		// reported rather than a failed import; matched by it where either side
		// has no address, it is the same person, which a re-run of a realm
		// whose people have no email must survive. Both failed the whole import
		// on users_org_username_key.
		var holder, holderEmail string
		if u.Username != "" {
			err := tx.QueryRow(ctx, `SELECT id::text, COALESCE(email, '') FROM core.users
				WHERE org_id = $1::uuid AND lower(username) = lower($2)`, orgID, u.Username).Scan(&holder, &holderEmail)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("importer: looking up %s: %w", identifier, err)
			}
		}
		if holder != "" && u.Email != "" && holderEmail != "" && !strings.EqualFold(holderEmail, u.Email) {
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("%s (the username %s belongs to another "+
				"account here, %s)", identifier, u.Username, holderEmail))
			continue
		}

		var userID string
		var inserted bool
		var err error
		if holder != "" && (u.Email == "" || holderEmail == "") {
			userID = holder
			_, err = tx.Exec(ctx, `UPDATE core.users SET
				given_name = COALESCE(given_name, NULLIF($2,'')), surname = COALESCE(surname, NULLIF($3,'')),
				display_name = COALESCE(display_name, NULLIF(btrim($2 || ' ' || $3), ''))
				WHERE id = $1::uuid`, holder, strings.TrimSpace(u.FirstName), strings.TrimSpace(u.LastName))
		} else {
			err = tx.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, username, user_handle, email_verified_at, migration_state,
			                        given_name, surname, display_name)
			VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''),
			        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
			        CASE WHEN $4 THEN now() ELSE NULL END, CASE WHEN $7 THEN 'pending' ELSE 'none' END,
			        NULLIF($5,''), NULLIF($6,''), NULLIF(btrim($5 || ' ' || $6), ''))
			-- Matches users_org_email_key exactly: a PARTIAL unique index on
			-- (org_id, lower(email)). The conflict target must mirror the index
			-- expression and its WHERE clause, or PostgreSQL cannot use it and the
			-- import fails on the first existing user -- which is precisely the
			-- re-run an idempotent importer exists to make safe.
			ON CONFLICT (org_id, lower(email)) WHERE email IS NOT NULL
			DO UPDATE SET username = COALESCE(core.users.username, EXCLUDED.username),
			              -- The names fill gaps and never replace what an account
			              -- already holds; they were dropped on import entirely.
			              given_name = COALESCE(core.users.given_name, EXCLUDED.given_name),
			              surname = COALESCE(core.users.surname, EXCLUDED.surname),
			              display_name = COALESCE(core.users.display_name, EXCLUDED.display_name)
			RETURNING id::text, (xmax = 0)`,
				orgID, strings.ToLower(u.Email), u.Username, u.EmailVerified,
				strings.TrimSpace(u.FirstName), strings.TrimSpace(u.LastName), ok).Scan(&userID, &inserted)
		}
		if err != nil {
			return nil, fmt.Errorf("importer: creating user %s: %w", identifier, err)
		}

		if ok {
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, source_system, is_current)
				VALUES ($1::uuid, $2::uuid, $3, 'keycloak', 'keycloak', false)
				ON CONFLICT (user_id) DO UPDATE SET
					hash = EXCLUDED.hash, algorithm = 'keycloak',
					source_system = 'keycloak', is_current = false, updated_at = now()`,
				userID, orgID, hash); err != nil {
				return nil, fmt.Errorf("importer: storing credential for %s: %w", identifier, err)
			}
		}
		if inserted {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}

		// Membership: the groups by path, the realm roles as their groups.
		var member []string
		for _, path := range u.Groups {
			if name, ok := groups[path]; ok {
				member = append(member, name)
			} else {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's membership of %s (no such group came across)",
					identifier, path))
			}
		}
		for _, r := range u.RealmRoles {
			if keycloakBuiltInRole(r) {
				continue
			}
			if name, ok := roles[r]; ok {
				member = append(member, name)
			} else {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's realm role %s (no such role came across)",
					identifier, r))
			}
		}
		for _, name := range member {
			tag, err := tx.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
				SELECT id, $3::uuid, org_id FROM core.groups WHERE org_id = $1::uuid AND name = $2
				ON CONFLICT DO NOTHING`, orgID, name, userID)
			if err != nil {
				return nil, fmt.Errorf("importer: adding %s to %s: %w", identifier, name, err)
			}
			res.Memberships += int(tag.RowsAffected())
		}
		for client, held := range u.ClientRoles {
			for _, r := range held {
				clientRoles[client+"/"+r]++
			}
		}

		if err := importKeycloakFactors(ctx, tx, orgID, userID, identifier, realm, u, opts, res); err != nil {
			return nil, err
		}
		for _, l := range links {
			if _, err := store.LinkSubject(ctx, tx, orgID, l.IdentityProvider, userID, l.UserID); err != nil {
				if errors.Is(err, store.ErrIdPLinkTaken) || errors.Is(err, store.ErrIdPLinkPersonElsewhere) {
					res.Dropped = append(res.Dropped, fmt.Sprintf("%s's link to %s as %s (%v)", identifier,
						l.IdentityProvider, l.UserID, err))
					continue
				}
				return nil, fmt.Errorf("importer: linking %s to %s: %w", identifier, l.IdentityProvider, err)
			}
			res.LinksImported++
		}
		for name, values := range u.Attributes {
			n, err := importKeycloakAttribute(ctx, tx, orgID, userID, name, values, opts.Root)
			if err != nil {
				return nil, fmt.Errorf("importer: %s's attribute %s: %w", identifier, name, err)
			}
			if n == 0 {
				attributes[name]++
			}
			res.AttributesImported += n
		}
	}
	for _, p := range sortedKeys(unlinked) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%d link(s) to provider %s (register it here with that slug, "+
			"then import again)", unlinked[p], p))
	}
	for _, r := range sortedKeys(clientRoles) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("client role %s, held by %d (a client's roles have no "+
			"counterpart here; grant a group and release it to the client)", r, clientRoles[r]))
	}
	for _, a := range sortedKeys(attributes) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("attribute %s on %d (declare it, then import again)", a,
			attributes[a]))
	}

	for _, c := range realm.Clients {
		if slices.Contains(keycloakBuiltInClients, c.ClientID) {
			res.BuiltIns = append(res.BuiltIns, "client "+c.ClientID)
			continue
		}
		if c.Protocol == "saml" {
			if err := importKeycloakSAML(ctx, tx, orgID, c, res); err != nil {
				return nil, err
			}
			continue
		}
		if err := importKeycloakClient(ctx, tx, orgID, c, opts.Hasher, res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// groupNamePart is what a group name here may hold (groups_name_shape).
var groupNamePart = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// keycloakGroupName is a group path as a name here: its segments joined by
// dots, each one's other characters a hyphen; "" for one that does not fit.
func keycloakGroupName(path string) string {
	var parts []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg = strings.Trim(groupNamePart.ReplaceAllString(seg, "-"), "-"); seg != "" {
			parts = append(parts, seg)
		}
	}
	name := strings.Join(parts, ".")
	if len(name) > 64 {
		return ""
	}
	return name
}

// importKeycloakGroups makes every group in the tree, answering each path's
// name here.
func importKeycloakGroups(ctx context.Context, tx pgx.Tx, orgID string, realm *KeycloakRealm,
	res *Result) (map[string]string, error) {
	names := map[string]string{}
	taken := map[string]string{}
	var walk func(gs []keycloakGroup, parent string) error
	walk = func(gs []keycloakGroup, parent string) error {
		for _, g := range gs {
			path := g.Path
			if path == "" {
				path = parent + "/" + g.Name
			}
			name := keycloakGroupName(path)
			switch {
			case name == "":
				res.Dropped = append(res.Dropped, fmt.Sprintf("group %s (its path makes no name of at most 64 "+
					"letters, digits, dots, hyphens and underscores)", path))
			case taken[name] != "":
				res.Dropped = append(res.Dropped, fmt.Sprintf("group %s (it would be named %s, as %s is)", path,
					name, taken[name]))
			default:
				taken[name] = path
				names[path] = name
				if name != strings.TrimPrefix(path, "/") {
					res.Renamed = append(res.Renamed, fmt.Sprintf("group %s is %s", path, name))
				}
				tag, err := tx.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name, description)
					VALUES ($1::uuid, $2, $3, $4) ON CONFLICT (org_id, name) DO NOTHING`, orgID, name, g.Name,
					"From Keycloak realm "+realm.Realm+", "+path)
				if err != nil {
					return fmt.Errorf("importer: creating group %s: %w", path, err)
				}
				res.GroupsCreated += int(tag.RowsAffected())
			}
			if len(g.RealmRoles) > 0 || len(g.ClientRoles) > 0 {
				res.Dropped = append(res.Dropped, fmt.Sprintf("the roles group %s grants its members (a group "+
					"here grants nothing itself; policies name it)", path))
			}
			if len(g.Attributes) > 0 {
				res.Dropped = append(res.Dropped, fmt.Sprintf("group %s's attributes %s", path,
					strings.Join(sortedKeys(g.Attributes), ", ")))
			}
			if err := walk(g.SubGroups, path); err != nil {
				return err
			}
		}
		return nil
	}
	return names, walk(realm.Groups, "")
}

// importKeycloakRoles makes a group for each realm role, role.<name>, so a
// policy can name who held it; Keycloak's own roles are left behind.
func importKeycloakRoles(ctx context.Context, tx pgx.Tx, orgID string, realm *KeycloakRealm,
	res *Result) (map[string]string, error) {
	names := map[string]string{}
	for _, r := range realm.Roles.Realm {
		if keycloakBuiltInRole(r.Name) {
			res.BuiltIns = append(res.BuiltIns, "role "+r.Name)
			continue
		}
		part := keycloakGroupName("/" + r.Name)
		name := "role." + part
		if part == "" || len(name) > 64 {
			res.Dropped = append(res.Dropped, fmt.Sprintf("realm role %s (its name makes no group name here)", r.Name))
			continue
		}
		names[r.Name] = name
		res.Renamed = append(res.Renamed, fmt.Sprintf("realm role %s is group %s", r.Name, name))
		if r.Composite {
			res.Dropped = append(res.Dropped, fmt.Sprintf("the roles realm role %s contains (its holders are "+
				"members of %s and of nothing it contained)", r.Name, name))
		}
		desc := "From Keycloak realm " + realm.Realm + ", realm role " + r.Name
		if r.Description != "" {
			desc += ": " + r.Description
		}
		tag, err := tx.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name, description)
			VALUES ($1::uuid, $2, $3, $4) ON CONFLICT (org_id, name) DO NOTHING`, orgID, name, r.Name, desc)
		if err != nil {
			return nil, fmt.Errorf("importer: creating the group for role %s: %w", r.Name, err)
		}
		res.GroupsCreated += int(tag.RowsAffected())
	}
	return names, nil
}

// keycloakOTPData is an OTP credential's settings (OTPCredentialData.java:16-21).
type keycloakOTPData struct {
	SubType        string `json:"subType"`
	Digits         int    `json:"digits"`
	Counter        int    `json:"counter"`
	Period         int    `json:"period"`
	Algorithm      string `json:"algorithm"`
	SecretEncoding string `json:"secretEncoding"`
}

// keycloakOTPAlgorithms are HmacOTP.java:32-34's names.
var keycloakOTPAlgorithms = map[string]mfa.Algorithm{"HmacSHA1": mfa.SHA1, "HmacSHA256": mfa.SHA256,
	"HmacSHA512": mfa.SHA512}

// keycloakWebAuthnData is a passkey's (WebAuthnCredentialData.java:42-48).
type keycloakWebAuthnData struct {
	AAGUID                     string   `json:"aaguid"`
	CredentialID               string   `json:"credentialId"`
	Counter                    int64    `json:"counter"`
	CredentialPublicKey        string   `json:"credentialPublicKey"`
	AttestationStatementFormat string   `json:"attestationStatementFormat"`
	Transports                 []string `json:"transports"`
}

// importKeycloakFactors brings a person's OTP and passkeys.
func importKeycloakFactors(ctx context.Context, tx pgx.Tx, orgID, userID, identifier string, realm *KeycloakRealm,
	u keycloakUser, opts Options, res *Result) error {
	otp := false
	for _, c := range u.Credentials {
		switch c.Type {
		case "otp":
			if otp {
				res.Dropped = append(res.Dropped, identifier+"'s second OTP credential (one is held here)")
				continue
			}
			otp = true
			// One held already, imported before or enrolled here since, is
			// kept: assigned again, a counter-based token's counter would go
			// back to the export's, and the codes pressed since would work twice.
			var held bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.totp_credentials
				WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL)`, userID).Scan(&held); err != nil {
				return err
			}
			if held {
				continue
			}
			why, err := importKeycloakOTP(ctx, tx, orgID, userID, c, opts.Root)
			if err != nil {
				return err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's OTP (%s)", identifier, why))
				continue
			}
			res.OTPImported++
		case "webauthn", "webauthn-passwordless":
			imported, why, err := importKeycloakPasskey(ctx, tx, orgID, userID, realm, c)
			if err != nil {
				return err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's %s credential (%s)", identifier, c.Type, why))
				continue
			}
			if imported {
				res.PasskeysImported++
			}
		case "password":
		default:
			res.Dropped = append(res.Dropped, fmt.Sprintf("%s's %s credential (not a kind this server holds)",
				identifier, c.Type))
		}
	}
	return nil
}

// importKeycloakOTP assigns the credential's seed, answering why not when it
// cannot be carried.
func importKeycloakOTP(ctx context.Context, tx pgx.Tx, orgID, userID string, c keycloakCredential,
	root *keys.RootKey) (string, error) {
	var data keycloakOTPData
	var secret struct {
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(c.CredentialData), &data) != nil || json.Unmarshal([]byte(c.SecretData), &secret) != nil {
		return "its data does not parse", nil
	}
	// OTPCredentialModel.java:111-121: no encoding is the value's own bytes,
	// BASE32 its decoding.
	seed := []byte(secret.Value)
	if strings.EqualFold(data.SecretEncoding, "BASE32") {
		v := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret.Value, " ", ""), "="))
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(v)
		if err != nil {
			return "its Base32 seed does not decode", nil
		}
		seed = decoded
	} else if data.SecretEncoding != "" {
		return "its seed is in an encoding Keycloak itself refuses, " + data.SecretEncoding, nil
	}
	algorithm, known := keycloakOTPAlgorithms[data.Algorithm]
	if !known {
		return "its algorithm " + data.Algorithm + " is not SHA1, SHA256 or SHA512", nil
	}
	params := mfa.Params{Algorithm: algorithm, Digits: data.Digits, Period: time.Duration(data.Period) * time.Second}
	kind, last := "totp", int64(0)
	if data.SubType == "hotp" {
		// Keycloak keeps the next counter to try (HmacOTP.java:82-93, saved
		// by OTPCredentialProvider.java:105-109); this keeps the last used.
		kind, last = "hotp", int64(data.Counter)-1
		params.Period = mfa.DefaultPeriod
	} else if data.SubType != "totp" {
		return "its kind " + data.SubType + " is neither totp nor hotp", nil
	}
	if err := params.Check(); err != nil {
		return err.Error(), nil
	}
	if root == nil {
		return "sealing a seed needs SIGNARI_ROOT_KEY, which is not loaded", nil
	}
	if _, err := store.AssignOTPToken(ctx, tx, userID, orgID, seed, kind, string(params.Algorithm), params.Digits,
		params.Period, last, root); err != nil {
		return "", fmt.Errorf("importer: assigning OTP: %w", err)
	}
	return "", nil
}

// decodeKeycloakBytes reads base64 in any of the encodings a key may have
// been written in: Keycloak encodes a credential id with the standard
// alphabet (WebAuthnCredentialProvider.java:131), and the public key through a
// library converter, so both alphabets, padded or not, are tried.
func decodeKeycloakBytes(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
		base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// importKeycloakPasskey saves the credential under the relying party ID the
// realm registered it with, answering whether it was saved now, or why it
// cannot be carried.
func importKeycloakPasskey(ctx context.Context, tx pgx.Tx, orgID, userID string, realm *KeycloakRealm,
	c keycloakCredential) (bool, string, error) {
	rpID := realm.WebAuthnRPID
	if c.Type == "webauthn-passwordless" {
		rpID = realm.WebAuthnPasswordlessRPID
	}
	if rpID == "" {
		return false, "the realm states no relying party ID, so Keycloak used its host name, which the export " +
			"does not record; the person registers a passkey again", nil
	}
	var data keycloakWebAuthnData
	if json.Unmarshal([]byte(c.CredentialData), &data) != nil {
		return false, "its data does not parse", nil
	}
	id, ok := decodeKeycloakBytes(data.CredentialID)
	if !ok || len(id) == 0 {
		return false, "its credential id does not decode", nil
	}
	key, ok := decodeKeycloakBytes(data.CredentialPublicKey)
	if !ok {
		return false, "its public key does not decode", nil
	}
	// Checked as sign-in will read it: a key that does not parse here would
	// fail every ceremony.
	if _, err := webauthncose.ParsePublicKey(key); err != nil {
		return false, "its public key is not a COSE key: " + err.Error(), nil
	}
	var aaguid []byte
	if data.AAGUID != "" {
		u, err := uuid.Parse(data.AAGUID)
		if err != nil {
			return false, "its AAGUID is not a UUID", nil
		}
		aaguid = u[:]
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.webauthn_credentials WHERE credential_id = $1)`,
		id).Scan(&exists); err != nil {
		return false, "", err
	}
	if exists {
		// Imported before: the import is idempotent, and the counter it holds
		// now is newer than the export's.
		return false, "", nil
	}
	transports := data.Transports
	if transports == nil {
		transports = []string{}
	}
	if err := store.SaveCredential(ctx, tx, userID, orgID, rpID, id, key, aaguid, uint32(max(data.Counter, 0)),
		c.Type == "webauthn-passwordless", false, false, transports, data.AttestationStatementFormat,
		c.UserLabel); err != nil {
		return false, "", fmt.Errorf("importer: saving a passkey: %w", err)
	}
	return true, "", nil
}

// importKeycloakAttribute writes a person's attribute when the organisation
// declares it, answering how many values went across: 0 for one undeclared.
func importKeycloakAttribute(ctx context.Context, tx pgx.Tx, orgID, userID, name string, values []string,
	root *keys.RootKey) (int, error) {
	var declared bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2)`, orgID, name).Scan(&declared); err != nil {
		return 0, err
	}
	if !declared || len(values) == 0 {
		return 0, nil
	}
	// One value per attribute here; the first is Keycloak's own primary.
	if err := store.SetUserAttribute(ctx, tx, userID, orgID, name, values[0], root); err != nil {
		return 0, err
	}
	return 1, nil
}

// keycloakNameIDFormats are SamlClient.java:71-89's names, as this server's.
// "username" (or anything else, there) is unspecified carrying the username,
// which has no counterpart here.
var keycloakNameIDFormats = map[string]string{"email": "emailAddress", "persistent": "persistent",
	"transient": "transient"}

// importKeycloakSAML makes a SAML client a service provider.
func importKeycloakSAML(ctx context.Context, tx pgx.Tx, orgID string, c keycloakClient, res *Result) error {
	format, ok := keycloakNameIDFormats[c.Attributes["saml_name_id_format"]]
	if c.Attributes["saml_name_id_format"] == "" {
		format, ok = "persistent", true
	}
	if !ok {
		res.ClientsSkipped = append(res.ClientsSkipped, fmt.Sprintf("SAML client %s (its NameID format %q sends "+
			"the username, which no format here does; brought across as another, every account at the service "+
			"provider would be keyed on a subject it has never seen)", c.ClientID, c.Attributes["saml_name_id_format"]))
		return nil
	}
	// SamlProtocol.java:127, then the redirect URIs Keycloak also matches.
	var acs []string
	if u := c.Attributes["saml_assertion_consumer_url_post"]; u != "" {
		acs = append(acs, u)
	}
	for _, u := range c.RedirectURIs {
		if !strings.Contains(u, "*") && !slices.Contains(acs, u) {
			acs = append(acs, u)
		}
	}
	var usable []string
	for _, u := range acs {
		if strings.HasPrefix(u, "https://") {
			usable = append(usable, u)
		} else {
			res.ClientsSkipped = append(res.ClientsSkipped, fmt.Sprintf("SAML client %s ACS %s (it carries a "+
				"signed assertion and must be https)", c.ClientID, u))
		}
	}
	if len(usable) == 0 {
		res.ClientsSkipped = append(res.ClientsSkipped, "SAML client "+c.ClientID+" (no https ACS URL)")
		return nil
	}
	name := c.Name
	if name == "" {
		name = c.ClientID
	}
	var id string
	var created bool
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name, name_id_format, enabled)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (org_id, entity_id) DO UPDATE SET display_name = core.saml_providers.display_name
		RETURNING id::text, (xmax = 0)`, orgID, c.ClientID, name, format, c.Enabled).Scan(&id, &created); err != nil {
		if strings.Contains(err.Error(), "saml_providers_entity_id_key") {
			res.ClientsSkipped = append(res.ClientsSkipped, "SAML client "+c.ClientID+
				" (another organisation registered that entity ID)")
			return nil
		}
		return fmt.Errorf("importer: SAML provider %s: %w", c.ClientID, err)
	}
	for i, u := range usable {
		if _, err := tx.Exec(ctx, `INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
			VALUES ($1::uuid, $2, 'HTTP-POST', $3) ON CONFLICT DO NOTHING`, id, u, i == 0 && created); err != nil {
			return fmt.Errorf("importer: SAML provider %s ACS %s: %w", c.ClientID, u, err)
		}
	}
	if created {
		res.SAMLProvidersCreated++
	}
	res.Dropped = append(res.Dropped, fmt.Sprintf("SAML client %s's certificates, signing settings and "+
		"attribute mappers (set them with `signari saml`)", c.ClientID))
	return nil
}

// importKeycloakClient makes an OpenID Connect client.
func importKeycloakClient(ctx context.Context, tx pgx.Tx, orgID string, c keycloakClient, hasher *passwords.Hasher,
	res *Result) error {
	// Keycloak calls the client credentials grant "service accounts", and a
	// client may have it with or without the browser flow.
	//
	// This used to import only `standardFlowEnabled` clients and hardcode
	// grant_types to authorization_code + refresh_token, which got both cases
	// wrong in opposite directions. A client with BOTH flows was created
	// without client_credentials: browser logins kept working, and its
	// machine-to-machine calls started failing `unauthorized_client` after
	// cutover -- the silent half of a migration, discovered by whichever
	// batch job ran next. A client with ONLY service accounts was skipped and
	// reported as "not using the authorization code flow", which is true and
	// beside the point, because we implement the grant it does use.
	grants := []string{}
	if c.StandardFlowEnabled {
		grants = append(grants, "authorization_code", "refresh_token")
	}
	// Confidential only. Keycloak does not permit service accounts on a public
	// client, and a public client holding no secret cannot authenticate for
	// this grant -- importing it would create exactly the unusable shape this
	// block exists to avoid.
	if c.ServiceAccountEnabled && !c.PublicClient {
		grants = append(grants, "client_credentials")
	}
	if c.ImplicitFlowEnabled {
		res.Dropped = append(res.Dropped, "client "+c.ClientID+"'s implicit flow (not implemented: tokens in a "+
			"URL fragment; it uses the code flow here)")
	}
	if c.DirectAccessGrantsEnabled {
		res.Dropped = append(res.Dropped, "client "+c.ClientID+"'s direct access grants (the password grant is "+
			"not implemented)")
	}
	for _, m := range c.ProtocolMappers {
		res.Dropped = append(res.Dropped, fmt.Sprintf("client %s's mapper %s (%s; declare a claim mapper)",
			c.ClientID, m.Name, m.ProtocolMapper))
	}
	if c.ClientID == "" || len(grants) == 0 {
		// A client using no flow we implement. Left out and said so, rather
		// than created in a shape that cannot work.
		res.ClientsSkipped = append(res.ClientsSkipped,
			c.ClientID+" (uses no flow this server implements)")
		return nil
	}

	kind := "confidential"
	if c.PublicClient {
		kind = "public"
	}
	// The application keeps the secret it already has -- that is the point of
	// the whole feature -- but it is HASHED before storage, exactly like one
	// we generated.
	//
	// The first version of this wrote the plaintext into client_secret_hash.
	// Two things were wrong with that and only one of them is obvious: a
	// plaintext secret sat in a column named `_hash`, AND the Argon2 verifier
	// correctly refused it, so every imported client silently could not
	// authenticate. "Verbatim import" meant "verbatim and unusable".
	secretHash := ""
	if c.Secret != "" {
		h, herr := hasher.Hash(ctx, c.Secret)
		if herr != nil {
			return fmt.Errorf("importer: hashing the secret for %s: %w", c.ClientID, herr)
		}
		secretHash = h
	}
	name := c.Name
	if name == "" {
		name = c.ClientID
	}
	// PKCE required, as for every client created here. This once required it
	// only of public clients, so every imported confidential client accepted
	// an authorization request with no challenge. The ones that may need an
	// opt-out are listed, not left to fail silently in either direction.
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, enabled, grant_types, scopes, require_pkce)
		VALUES ($1, $2::uuid, $7, $3, $4, $5, $6,
		        ARRAY['openid','profile','email'], true)
		ON CONFLICT (client_id) DO NOTHING`,
		c.ClientID, orgID, kind, secretHash, c.Enabled, grants, name)
	if err != nil {
		return fmt.Errorf("importer: creating client %s: %w", c.ClientID, err)
	}
	if tag.RowsAffected() == 1 && !c.PublicClient && c.StandardFlowEnabled {
		res.ClientsNowRequiringPKCE = append(res.ClientsNowRequiringPKCE, c.ClientID)
	}
	for _, u := range c.RedirectURIs {
		// An import brings somebody else's registrations, and Keycloak
		// permits shapes we do not: wildcards, and redirect URIs carrying
		// response parameters.
		//
		// SKIPPED AND REPORTED rather than fatal. A migration that dies on
		// one bad URI out of four hundred is a migration nobody finishes,
		// and the operator needs the list of what did not come across --
		// which is exactly what ClientsSkipped is.
		if verr := clients.ValidateRedirectURI(u); verr != nil {
			res.ClientsSkipped = append(res.ClientsSkipped,
				c.ClientID+" redirect "+u+" ("+verr.Error()+")")
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2) ON CONFLICT DO NOTHING`, c.ClientID, u); err != nil {
			return fmt.Errorf("importer: redirect for %s: %w", c.ClientID, err)
		}
	}
	if tag.RowsAffected() == 1 {
		res.ClientsCreated++
	}
	return nil
}

// keycloakPasswordHash extracts a usable password credential.
func keycloakPasswordHash(u keycloakUser) (string, bool) {
	for _, c := range u.Credentials {
		if c.Type != "password" || c.SecretData == "" || c.CredentialData == "" {
			continue
		}
		return passwords.EncodeKeycloak(c.CredentialData, c.SecretData), true
	}
	return "", false
}
