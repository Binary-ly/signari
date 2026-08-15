package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/passwords"
)

// Importing from authentik.
//
// # Why the password hashes come across
//
// authentik is a Django application and does not set PASSWORD_HASHERS, so
// Django's defaults apply and the first of those -- the one used for every
// password set -- is PBKDF2PasswordHasher, which writes
//
//	pbkdf2_sha256$<iterations>$<salt>$<base64 hash>
//
// internal/passwords already verifies that format, because it is common to a
// great deal of Python software. So an authentik user signs in here with the
// password they already had, and is transparently upgraded to Argon2id on first
// success. Nobody has to reset anything.
//
// # Why a dumpdata file rather than the API
//
// authentik's REST API never returns password hashes -- Django does not expose
// them, correctly. The portable export that does is Django's own:
//
//	ak dumpdata authentik_core.User authentik_core.Group > authentik.json
//
// That is a documented Django management command, not a private interface.
//
// # Honesty about what this has been tested against
//
// Built against the documented `dumpdata` shape. Field names below are what
// Django emits for these models; a version that renames one will be REPORTED as
// a skipped user rather than silently imported without a credential, and
// `-dry-run` prints exactly what was parsed. Run that first.

// authentikRecord is one row of a Django dumpdata file.
type authentikRecord struct {
	Model  string          `json:"model"`
	PK     any             `json:"pk"`
	Fields json.RawMessage `json:"fields"`
}

type authentikUserFields struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	IsActive bool   `json:"is_active"`
	UUID     string `json:"uuid"`
	// Group membership, as primary keys into the group records.
	Groups []any `json:"ak_groups"`
}

type authentikGroupFields struct {
	Name        string `json:"name"`
	IsSuperuser bool   `json:"is_superuser"`
}

// AuthentikExport is a parsed dumpdata file.
type AuthentikExport struct {
	Users  []AuthentikUser
	Groups map[string]string // pk -> group name
}

// AuthentikUser is one imported person.
type AuthentikUser struct {
	Username string
	Name     string
	Email    string
	Password string
	IsActive bool
	Groups   []string
}

// ParseAuthentik reads a Django dumpdata export.
func ParseAuthentik(r io.Reader) (*AuthentikExport, error) {
	var records []authentikRecord
	if err := json.NewDecoder(r).Decode(&records); err != nil {
		return nil, fmt.Errorf("importer: reading the authentik export: %w "+
			"(expected the JSON array Django's `ak dumpdata` produces)", err)
	}

	out := &AuthentikExport{Groups: map[string]string{}}
	groupsByPK := map[string]string{}

	// Groups first: a user record references them by primary key, and a single
	// pass would resolve names only for groups that happened to appear earlier.
	for _, rec := range records {
		if !strings.EqualFold(rec.Model, "authentik_core.group") {
			continue
		}
		var g authentikGroupFields
		if err := json.Unmarshal(rec.Fields, &g); err != nil {
			continue
		}
		if g.Name != "" {
			groupsByPK[fmt.Sprint(rec.PK)] = g.Name
		}
	}
	out.Groups = groupsByPK

	for _, rec := range records {
		if !strings.EqualFold(rec.Model, "authentik_core.user") {
			continue
		}
		var f authentikUserFields
		if err := json.Unmarshal(rec.Fields, &f); err != nil {
			continue
		}
		u := AuthentikUser{
			Username: f.Username,
			Name:     f.Name,
			Email:    f.Email,
			Password: f.Password,
			IsActive: f.IsActive,
		}
		for _, pk := range f.Groups {
			if name, ok := groupsByPK[fmt.Sprint(pk)]; ok {
				u.Groups = append(u.Groups, name)
			}
		}
		out.Users = append(out.Users, u)
	}

	if len(out.Users) == 0 {
		return nil, fmt.Errorf("importer: no authentik_core.user records found. " +
			"Export with `ak dumpdata authentik_core.User authentik_core.Group`")
	}
	return out, nil
}

// AuthentikResult reports what an import did.
type AuthentikResult struct {
	UsersCreated  int
	UsersUpdated  int
	UsersSkipped  []string
	GroupsCreated int
	// HashFormats counts what was seen, so an operator learns immediately if
	// this deployment stores something we cannot verify -- rather than finding
	// out when people cannot sign in.
	HashFormats map[string]int
}

// ImportAuthentik creates users and groups from a parsed export.
//
// One transaction, for the same reason as the Keycloak importer: a half-imported
// directory is the worst outcome, because nobody can tell which half.
func ImportAuthentik(ctx context.Context, tx pgx.Tx, orgID string, exp *AuthentikExport,
	dryRun bool) (*AuthentikResult, error) {

	res := &AuthentikResult{HashFormats: map[string]int{}}

	// Groups first, so membership can reference them.
	groupIDs := map[string]string{}
	for _, name := range exp.Groups {
		if dryRun {
			res.GroupsCreated++
			continue
		}
		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, $2, $2)
			ON CONFLICT (org_id, name) DO UPDATE SET display_name = EXCLUDED.display_name
			RETURNING id::text`, orgID, name).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("importing group %q: %w", name, err)
		}
		groupIDs[name] = id
		res.GroupsCreated++
	}

	for _, u := range exp.Users {
		identifier := u.Email
		if identifier == "" {
			identifier = u.Username
		}
		if identifier == "" {
			res.UsersSkipped = append(res.UsersSkipped, "(a user with no username or email)")
			continue
		}

		res.HashFormats[hashFormatName(u.Password)]++

		if !u.IsActive {
			// Inactive there means inactive here. Importing them as active would
			// silently re-enable accounts somebody deliberately turned off.
			res.UsersSkipped = append(res.UsersSkipped, identifier+" (inactive in authentik)")
			continue
		}
		if !passwords.CanVerify(u.Password) {
			// Named rather than imported without a credential. An account nobody
			// can sign in to is worse than one that was refused out loud.
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf(
				"%s (password format %q cannot be verified here; they must use "+
					"recovery or delegated sign-in)", identifier, hashFormatName(u.Password)))
			continue
		}

		if dryRun {
			res.UsersCreated++
			continue
		}

		var userID string
		created := true
		// Conflict target mirrors users_org_email_key exactly -- a PARTIAL unique
		// index on (org_id, lower(email)). Anything less specific and PostgreSQL
		// cannot use the index, so the import dies on the first existing user,
		// which is precisely the re-run an idempotent importer exists to allow.
		err := tx.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, username, user_handle, migration_state)
			VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''),
			        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
			        'pending')
			ON CONFLICT (org_id, lower(email)) WHERE email IS NOT NULL
			DO UPDATE SET username = COALESCE(EXCLUDED.username, core.users.username),
			              updated_at = now()
			RETURNING id::text, (xmax = 0)`,
			orgID, u.Email, u.Username).Scan(&userID, &created)
		if err != nil {
			return nil, fmt.Errorf("importing user %q: %w", identifier, err)
		}
		if created {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}

		// is_current = false and migration_state = 'pending' on purpose: that is
		// what routes this credential through the migration path, where the
		// Django hash is verified on first sign-in and replaced with Argon2id in
		// the same transaction. Storing it as current instead would work and
		// would quietly bypass the rehash, leaving a foreign hash in place
		// forever.
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.password_credentials
				(user_id, org_id, hash, algorithm, source_system, is_current)
			VALUES ($1::uuid, $2::uuid, $3, 'django-pbkdf2', 'authentik', false)
			ON CONFLICT (user_id) DO UPDATE SET
				hash = EXCLUDED.hash, algorithm = 'django-pbkdf2',
				source_system = 'authentik', is_current = false, updated_at = now()`,
			userID, orgID, u.Password); err != nil {
			return nil, fmt.Errorf("importing the password for %q: %w", identifier, err)
		}

		for _, g := range u.Groups {
			gid, ok := groupIDs[g]
			if !ok {
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.group_members (group_id, user_id, org_id)
				VALUES ($1::uuid, $2::uuid, $3::uuid) ON CONFLICT DO NOTHING`,
				gid, userID, orgID); err != nil {
				return nil, fmt.Errorf("adding %q to group %q: %w", identifier, g, err)
			}
		}
	}
	return res, nil
}

// hashFormatName names a stored hash's format for reporting.
//
// Reported rather than guessed at: "we imported 400 users" means nothing if 380
// of them carry a format nothing here can check.
//
// The verifiable/not verdict comes from passwords.CanVerify rather than from a
// second list here. A first version kept its own prefixes and got one wrong --
// it tested for "argon2" where the stored form is "$argon2id$" -- so a perfectly
// importable hash was reported as unrecognised, which would send an operator
// into a cutover planning password resets nobody needed.
func hashFormatName(stored string) string {
	verdict := " (NOT verifiable here)"
	if passwords.CanVerify(stored) {
		verdict = " (verifiable)"
	}

	switch {
	case stored == "":
		return "(none)"
	case strings.HasPrefix(stored, "!"):
		// Django's marker for "no usable password": a user who only ever signed
		// in through a federated source, or whose password was disabled.
		return "unusable (federated or never set)"
	case strings.HasPrefix(stored, "pbkdf2_sha256$"):
		return "pbkdf2_sha256, Django default" + verdict
	case strings.HasPrefix(stored, "$argon2"):
		return "argon2" + verdict
	case strings.HasPrefix(stored, "$2a$"), strings.HasPrefix(stored, "$2b$"),
		strings.HasPrefix(stored, "$2y$"):
		return "bcrypt" + verdict
	case strings.HasPrefix(stored, "scrypt$"):
		// Django's own scrypt hasher, which is NOT the "$scrypt$" form this
		// engine verifies. Different encodings with confusingly similar names.
		return "scrypt, Django variant" + verdict
	default:
		if i := strings.Index(stored, "$"); i > 0 {
			return stored[:i] + verdict
		}
		return "unrecognised" + verdict
	}
}
