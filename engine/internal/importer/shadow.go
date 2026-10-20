package importer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/passwords"
)

// An /etc/shadow file (4.09): name:hash:..., one account a line. The hashes
// are crypt(3) -- SHA-crypt ($5$, $6$) on any current distribution, md5-crypt
// ($1$) on old ones -- and verify as they are at the first sign-in, which
// replaces them with Argon2id, as every imported hash does.

// ShadowEntry is one line's account.
type ShadowEntry struct {
	Name, Hash string
}

// shadowName is what a Unix login may be, by the portable filename set POSIX
// gives user names. Anything else is not an account this file is describing.
var shadowName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)

// ParseShadow reads a shadow file. A line that is not name:hash:... is an
// error naming its number: a misread file is not imported in part.
func ParseShadow(r io.Reader) ([]ShadowEntry, error) {
	var out []ShadowEntry
	s := bufio.NewScanner(r)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 || !shadowName.MatchString(fields[0]) {
			return nil, fmt.Errorf("line %d is not a shadow entry (name:hash:...)", n)
		}
		out = append(out, ShadowEntry{Name: fields[0], Hash: fields[1]})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("importer: no shadow entries found")
	}
	return out, nil
}

// ShadowResult reports what an import did.
type ShadowResult struct {
	UsersCreated, UsersUpdated int
	UsersSkipped               []string
	HashFormats                map[string]int
}

// ImportShadow creates an account for each entry with a password: the name as
// the username, and name@domain as the address when a domain is given. An
// entry with no password (`!`, `*`, empty: a locked or system account) is
// skipped and named, as is one whose hash cannot be verified here. One
// transaction, as the other importers: a half-imported directory is the worst
// outcome, because nobody can tell which half.
func ImportShadow(ctx context.Context, tx pgx.Tx, orgID string, entries []ShadowEntry,
	domain string, dryRun bool) (*ShadowResult, error) {

	res := &ShadowResult{HashFormats: map[string]int{}}
	for _, e := range entries {
		switch {
		case e.Hash == "" || strings.HasPrefix(e.Hash, "!") || strings.HasPrefix(e.Hash, "*"):
			res.HashFormats["no password (locked or a system account)"]++
			res.UsersSkipped = append(res.UsersSkipped, e.Name+" (no password: locked or a system account)")
			continue
		case !passwords.CanVerify(e.Hash):
			res.HashFormats[cryptFormat(e.Hash)+" (NOT verifiable here)"]++
			reason := "its hash format cannot be verified here"
			if err := passwords.CostRefusal(e.Hash); err != nil {
				reason = fmt.Sprintf("its hash costs more than this server verifies: %v", err)
			}
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("%s (%s)", e.Name, reason))
			continue
		}
		res.HashFormats[cryptFormat(e.Hash)+" (verifiable)"]++
		if dryRun {
			res.UsersCreated++
			continue
		}
		email := ""
		if domain != "" {
			email = e.Name + "@" + domain
		}
		var userID string
		created := true
		err := tx.QueryRow(ctx, `
			WITH found AS (
				SELECT id FROM core.users
				 WHERE org_id = $1::uuid AND lower(username) = lower($3)
			), made AS (
				INSERT INTO core.users (org_id, email, username, user_handle, migration_state)
				SELECT $1::uuid, NULLIF($2,''), $3,
				       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
				              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
				       'pending'
				 WHERE NOT EXISTS (SELECT 1 FROM found)
				RETURNING id
			)
			SELECT id::text, true FROM made
			UNION ALL SELECT id::text, false FROM found`,
			orgID, email, e.Name).Scan(&userID, &created)
		if err != nil {
			return nil, fmt.Errorf("importing %q: %w", e.Name, err)
		}
		if created {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}
		// Not current and pending, as the other importers store theirs: the
		// first sign-in verifies the crypt hash and replaces it with Argon2id.
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.password_credentials
				(user_id, org_id, hash, algorithm, source_system, is_current)
			VALUES ($1::uuid, $2::uuid, $3, 'crypt', 'shadow', false)
			ON CONFLICT (user_id) DO UPDATE SET
				hash = EXCLUDED.hash, algorithm = 'crypt',
				source_system = 'shadow', is_current = false, updated_at = now()`,
			userID, orgID, e.Hash); err != nil {
			return nil, fmt.Errorf("importing the password for %q: %w", e.Name, err)
		}
	}
	return res, nil
}

// cryptFormat names a crypt(3) hash's format for the census.
func cryptFormat(h string) string {
	switch {
	case strings.HasPrefix(h, "$6$"):
		return "SHA-512 crypt ($6$)"
	case strings.HasPrefix(h, "$5$"):
		return "SHA-256 crypt ($5$)"
	case strings.HasPrefix(h, "$1$"):
		return "MD5 crypt ($1$)"
	case strings.HasPrefix(h, "$y$"), strings.HasPrefix(h, "$7$"):
		return "yescrypt/scrypt crypt (" + h[:3] + ")"
	case strings.HasPrefix(h, "$2"):
		return "bcrypt"
	default:
		if i := strings.Index(h[1:], "$"); strings.HasPrefix(h, "$") && i > 0 {
			return h[:i+2]
		}
		return "DES or unrecognised"
	}
}
