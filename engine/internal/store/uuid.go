package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// CanonicalUUID reads a uuid the way PostgreSQL's uuid_in does and returns it
// in canonical form (lower case, 8-4-4-4-12). ok is false exactly when
// PostgreSQL would refuse the value.
//
// The two readings have to agree. A guard that parsed ids more strictly than
// the database treated `{…}` or a hyphen every four digits as "no such row",
// while the write it guarded, casting with PostgreSQL, found the real one: a
// users:write token took over an administrator that way. Parsing in Go rather
// than asking the database also keeps a malformed id from raising an error
// that would abort the caller's transaction.
//
// The rule, as uuid_in applies it: an optional brace pair around the whole
// value; 32 hexadecimal digits in either case; at most one hyphen, and only
// after a group of four digits, never after the last.
func CanonicalUUID(s string) (string, bool) {
	if strings.HasPrefix(s, "{") {
		if !strings.HasSuffix(s, "}") || len(s) < 2 {
			return "", false
		}
		s = s[1 : len(s)-1]
	}
	hex := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			hex = append(hex, c)
		case c >= 'A' && c <= 'F':
			hex = append(hex, c+('a'-'A'))
		case c == '-':
			// After a whole group of four, not at the start or the end, and
			// not twice in a row.
			if len(hex) == 0 || len(hex)%4 != 0 || len(hex) == 32 || s[i-1] == '-' {
				return "", false
			}
		default:
			return "", false
		}
		if len(hex) > 32 {
			return "", false
		}
	}
	if len(hex) != 32 || strings.HasSuffix(s, "-") {
		return "", false
	}
	h := string(hex)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], true
}

// ExactUUID says whether s is a uuid as the database writes one, which is what
// `id::text = $1` asked, and lets the question go to the column itself. Through
// its text a uuid column can use no index, its primary key included, so every
// such lookup read the whole table (0.53); cast instead, a malformed id is an
// error from the driver rather than nobody, and an upstream retries a 500
// forever.
//
// Stricter than PostgreSQL reads a uuid, which CanonicalUUID warns about in a
// guard. Here nothing follows a refusal: the id reaches no statement at all,
// so no write can find the row the guard said was not there.
func ExactUUID(s string) bool {
	canonical, ok := CanonicalUUID(s)
	return ok && canonical == s
}

// ExactUUIDOrNil is s as a bind for a uuid column: NULL, which matches nobody,
// when it cannot be one.
func ExactUUIDOrNil(s string) *string {
	if !ExactUUID(s) {
		return nil
	}
	return &s
}

// OrgOfUser reads which organisation a person belongs to. pgx.ErrNoRows when
// there is no such person, as for an id that could not be one.
func OrgOfUser(ctx context.Context, q rowQuerier, userID string) (string, error) {
	if !ExactUUID(userID) {
		return "", pgx.ErrNoRows
	}
	var orgID string
	err := q.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID)
	return orgID, err
}
