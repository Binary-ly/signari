package store

import "strings"

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
