package passwords

import "strings"

// AlgorithmOf names what a hash Hasher.Hash made is, for the algorithm column beside
// it: Argon2id, or PBKDF2-SHA256 when FIPS is on (see Hasher.Hash). Every writer used
// to record "argon2id" whatever it stored, so under FIPS the column misstated every
// password changed or rehashed.
func AlgorithmOf(hash string) string {
	if strings.HasPrefix(hash, "$pbkdf2-sha256$") {
		return "pbkdf2-sha256"
	}
	return "argon2id"
}
