package passwords

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"strings"
)

// The Unix and LDAP hash families a directory being migrated off holds (4.09):
// md5-crypt (`$1$`, and Apache's `$apr1$`), and the LDAP userPassword schemes
// `{SSHA}`, `{SHA}`, `{SMD5}`, `{MD5}`, their SHA-2 forms, and `{CRYPT}`, which
// wraps any crypt(3) hash. glibc SHA-crypt (`$5$`, `$6$`) is in foreign.go.
// Each is checked against vectors another implementation produced
// (crypt_test.go); a verifier that agrees only with itself would tell every
// imported person their password was wrong.

// verifyMD5Crypt handles `$1$salt$hash` and `$apr1$salt$hash`: the same
// algorithm under two magic strings, salt at most eight characters.
func verifyMD5Crypt(stored, password string) error {
	magic := "$1$"
	if strings.HasPrefix(stored, "$apr1$") {
		magic = "$apr1$"
	}
	rest := strings.TrimPrefix(stored, magic)
	salt, want, ok := strings.Cut(rest, "$")
	if !ok || want == "" || strings.Contains(want, "$") {
		return ErrMismatch
	}
	if len(salt) > 8 {
		salt = salt[:8]
	}
	if subtle.ConstantTimeCompare([]byte(md5Crypt([]byte(password), []byte(salt), magic)), []byte(want)) != 1 {
		return ErrMismatch
	}
	return nil
}

// md5Crypt is the algorithm FreeBSD's crypt(3) introduced and glibc, OpenSSL
// and Apache share.
func md5Crypt(password, salt []byte, magic string) string {
	alt := md5.New()
	alt.Write(password)
	alt.Write(salt)
	alt.Write(password)
	final := alt.Sum(nil)

	ctx := md5.New()
	ctx.Write(password)
	ctx.Write([]byte(magic))
	ctx.Write(salt)
	for left := len(password); left > 0; left -= 16 {
		ctx.Write(final[:min(left, 16)])
	}
	for i := len(password); i > 0; i >>= 1 {
		if i&1 != 0 {
			ctx.Write([]byte{0})
		} else {
			ctx.Write(password[:1])
		}
	}
	final = ctx.Sum(nil)

	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 != 0 {
			c.Write(password)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write(salt)
		}
		if i%7 != 0 {
			c.Write(password)
		}
		if i&1 != 0 {
			c.Write(final)
		} else {
			c.Write(password)
		}
		final = c.Sum(nil)
	}

	var out strings.Builder
	put := func(v, n int) {
		for ; n > 0; n-- {
			out.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	}
	for _, g := range [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		put(int(final[g[0]])<<16|int(final[g[1]])<<8|int(final[g[2]]), 4)
	}
	put(int(final[11]), 2)
	return out.String()
}

// ldapScheme is one LDAP userPassword scheme: the digest, and whether a salt
// follows the digest inside the base64.
type ldapScheme struct {
	newHash func() hash.Hash
	size    int
	salted  bool
	// weak is a scheme built on MD5 or SHA-1, which FIPS 140-only mode refuses.
	weak bool
}

var ldapSchemes = map[string]ldapScheme{
	"{SSHA}":    {sha1.New, sha1.Size, true, true},
	"{SHA}":     {sha1.New, sha1.Size, false, true},
	"{SMD5}":    {md5.New, md5.Size, true, true},
	"{MD5}":     {md5.New, md5.Size, false, true},
	"{SSHA256}": {sha256.New, sha256.Size, true, false},
	"{SHA256}":  {sha256.New, sha256.Size, false, false},
	"{SSHA512}": {sha512.New, sha512.Size, true, false},
	"{SHA512}":  {sha512.New, sha512.Size, false, false},
}

// ldapSchemeOf is the scheme a stored LDAP hash names, its base64, and
// whether it names one. Scheme names are case-insensitive in LDAP.
func ldapSchemeOf(stored string) (string, ldapScheme, string, bool) {
	end := strings.IndexByte(stored, '}')
	if !strings.HasPrefix(stored, "{") || end < 0 {
		return "", ldapScheme{}, "", false
	}
	name := strings.ToUpper(stored[:end+1])
	s, ok := ldapSchemes[name]
	return name, s, stored[end+1:], ok
}

// verifyLDAP handles the digest schemes: base64 of H(password + salt) + salt,
// or of H(password) unsalted.
func verifyLDAP(s ldapScheme, encoded, password string) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < s.size || (!s.salted && len(raw) != s.size) {
		return ErrMismatch
	}
	digest, salt := raw[:s.size], raw[s.size:]
	h := s.newHash()
	h.Write([]byte(password))
	h.Write(salt)
	if subtle.ConstantTimeCompare(h.Sum(nil), digest) != 1 {
		return ErrMismatch
	}
	return nil
}

// cryptOf unwraps `{CRYPT}` (case-insensitive), the LDAP scheme that holds a
// crypt(3) hash as it is.
func cryptOf(stored string) (string, bool) {
	if len(stored) > 7 && strings.EqualFold(stored[:7], "{CRYPT}") {
		return stored[7:], true
	}
	return stored, false
}
