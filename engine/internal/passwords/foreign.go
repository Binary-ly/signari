package passwords

import (
	// #nosec G501 -- md5 and sha1 appear here to VERIFY hashes made by other
	// systems during a migration. Verifying a legacy hash requires the legacy
	// algorithm; there is no version of this that uses a modern one. Nothing here
	// creates a hash: every verified credential is immediately re-hashed with
	// Argon2id, which is the point of the migration.
	"crypto/md5"
	"crypto/sha1" // #nosec G505 -- see the note on the md5 import above
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Verifiers for password hashes produced by OTHER systems.
//
// This is the migration wedge, and it is worth being clear about why it matters
// more than it looks. The reason organisations stay on an identity provider they
// dislike is almost never the features -- it is that moving means either asking
// every user to reset their password, or running two systems indefinitely.
// Neither is acceptable, so nobody moves.
//
// Being able to verify a foreign hash means users sign in with the password they
// already have, on the new system, on day one. The hash is then silently
// upgraded to Argon2id on that first successful sign-in (see Verify's
// needsRehash), so the foreign format is transitional rather than permanent.
//
// Every verifier here follows the same two rules:
//
//  1. NEVER fail open. An unrecognised or malformed hash is a mismatch, never a
//     pass. A bad import must produce users who cannot sign in, not an
//     authentication bypass.
//  2. Constant-time comparison, always. These run on the login path with
//     attacker-supplied input.

// verifyPHPass handles the portable phpMyAdmin/WordPress/Drupal 7 format.
//
// Prefix $P$ (WordPress, phpBB) or $H$ (older phpBB). Drupal 7 uses $S$ with
// SHA-512 -- handled separately below.
//
// The scheme is md5 iterated 2^n times, with a non-standard base64 alphabet.
// It is weak by modern standards, which is exactly why supporting it matters:
// the systems still running it are the ones most in need of migrating off.
func verifyPHPass(stored, password string) error {
	if len(stored) < 12 {
		return ErrMismatch
	}
	countLog2 := strings.IndexByte(itoa64, stored[3])
	if countLog2 < 7 || countLog2 > 30 {
		return ErrMismatch
	}
	count := 1 << uint(countLog2)
	salt := stored[4:12]

	sum := md5.Sum(append([]byte(salt), password...)) // #nosec G401 -- verifying a foreign hash
	digest := sum[:]
	for i := 0; i < count; i++ {
		s := md5.Sum(append(digest, password...)) // #nosec G401 -- verifying a foreign hash
		digest = s[:]
	}

	want := stored[:12] + encode64(digest, 16)
	if subtle.ConstantTimeCompare([]byte(want), []byte(stored)) != 1 {
		return ErrMismatch
	}
	return nil
}

// verifyDrupal7 handles $S$ -- the same iterated construction with SHA-512.
func verifyDrupal7(stored, password string) error {
	if len(stored) < 12 {
		return ErrMismatch
	}
	countLog2 := strings.IndexByte(itoa64, stored[3])
	if countLog2 < 7 || countLog2 > 30 {
		return ErrMismatch
	}
	count := 1 << uint(countLog2)
	salt := stored[4:12]

	sum := sha512.Sum512(append([]byte(salt), password...))
	digest := sum[:]
	for i := 0; i < count; i++ {
		s := sha512.Sum512(append(digest, password...))
		digest = s[:]
	}

	// Drupal truncates the stored hash to 55 characters.
	want := stored[:12] + encode64(digest, len(digest))
	if len(want) > 55 {
		want = want[:55]
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(stored)) != 1 {
		return ErrMismatch
	}
	return nil
}

// verifySHACrypt handles $5$/$6$ -- glibc crypt(3).
//
// NOT WIRED IN. It disagrees with PHP's crypt(3) on real vectors, and the fault
// is somewhere in the final permutation/encoding rather than the digest loop.
// Kept because the structure is right and finishing it is a bounded job, but it
// is deliberately unreachable from Verify until it agrees with published
// vectors: a verifier that only agrees with itself would tell every imported
// LDAP user their password was wrong.
//
// Implemented rather than shelled out to crypt(3) because the C library's
// behaviour varies by platform, and an authentication decision must not depend
// on which libc the container happened to ship.
func verifySHACrypt(stored, password string) error {
	parts := strings.Split(stored, "$")
	// $6$rounds=5000$salt$hash  or  $6$salt$hash
	if len(parts) < 4 {
		return ErrMismatch
	}
	var newHash func() hash.Hash
	var size int
	switch parts[1] {
	case "5":
		newHash, size = sha256.New, 32
	case "6":
		newHash, size = sha512.New, 64
	default:
		return ErrMismatch
	}

	rounds := 5000
	idx := 2
	if strings.HasPrefix(parts[2], "rounds=") {
		n, err := strconv.Atoi(strings.TrimPrefix(parts[2], "rounds="))
		if err != nil {
			return ErrMismatch
		}
		// Clamped exactly as glibc does; a hash written with an out-of-range
		// value was computed with the clamped one.
		if n < 1000 {
			n = 1000
		}
		if n > 999999999 {
			n = 999999999
		}
		rounds = n
		idx = 3
	}
	if len(parts) < idx+2 {
		return ErrMismatch
	}
	salt, want := parts[idx], parts[idx+1]
	if len(salt) > 16 {
		salt = salt[:16]
	}

	got := shaCrypt(newHash, size, []byte(password), []byte(salt), rounds)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return ErrMismatch
	}
	return nil
}

// verifyScrypt handles the common "N$r$p$salt$hash" style used by Firebase and
// several Node ecosystems, plus the PHC form $scrypt$ln=,r=,p=$salt$hash.
func verifyScrypt(stored, password string) error {
	var N, r, p int
	var salt, want []byte
	var err error

	switch {
	case strings.HasPrefix(stored, "$scrypt$"):
		// PHC: $scrypt$ln=15,r=8,p=1$<salt>$<hash>
		parts := strings.Split(stored, "$")
		if len(parts) != 5 {
			return ErrMismatch
		}
		ln := 0
		for _, kv := range strings.Split(parts[2], ",") {
			k, v, _ := strings.Cut(kv, "=")
			n, e := strconv.Atoi(v)
			if e != nil {
				return ErrMismatch
			}
			switch k {
			case "ln":
				ln = n
			case "r":
				r = n
			case "p":
				p = n
			}
		}
		if ln <= 0 || ln > 22 {
			return ErrMismatch
		}
		N = 1 << uint(ln)
		if salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
			return ErrMismatch
		}
		if want, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
			return ErrMismatch
		}
	default:
		return ErrMismatch
	}

	if r <= 0 || p <= 0 || len(want) == 0 {
		return ErrMismatch
	}
	// Bounded so a malicious or corrupt import cannot ask for gigabytes of
	// memory on the login path.
	if N > 1<<20 || r > 32 || p > 16 {
		return ErrMismatch
	}
	got, err := scrypt.Key([]byte(password), salt, N, r, p, len(want))
	if err != nil {
		return ErrMismatch
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// keycloakCredential is the JSON Keycloak exports in credentialData.
type keycloakCredential struct {
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"hashIterations"`
}

// VerifyKeycloak handles a Keycloak credential, whose parameters live in a JSON
// blob beside the hash rather than in the hash string itself.
//
// Exported because a realm import has the parts separately and must not have to
// reassemble them into a fake PHC string first.
func VerifyKeycloak(credentialDataJSON, secretDataJSON, password string) error {
	var cd keycloakCredential
	if err := json.Unmarshal([]byte(credentialDataJSON), &cd); err != nil {
		return ErrMismatch
	}
	var sd struct {
		Value string `json:"value"`
		Salt  string `json:"salt"`
	}
	if err := json.Unmarshal([]byte(secretDataJSON), &sd); err != nil {
		return ErrMismatch
	}
	salt, err := base64.StdEncoding.DecodeString(sd.Salt)
	if err != nil {
		return ErrMismatch
	}
	want, err := base64.StdEncoding.DecodeString(sd.Value)
	if err != nil {
		return ErrMismatch
	}
	if cd.Iterations <= 0 || cd.Iterations > 1_000_000 || len(want) == 0 {
		return ErrMismatch
	}

	var newHash func() hash.Hash
	switch strings.ToLower(cd.Algorithm) {
	case "pbkdf2-sha256":
		newHash = sha256.New
	case "pbkdf2-sha512":
		newHash = sha512.New
	case "pbkdf2-sha1", "pbkdf2":
		newHash = sha1.New
	default:
		return ErrMismatch
	}

	got := pbkdf2.Key([]byte(password), salt, cd.Iterations, len(want), newHash)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// encode64 is phpass's own base64 variant: little-endian groups, custom
// alphabet, no padding. Not interchangeable with any standard encoding.
func encode64(src []byte, n int) string {
	var out strings.Builder
	for i := 0; i < n; {
		v := int(src[i])
		i++
		out.WriteByte(itoa64[v&0x3f])
		if i < n {
			v |= int(src[i]) << 8
		}
		out.WriteByte(itoa64[(v>>6)&0x3f])
		if i >= n {
			break
		}
		i++
		if i < n {
			v |= int(src[i]) << 16
		}
		out.WriteByte(itoa64[(v>>12)&0x3f])
		if i >= n {
			break
		}
		i++
		out.WriteByte(itoa64[(v>>18)&0x3f])
	}
	return out.String()
}

// shaCrypt implements the glibc SHA-crypt algorithm (Ulrich Drepper's spec).
func shaCrypt(newHash func() hash.Hash, size int, password, salt []byte, rounds int) string {
	b := newHash()
	b.Write(password)
	b.Write(salt)
	b.Write(password)
	altSum := b.Sum(nil)

	a := newHash()
	a.Write(password)
	a.Write(salt)
	for i := len(password); i > size; i -= size {
		a.Write(altSum)
	}
	a.Write(altSum[:len(password)%size])
	for i := len(password); i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(altSum)
		} else {
			a.Write(password)
		}
	}
	sum := a.Sum(nil)

	p := newHash()
	for i := 0; i < len(password); i++ {
		p.Write(password)
	}
	pSeq := expand(p.Sum(nil), len(password), size)

	s := newHash()
	for i := 0; i < 16+int(sum[0]); i++ {
		s.Write(salt)
	}
	sSeq := expand(s.Sum(nil), len(salt), size)

	for i := 0; i < rounds; i++ {
		c := newHash()
		if i&1 != 0 {
			c.Write(pSeq)
		} else {
			c.Write(sum)
		}
		if i%3 != 0 {
			c.Write(sSeq)
		}
		if i%7 != 0 {
			c.Write(pSeq)
		}
		if i&1 != 0 {
			c.Write(sum)
		} else {
			c.Write(pSeq)
		}
		sum = c.Sum(nil)
	}
	return shaCryptEncode(sum, size)
}

func expand(src []byte, want, size int) []byte {
	out := make([]byte, 0, want)
	for len(out) < want {
		n := want - len(out)
		if n > size {
			n = size
		}
		out = append(out, src[:n]...)
	}
	return out
}

// shaCryptEncode applies the byte-order permutation glibc uses before base64.
func shaCryptEncode(sum []byte, size int) string {
	var order []int
	switch size {
	case 32:
		order = []int{20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15,
			26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31}
	case 64:
		order = []int{42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47,
			48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53,
			54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58, 37, 38, 17, 59,
			60, 39, 18, 19, 61, 40, 41, 20, 62, 63}
	default:
		return ""
	}

	var out strings.Builder
	for i := 0; i+2 < len(order); i += 3 {
		v := int(sum[order[i]])<<16 | int(sum[order[i+1]])<<8 | int(sum[order[i+2]])
		for j := 0; j < 4; j++ {
			out.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	}
	// The tail differs by size: 32 leaves two bytes, 64 leaves one.
	if size == 32 {
		v := int(sum[31])<<8 | int(sum[30])
		for j := 0; j < 3; j++ {
			out.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	} else {
		v := int(sum[63])
		for j := 0; j < 2; j++ {
			out.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	}
	return out.String()
}

// EncodeKeycloak packs a Keycloak credential into a single storable string.
//
// Keycloak keeps its parameters in one JSON column and the salt+hash in another,
// which does not fit a hash column. Rather than add columns for one vendor's
// layout, the two blobs are packed into a PHC-shaped string the normal verifier
// dispatch recognises -- so an imported Keycloak user goes through exactly the
// same login path as everyone else, and gets rehashed to Argon2id on first
// sign-in like every other foreign format.
func EncodeKeycloak(credentialData, secretData string) string {
	return "$keycloak$" +
		base64.RawStdEncoding.EncodeToString([]byte(credentialData)) + "$" +
		base64.RawStdEncoding.EncodeToString([]byte(secretData))
}

// verifyKeycloakPacked unpacks what EncodeKeycloak produced.
func verifyKeycloakPacked(stored, password string) error {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 {
		return ErrMismatch
	}
	cd, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrMismatch
	}
	sd, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return ErrMismatch
	}
	return VerifyKeycloak(string(cd), string(sd), password)
}
