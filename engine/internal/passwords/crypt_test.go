package passwords

import (
	"context"
	"crypto/fips140"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// md5-crypt, apr1 and the LDAP schemes against vectors other implementations
// made (4.09): `openssl passwd -1|-apr1 -salt <s> <pw>` (OpenSSL 3.6.3, with
// PHP 8.4.18's crypt() giving the same $1$ answers) and OpenLDAP's
// `/usr/sbin/slappasswd -s <pw> -h <scheme>`, whose salts are random, so each
// vector is one it made. {CRYPT} wraps the OpenSSL ones; slappasswd's own
// {CRYPT} on this host falls back to DES, which nothing here reads.
const sixtyFour = "this is a password that is exactly sixty-four bytes long!!!!!!!!"

var unixAndLDAPVectors = []struct{ password, stored string }{
	{"a", "$1$saltsalt$MzDjbImyzEz2m0NTiPzNW/"},
	{"a", "$1$abcdefgh$jUYc1Xi7pkozuzWQ0Dft71"},
	{"Hello world!", "$1$saltsalt$le8lFSqqnPaRFOlmAZpvH1"},
	{"Hello world!", "$1$abcdefgh$fzmjzFdo5nMtBG8gtud5e0"},
	{sixtyFour, "$1$saltsalt$KM5G.Cn4ZQpFwQcKdUnkI0"},
	{sixtyFour, "$1$abcdefgh$sV6NVyjZxk2FJ63g2uapf."},
	{"a", "$apr1$saltsalt$OEnK0QmmvoDzFw9W2yFYT/"},
	{"Hello world!", "$apr1$saltsalt$6BwcdpRros16.J9J/tHRr/"},
	{"Hello world!", "$apr1$abcdefgh$Unf1zc.jsgCbBQDCL104q."},
	{sixtyFour, "$apr1$abcdefgh$kjHeyNrJDvdo271Jy1DTa/"},
	{"a", "{SSHA}rRweplXyHQWBXpQrTMgjabA0wxv6hkAk"},
	{"Hello world!", "{SSHA}bYlKV0AdVWg4keIMOSdsx2xa6kXqaaZ5"},
	{sixtyFour, "{SSHA}eB73QDi2hP0Nu+7zlj0TBcRplHugI6Ts"},
	{"a", "{SHA}hvfkN/qlp/zhXR3cuerq6jd2Z7g="},
	{"Hello world!", "{SHA}00hq6RNueFa8QiEjhep5cJRHWAI="},
	{"a", "{SMD5}w1IgxTMmBaShE3slTaAG7oRzL9U="},
	{"Hello world!", "{SMD5}oJ2EUEbqgcz1zLKZs6sAaOpIY4Y="},
	{"a", "{MD5}DMF1ucDxtqgxw5niaXcmYQ=="},
	{"Hello world!", "{MD5}hvsmnRkNLIX24EaM7KQqIA=="},
	{"Hello world!", "{crypt}$1$saltsalt$le8lFSqqnPaRFOlmAZpvH1"},
	{"Hello world!", "{CRYPT}$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
}

func TestUnixAndLDAPHashesAgreeWithOtherImplementations(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("MD5 and SHA-1, which fips140=only refuses")
	}
	h := NewHasher(MemoryBudgetMiB)
	ctx := context.Background()
	for _, v := range unixAndLDAPVectors {
		if !CanVerify(v.stored) {
			t.Errorf("CanVerify says no to %.30s...", v.stored)
		}
		rehash, err := h.Verify(ctx, v.stored, v.password)
		if err != nil || !rehash {
			t.Errorf("%.30s... with %q: rehash %v, %v", v.stored, v.password, rehash, err)
		}
		if _, err := h.Verify(ctx, v.stored, v.password+"x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("%.30s... verified the wrong password", v.stored)
		}
	}
}

// Under fips140=only the MD5 and SHA-1 schemes are refused, by name, and
// nothing panics; SHA-crypt and the SHA-2 schemes still verify.
func TestTheWeakSchemesAreRefusedUnderFIPS(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTheWeakSchemesAreRefusedUnderFIPS$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	h := NewHasher(MemoryBudgetMiB)
	ctx := context.Background()
	for _, stored := range []string{"$1$saltsalt$le8lFSqqnPaRFOlmAZpvH1",
		"$apr1$saltsalt$6BwcdpRros16.J9J/tHRr/", "{SSHA}bYlKV0AdVWg4keIMOSdsx2xa6kXqaaZ5",
		"{MD5}hvsmnRkNLIX24EaM7KQqIA=="} {
		_, err := h.Verify(ctx, stored, "Hello world!")
		if !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "FIPS") {
			t.Errorf("%.20s under fips140=only: %v; want a refusal saying why", stored, err)
		}
	}
	if _, err := h.Verify(ctx, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
		"Hello world!"); err != nil {
		t.Errorf("SHA-crypt under fips140=only: %v", err)
	}
}

// The SHA-2 schemes have no slappasswd here (OpenLDAP's pw-sha2 module is not
// installed), so their vectors are composed from the {SSHA} construction with
// the standard library's digests: base64 of H(password + salt) + salt.
func TestTheSHA2LDAPSchemes(t *testing.T) {
	h := NewHasher(MemoryBudgetMiB)
	ctx := context.Background()
	salt := []byte("pepper-free salt")
	sum256 := sha256.Sum256(append([]byte("Hello world!"), salt...))
	sum512 := sha512.Sum512(append([]byte("Hello world!"), salt...))
	plain256 := sha256.Sum256([]byte("Hello world!"))
	for _, stored := range []string{
		"{SSHA256}" + base64.StdEncoding.EncodeToString(append(sum256[:], salt...)),
		"{SSHA512}" + base64.StdEncoding.EncodeToString(append(sum512[:], salt...)),
		"{SHA256}" + base64.StdEncoding.EncodeToString(plain256[:]),
	} {
		if _, err := h.Verify(ctx, stored, "Hello world!"); err != nil {
			t.Errorf("%.12s: %v", stored, err)
		}
		if _, err := h.Verify(ctx, stored, "Hello world"); !errors.Is(err, ErrMismatch) {
			t.Errorf("%.12s verified the wrong password", stored)
		}
	}
	// An unsalted scheme with bytes after the digest is not that scheme.
	padded := "{SHA256}" + base64.StdEncoding.EncodeToString(append(plain256[:], 'x'))
	if _, err := h.Verify(ctx, padded, "Hello world!"); err == nil {
		t.Error("an unsalted digest with a tail verified")
	}
}
