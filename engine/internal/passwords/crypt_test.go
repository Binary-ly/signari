package passwords

import (
	"context"
	"crypto/fips140"
	"crypto/sha256"
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

// The SHA-2 schemes against OpenLDAP's own pw-sha2 module: `slappasswd -o
// module-load=pw-sha2 -h <scheme> -s <pw>` from slapd-contrib 2.5.13+dfsg-5
// (Debian bookworm), whose salts are random, so each vector is one it made.
// The second password is not ASCII; its UTF-8 bytes are what was hashed.
var sha2LDAPVectors = []struct{ password, stored string }{
	{"correct horse", "{SHA256}QQTTb42iwlQ0n4WDZ5Pr4CngyVcGOjTJHC6SAxh7VjE="},
	{"correct horse", "{SSHA256}mkZXlgKyZzjfJNae0Q1FD0JhZolUtJAzo+Pn8UQbPQZgOvBRzMBeAw=="},
	{"correct horse", "{SHA384}ArIKby67E2Cppg9M+QhXNj7UGcAisSFWfOX5HG45Zk+3j9YCNMSli1v8cUWumDKS"},
	{"correct horse", "{SSHA384}wAVbWNToqX30uUQhq/ynCz4ag3p75DqPY5vcLc9ho3bqp6OlE/Fb3yGIuyZ/OF4mA0qlD2mkw20="},
	{"correct horse", "{SHA512}VraY3v7bWkNbY0r+MyC7rz/c2SC2xQOkRvx7endrKY1HnRumqLYXgI6wv1ec6aldZoNHvKtxSQhayTyyeZUZew=="},
	{"correct horse", "{SSHA512}X5RfBvr6fmy8SJK7Qi2X4yrF8gQpzPIS29kNEnKs6KfYCzS3EodFcqGP0WgwH3MV8/Qq+khhAKbCGu5+9L91nHhw05F0PnRM"},
	{"pässwörd-ünïcode", "{SHA256}NUUDWWRQXV8R0aRrVKI5NDsA8nj3T47Z3s/sShcqUpc="},
	{"pässwörd-ünïcode", "{SSHA256}l95GVcidO3DV9HSOi0zlBa0VRrboeQyVNqpIhYaswRp7J5P50NFaSg=="},
	{"pässwörd-ünïcode", "{SHA384}s6wYSxIi1AxpBZuTyLAzfjV1OsKnokxq5GB61LLGXTAidDUKgdnRyu+4NtiEMp6B"},
	{"pässwörd-ünïcode", "{SSHA384}aqeV3SX7rDheK7xT0izIvjODgNsH7HmaeGm8Kjdjyulsz39dBa/d5O2eO5fjr6JY62UkLEYrxf0="},
	{"pässwörd-ünïcode", "{SHA512}Vv4ZvOqCGC3P/uqGmo6wqu2cQy9DMHIKoNu992v25y7X9dbryPj0oA4uzccik4RP2AIR2GJ0T2NUfiSiFg+6Wg=="},
	{"pässwörd-ünïcode", "{SSHA512}qQbHfbSMgr9+xR/122VACBFYizVs+oJ8D4ovliV1SFiGDEFLnphKLnZ5eLQVy0sUJKh/JYquYxFNfH9s7fO1U6tqjhJTjHFH"},
	{"x", "{SHA256}LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE="},
	{"x", "{SSHA256}H9d6CaXpGPEXSr0yZuNfZKmvO0Racq/zn2zMVhfZnGsQ6H4qR5/wBg=="},
	{"x", "{SHA384}11LCxR+6DimqGQVwqdQlPkQHegWNMpf6OlYw1b0BJiL5fCisrtMTtcg7uZDKp9qF"},
	{"x", "{SSHA384}aHZwA6jUD0gRPhl5nknp/6tUQsFh5apdkMDpRcI2/wxQXmwZeBkNRq5QiRf19BBJ2SoWQRO4ymw="},
	{"x", "{SHA512}pKvURIxJVi2CgRXROh/M6pJ/UrTVRZKX+LQ+QtqJI4vBNibkPcs43bCCSIkn7JBPtCBXRDmD6IWFF51QVRr+Yg=="},
	{"x", "{SSHA512}SSAtUv7J42Jz5Bc2qxFMOn7000pQ8uwdrAUzKqV/0EKtTLHjv235tlFnBtvSi5J1NV9wtO1EftGxwI1xVNO5ZrP4Yvh+Zaaj"},
}

func TestTheSHA2LDAPSchemes(t *testing.T) {
	h := NewHasher(MemoryBudgetMiB)
	ctx := context.Background()
	for _, v := range sha2LDAPVectors {
		if !CanVerify(v.stored) {
			t.Errorf("CanVerify says no to %.12s", v.stored)
		}
		if _, err := h.Verify(ctx, v.stored, v.password); err != nil {
			t.Errorf("%.12s with %q: %v", v.stored, v.password, err)
		}
		if _, err := h.Verify(ctx, v.stored, v.password+"x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("%.12s verified the wrong password", v.stored)
		}
	}
	plain256 := sha256.Sum256([]byte("Hello world!"))
	// An unsalted scheme with bytes after the digest is not that scheme.
	padded := "{SHA256}" + base64.StdEncoding.EncodeToString(append(plain256[:], 'x'))
	if _, err := h.Verify(ctx, padded, "Hello world!"); err == nil {
		t.Error("an unsalted digest with a tail verified")
	}
}
