package importer

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"signari.dev/engine/internal/passwords"
)

// djangoPBKDF2 produces a hash in exactly the format Django writes, which is
// what authentik stores: it does not set PASSWORD_HASHERS, so Django's default
// PBKDF2PasswordHasher applies.
func djangoPBKDF2(password, salt string, iterations int) string {
	dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	return "pbkdf2_sha256$" + itoa(iterations) + "$" + salt + "$" +
		base64.StdEncoding.EncodeToString(dk)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

const authentikExport = `[
 {"model":"authentik_core.group","pk":"11111111-1111-1111-1111-111111111111",
  "fields":{"name":"engineering","is_superuser":false}},
 {"model":"authentik_core.user","pk":1,
  "fields":{"username":"akadmin","name":"Admin","email":"akadmin@authentik.test",
            "password":"PLACEHOLDER","is_active":true,
            "ak_groups":["11111111-1111-1111-1111-111111111111"]}},
 {"model":"authentik_core.user","pk":2,
  "fields":{"username":"inactive","email":"gone@authentik.test",
            "password":"PLACEHOLDER","is_active":false,"ak_groups":[]}},
 {"model":"authentik_core.user","pk":3,
  "fields":{"username":"ssoonly","email":"sso@authentik.test",
            "password":"!","is_active":true,"ak_groups":[]}},
 {"model":"authentik_core.token","pk":9,"fields":{"identifier":"unrelated"}}
]`

// TestTheHashFormatAuthentikStoresIsVerifiableHere.
//
// The whole migration claim rests on this one fact: authentik is a Django app
// that does not set PASSWORD_HASHERS, so passwords are written by Django's
// default PBKDF2PasswordHasher, and this engine already verifies that format.
// If it ever stops being true, "nobody has to reset a password" becomes a lie,
// so it is asserted rather than believed.
func TestTheHashFormatAuthentikStoresIsVerifiableHere(t *testing.T) {
	stored := djangoPBKDF2("the-original-password", "abcdefghijkl", 600000)

	if !strings.HasPrefix(stored, "pbkdf2_sha256$") {
		t.Fatalf("test fixture is not in Django's format: %q", stored)
	}
	if !passwords.CanVerify(stored) {
		t.Fatal("this engine cannot verify the format authentik stores; the whole " +
			"import story depends on it")
	}

	h := passwords.NewHasher(passwords.MemoryBudgetMiB)
	needsRehash, err := h.Verify(t.Context(), stored, "the-original-password")
	if err != nil {
		t.Fatalf("a correct authentik password did not verify: %v", err)
	}
	if !needsRehash {
		t.Error("a foreign hash did not ask to be rehashed; it would stay Django " +
			"forever instead of becoming Argon2id on first sign-in")
	}
	if _, err := h.Verify(t.Context(), stored, "the-wrong-password"); err == nil {
		t.Error("a wrong password verified against an imported hash")
	}
}

func TestParseAuthentikReadsUsersAndGroups(t *testing.T) {
	body := strings.ReplaceAll(authentikExport, "PLACEHOLDER",
		djangoPBKDF2("pw", "saltsaltsalt", 100))

	exp, err := ParseAuthentik(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Users) != 3 {
		t.Fatalf("parsed %d users, want 3 (the token record must be ignored)", len(exp.Users))
	}
	if len(exp.Groups) != 1 {
		t.Fatalf("parsed %d groups, want 1", len(exp.Groups))
	}

	var admin *AuthentikUser
	for i := range exp.Users {
		if exp.Users[i].Username == "akadmin" {
			admin = &exp.Users[i]
		}
	}
	if admin == nil {
		t.Fatal("akadmin was not parsed")
	}
	// Group membership arrives as primary keys and has to be resolved to names.
	// Groups are read in a first pass for exactly this reason: a single pass
	// would resolve only groups that happened to appear before the user.
	if len(admin.Groups) != 1 || admin.Groups[0] != "engineering" {
		t.Errorf("group membership did not resolve: %v", admin.Groups)
	}
	if admin.Email != "akadmin@authentik.test" {
		t.Errorf("email = %q", admin.Email)
	}
}

// TestParseRejectsSomethingThatIsNotAnExport. A helpful error beats importing
// nothing and reporting success.
func TestParseRejectsSomethingThatIsNotAnExport(t *testing.T) {
	for _, body := range []string{`[]`, `[{"model":"authentik_core.token","pk":1,"fields":{}}]`} {
		if _, err := ParseAuthentik(strings.NewReader(body)); err == nil {
			t.Errorf("accepted %q as an authentik export", body)
		}
	}
	if _, err := ParseAuthentik(strings.NewReader(`{"not":"an array"}`)); err == nil {
		t.Error("accepted a JSON object; dumpdata produces an array")
	}
}

// TestHashFormatNamesAreHonest.
//
// The census this prints is what tells an operator whether a migration needs a
// password reset. Naming a format "verifiable" when it is not would send them
// into a cutover believing nobody has to do anything.
func TestHashFormatNamesAreHonest(t *testing.T) {
	cases := map[string]bool{ // stored hash -> should be reported verifiable
		djangoPBKDF2("x", "saltsalt", 100):   true,
		"$argon2id$v=19$m=65536,t=3,p=4$x$y": true,
		"$2b$12$abcdefghijklmnopqrstuv":      true,
		"!":                                  false,
		"":                                   false,
		"scrypt$16384$8$1$salt$hash":         false,
		"$6$rounds=5000$salt$hash":           false,
	}
	for stored, wantVerifiable := range cases {
		name := hashFormatName(stored)
		saysVerifiable := strings.Contains(name, "verifiable") &&
			!strings.Contains(name, "NOT verifiable")
		if saysVerifiable != wantVerifiable {
			t.Errorf("hashFormatName(%.20q) = %q, which claims verifiable=%v; "+
				"passwords.CanVerify says %v", stored, name, saysVerifiable,
				passwords.CanVerify(stored))
		}
		// And the two must agree, since one is shown to a human and the other
		// decides whether the user is imported at all.
		if saysVerifiable != passwords.CanVerify(stored) {
			t.Errorf("the census and the importer disagree about %.20q: report says "+
				"%v, CanVerify says %v", stored, saysVerifiable, passwords.CanVerify(stored))
		}
	}
}
