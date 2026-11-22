package passwords

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A hash whose own parameters cost more than this process verifies is refused
// before any work, at sign-in and at import alike, by the one CostRefusal.
// phpass and Drupal 7 accepted 2^30 iterations (minutes per attempt), bcrypt
// any cost up to 31 (days), and an Argon2id or scrypt hash over the memory
// budget was reported verifiable and then refused at every sign-in.
func TestAHashCostingMoreThanAllowedIsRefusedBeforeAnyWork(t *testing.T) {
	cheap, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// A realm export's PBKDF2 credential, packed as EncodeKeycloak packs it.
	exported := func(iter string) string {
		return EncodeKeycloak(`{"algorithm":"pbkdf2-sha256","hashIterations":`+iter+`}`,
			`{"value":"`+base64.StdEncoding.EncodeToString([]byte("h"))+`","salt":"c2FsdA=="}`)
	}

	refused := map[string]string{
		"phpass at 2^30":            "$P$" + string(itoa64[30]) + "saltsalt0123456789abcdefghij",
		"phpass at 2^21":            "$P$" + string(itoa64[21]) + "saltsalt0123456789abcdefghij",
		"Drupal 7 at 2^30":          "$S$" + string(itoa64[30]) + "saltsalt0123456789abcdefghij",
		"bcrypt cost 16":            "$2a$16$" + string(cheap[7:]),
		"Argon2id over the budget":  "$argon2id$v=19$m=614400,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"scrypt over the budget":    "$scrypt$ln=20,r=8,p=1$c2FsdA$aGFzaA",
		"PBKDF2 export at 2000000":  exported("2000000"),
		"Django at twenty million":  "pbkdf2_sha256$20000000$salt$aGFzaA==",
		"Argon2id over the ceiling": "$argon2id$v=19$m=19456,t=17,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
	}
	for name, stored := range refused {
		if CanVerify(stored) || CostRefusal(stored) == nil {
			t.Errorf("%s: reported verifiable, so an importer would create an account no "+
				"sign-in can reach", name)
		}
		start := time.Now()
		_, err := Shared().Verify(context.Background(), stored, "pw")
		if !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: Verify gave %v, want a mismatch", name, err)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Errorf("%s: refusing took %v; the cost was paid before it was refused", name, d)
		}
	}

	// At the ceilings, still verifiable: a real export is not refused.
	for name, stored := range map[string]string{
		"phpass at 2^20":           "$P$" + string(itoa64[20]) + "saltsalt0123456789abcdefghij",
		"bcrypt cost 15":           "$2a$15$" + string(cheap[7:]),
		"Argon2id at ours":         "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"scrypt within the budget": "$scrypt$ln=14,r=8,p=1$c2FsdA$aGFzaA",
		"exported PBKDF2 at 27500": exported("27500"),
	} {
		if !CanVerify(stored) {
			t.Errorf("%s: refused, though it is within every ceiling: %v", name, CostRefusal(stored))
		}
	}
}
