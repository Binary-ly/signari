package store

import (
	"context"
	"os"
	"regexp"
	"testing"
)

// SP 800-63B-4 §3.1.1.2: "Verifiers and CSPs SHALL NOT require users to change
// passwords periodically." (quoted in passwords' TestNoCompositionRulesAreImposed,
// with its twin about composition). Compliance is by absence, and absence is
// what a well-meant change removes: an expiry column, or a setting for one,
// reads like tightening security. The decision is D-composition (4.16), and
// docs/password-policy.md says why.
func TestNoPasswordExpiresOnASchedule(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	rows, err := conn.Query(ctx, `
		SELECT table_name || '.' || column_name FROM information_schema.columns
		 WHERE table_schema = 'core'
		   AND column_name ~ '(password|pwd)'
		   AND column_name ~ '(expir|max_age|valid_until|rotat|lifetime)'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatal(err)
		}
		t.Errorf("%s reads as a password expiry, which SP 800-63B-4 says SHALL NOT be "+
			"required; a password is changed on evidence of compromise", col)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	doc, err := os.ReadFile("../../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile("`SIGNARI_PASSWORD_[A-Z_]*(EXPIR|MAX_AGE|ROTAT|LIFETIME)[A-Z_]*`").Find(doc); m != nil {
		t.Errorf("%s is a setting for password expiry, which SP 800-63B-4 says SHALL NOT be required", m)
	}
}
