package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// factorTables classifies every table that holds an authentication credential.
//
// true  -- a user with only this factor must be challenged after a password
// false -- deliberately NOT a gate, with the reason recorded here
//
// An explicit list, checked against the live schema below, because the first
// version of this test discovered tables by name pattern and therefore could
// not see `duo_enrollments`. It passed while Duo was an MFA bypass. A test that
// fails to look is worse than no test: it is a no-test that reports success.
var factorTables = map[string]bool{
	"totp_credentials":      true,
	"email_otp_credentials": true,
	"sms_otp_credentials":   true,
	"duo_enrollments":       true,

	// A passkey is a FIRST factor here, not a second one. Somebody who
	// registered one signs in with it directly; requiring a password and then
	// the same passkey would be one credential counted twice. If that ever
	// changes, flip this to true -- and the assertion below will then demand the
	// query be updated to match.
	"webauthn_credentials": false,

	// Recovery codes are the way BACK IN when a factor is lost. Counting them
	// as a factor would mean a user whose only "factor" is a printed list is
	// challenged for it, which is a lockout dressed as security.
	"recovery_codes": false,

	// The password itself. It is the FIRST factor, so counting it as a second
	// one would mean every user with a password is challenged for a second
	// password.
	"password_credentials": false,

	// An in-flight password reset, not a credential somebody holds. Caught by
	// the deliberately broad discovery query above; that breadth is the point,
	// since a false positive costs one line here and a false negative is a
	// bypass.
	"recovery_requests": false,
}

// TestEveryFactorTableIsChecked fails when a second-factor table exists that
// HasSecondFactor does not consult -- or when a new one appears that nobody has
// classified.
//
// This is the third time the shape of this bug has appeared here. The function
// was once called HasConfirmedTOTP, checked TOTP alone, and claimed in its own
// comment to report "a usable second factor" -- harmless until email codes
// existed, and then immediately an MFA bypass for anybody whose only factor was
// email. Adding SMS created the same opportunity. Adding Duo actually took it:
// the enrollment table was written, the challenge was wired up, and the gate
// was not updated, so a Duo-only user would have signed in on a password alone.
func TestEveryFactorTableIsChecked(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Anything that looks like it holds a credential or an enrolment. Broad on
	// purpose: a false positive costs one line in factorTables, and a false
	// negative is an authentication bypass.
	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'core'
		  AND (table_name LIKE '%credentials'
		       OR table_name LIKE '%enrollments'
		       OR table_name LIKE '%enrolments'
		       OR table_name LIKE 'recovery_%')
		ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var found []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		found = append(found, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(found) < len(factorTables) {
		t.Fatalf("the discovery query found %v but %d tables are classified; the "+
			"query is too narrow, which is exactly how this test passed while Duo "+
			"was a bypass", found, len(factorTables))
	}

	src, err := os.ReadFile("mfa.go")
	if err != nil {
		t.Fatal(err)
	}
	// The body of HasSecondFactor only -- a mention anywhere else in the file
	// would not gate a sign-in.
	//
	// Matched to the next top-level func rather than to the first "\n}": the
	// signature contains an inline interface literal, so the first closing brace
	// is the interface's. An earlier version captured the signature alone and
	// reported every table as missing.
	body := regexp.MustCompile(`(?s)func HasSecondFactor\(.*?(\n}\n\n|\z)`).Find(src)
	if body == nil {
		t.Fatal("HasSecondFactor not found; this test is no longer checking anything")
	}
	if !strings.Contains(string(body), "SELECT") {
		t.Fatalf("the extracted body has no query in it, so this test is checking "+
			"nothing:\n%s", body)
	}

	for _, tbl := range found {
		gates, classified := factorTables[tbl]
		if !classified {
			t.Errorf("core.%s looks like a credential table and nobody has decided "+
				"whether it gates a password sign-in. Add it to factorTables with a "+
				"reason.", tbl)
			continue
		}
		mentioned := strings.Contains(string(body), "core."+tbl)
		switch {
		case gates && !mentioned:
			t.Errorf("core.%s holds second-factor credentials and HasSecondFactor "+
				"does not consult it. A user whose only factor is in that table "+
				"signs in with a password alone, while their account settings say "+
				"MFA is on.", tbl)
		case !gates && mentioned:
			t.Errorf("core.%s is classified as NOT a second factor, but "+
				"HasSecondFactor consults it. One of the two is wrong.", tbl)
		}
	}
}
