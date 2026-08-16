package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestEveryFactorTableIsChecked fails when a second-factor table exists that
// HasSecondFactor does not consult.
//
// This is the third time the shape of this bug has appeared here. The function
// was once called HasConfirmedTOTP, checked TOTP alone, and claimed in its own
// comment to report "a usable second factor" -- harmless until email codes
// existed, and then immediately an MFA bypass for anybody whose only factor was
// email. Adding SMS created the same opportunity again.
//
// A comment saying "remember to update this" is not a mechanism. The database
// knows which tables hold credentials; asking it is.
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

	// Every table whose name says it holds a second-factor credential.
	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'core'
		  AND (table_name LIKE '%otp_credentials' OR table_name = 'totp_credentials')
		ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(tables) < 2 {
		t.Fatalf("found only %v; the discovery query is wrong, which would make "+
			"this test pass by finding nothing", tables)
	}

	src, err := os.ReadFile("mfa.go")
	if err != nil {
		t.Fatal(err)
	}
	// The body of HasSecondFactor only -- a mention anywhere else in the file
	// would not gate a sign-in.
	//
	// Matched to the NEXT top-level func rather than to the first "\n}". The
	// signature contains an inline interface literal, so the first closing brace
	// is the interface's: the earlier version captured the signature alone and
	// reported every table as missing. A test that fails for the wrong reason is
	// as useless as one that passes for the wrong reason, and louder.
	body := regexp.MustCompile(`(?s)func HasSecondFactor\(.*?(\n}\n\n|\z)`).Find(src)
	if body == nil {
		t.Fatal("HasSecondFactor not found; this test is no longer checking anything")
	}
	if !strings.Contains(string(body), "SELECT") {
		t.Fatalf("the extracted body has no query in it, so this test is checking "+
			"nothing:\n%s", body)
	}

	for _, tbl := range tables {
		if !strings.Contains(string(body), "core."+tbl) {
			t.Errorf("core.%s holds second-factor credentials and HasSecondFactor "+
				"does not consult it. A user whose only factor is in that table "+
				"signs in with a password alone, while their account settings say "+
				"MFA is on.", tbl)
		}
	}
}
