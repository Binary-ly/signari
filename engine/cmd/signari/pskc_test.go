package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store/storetest"
)

// A batch of tokens from a vendor's file. The seed is the ASCII "12345678901234567890" of
// RFC 6030 Figure 6, whose presses start 755224, 287082, 359152, 969429, 338314.
func TestAVendorsFileGivesEachTokenToItsHolder(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNARI_ROOT_KEY", base64.StdEncoding.EncodeToString(append(key, key...)))
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var org string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://pskc-' || gen_random_uuid() || '.test', 'PSKC test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'p' || substr(gen_random_uuid()::text, 1, 8), 'PSKC' FROM i RETURNING id::text`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, db, org)
	people := []string{fmt.Sprintf("ada-%d@example.test", time.Now().UnixNano()), fmt.Sprintf("bob-%d@example.test", time.Now().UnixNano())}
	t.Cleanup(func() {
		for _, email := range people {
			_, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
		}
	})
	for _, email := range people {
		password := make([]byte, 24)
		_, _ = rand.Read(password)
		if err := run([]string{"user", "create", "-dsn", dsn, "-org", org, "-email", email,
			"-password", base64.RawURLEncoding.EncodeToString(password)}); err != nil {
			t.Fatalf("user create: %v", err)
		}
	}
	held := func(email string) bool {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM core.totp_credentials c JOIN core.users u ON u.id = c.user_id
			WHERE u.email = $1 AND c.kind = 'hotp' AND c.confirmed_at IS NOT NULL`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	dir := t.TempDir()
	const token = `<Key Id="%s" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp"><AlgorithmParameters>
		<ResponseFormat Length="6" Encoding="DECIMAL"/></AlgorithmParameters><Data><Secret>
		<PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=</PlainValue></Secret><Counter><PlainValue>0</PlainValue></Counter></Data></Key>`
	file := filepath.Join(dir, "tokens.xml")
	body := `<KeyContainer Version="1.0" xmlns="urn:ietf:params:xml:ns:keyprov:pskc">` +
		`<KeyPackage><DeviceInfo><SerialNo>A1</SerialNo></DeviceInfo>` + fmt.Sprintf(token, "k1") + `</KeyPackage>` +
		`<KeyPackage><DeviceInfo><SerialNo>B2</SerialNo></DeviceInfo>` + fmt.Sprintf(token, "k2") + `</KeyPackage>` +
		`</KeyContainer>`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	who := filepath.Join(dir, "who.csv")
	write := func(lines ...string) {
		t.Helper()
		if err := os.WriteFile(who, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"import", "pskc", "-dsn", dsn, "-org", org, "-file", file, "-assignments", who}

	// A preview proves and stores nothing.
	write("A1,"+people[0]+",969429,338314", "B2,"+people[1]+",755224,287082")
	if err := run(args); err != nil {
		t.Fatalf("a preview: %v", err)
	}
	if held(people[0]) || held(people[1]) {
		t.Fatal("a preview stored a token")
	}

	// One that fails its proof is that one's problem alone.
	write("A1,"+people[0]+",969429,338314", "B2,"+people[1]+",000000,111111")
	if err := run(append(args, "-apply")); err == nil {
		t.Error("a run with a refused token said nothing was wrong")
	}
	if !held(people[0]) {
		t.Error("the proved token was not assigned")
	}
	if held(people[1]) {
		t.Error("a token its codes did not prove was stored")
	}

	for name, line := range map[string]string{
		"an unknown serial": "ZZ9," + people[1] + ",755224,287082",
		"an unknown person": "B2,nobody@example.test,755224,287082",
		"one code of two":   "B2," + people[1] + ",755224",
	} {
		write(line)
		if err := run(append(args, "-apply")); err == nil {
			t.Errorf("%s was accepted", name)
		}
		if held(people[1]) {
			t.Fatalf("%s stored a token", name)
		}
	}
	write("B2," + people[1] + ",755224,287082")
	if err := run(append(args, "-apply")); err != nil {
		t.Fatalf("the second token: %v", err)
	}
	if !held(people[1]) {
		t.Error("the second token was not assigned")
	}
	var recorded int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type = 'mfa.otp_token_assigned' AND detail->>'via' = 'pskc'`, org).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 2 {
		t.Errorf("%d assignments on the record", recorded)
	}
	if err := run([]string{"import", "pskc", "-dsn", dsn, "-org", org, "-file", file}); err == nil {
		t.Error("a run with no -assignments was accepted")
	}
	bad := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(bad, []byte("only,two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"import", "pskc", "-dsn", dsn, "-org", org, "-file", file, "-assignments", bad}); err == nil {
		t.Error("a line that is not serial,person,code was accepted")
	}
}
