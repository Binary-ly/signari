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

	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store/storetest"
)

// A hardware token is assigned only with codes its seed produces (4.12): a
// wrong or mistyped seed stored would refuse the person at their next sign-in
// by a factor nobody can use. Through run(), so the flags reach the command.
// In an organisation of its own, because instance totp-policy changes it.
func TestAssignOTPStoresOnlyASeedItsCodesProve(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	if os.Getenv("SIGNARI_ROOT_KEY") == "" {
		t.Setenv("SIGNARI_ROOT_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var org string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://otp-cli-' || gen_random_uuid() || '.test', 'OTP CLI test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'OTP' FROM i RETURNING id::text`).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, db, org)
	email := fmt.Sprintf("assign-otp-%d@example.test", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
	})
	pw := make([]byte, 24)
	_, _ = rand.Read(pw)
	if err := run([]string{"user", "create", "-dsn", dsn, "-org", org, "-email", email,
		"-password", base64.RawURLEncoding.EncodeToString(pw)}); err != nil {
		t.Fatalf("user create: %v", err)
	}
	stored := func() (kind, alg string, digits, period int, counter int64, ok bool) {
		t.Helper()
		err := db.QueryRow(ctx, `SELECT c.kind, c.algorithm, c.digits, c.period_secs, c.last_used_counter
			FROM core.totp_credentials c JOIN core.users u ON u.id = c.user_id
			WHERE u.email = $1 AND c.confirmed_at IS NOT NULL`, email).
			Scan(&kind, &alg, &digits, &period, &counter)
		return kind, alg, digits, period, counter, err == nil
	}

	// The ASCII seed "12345678901234567890" as hex; its presses 0 to 4 give
	// 755224, 287082, 359152, 969429, 338314 (mfa's HOTP vectors).
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed")
	if err := os.WriteFile(seed, []byte("hex:3132333435363738393031323334353637383930\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hotp := []string{"user", "assign-otp", "-dsn", dsn, "-org", org, "-email", email, "-seed-file", seed, "-hotp"}
	for _, codes := range [][2]string{{"755224", "359152"}, {"000000", "111111"}, {"969429", "755224"}} {
		if err := run(append(hotp, "-code", codes[0], "-next-code", codes[1])); err == nil {
			t.Errorf("codes %v were accepted as two consecutive presses", codes)
		}
	}
	if _, _, _, _, _, ok := stored(); ok {
		t.Fatal("a seed its codes did not prove was stored")
	}
	// Pressed three times in testing: presses 3 and 4.
	if err := run(append(hotp, "-code", "969429", "-next-code", "338314")); err != nil {
		t.Fatalf("assign-otp -hotp: %v", err)
	}
	if kind, alg, digits, _, counter, ok := stored(); !ok || kind != "hotp" || alg != "SHA1" || digits != 6 || counter != 4 {
		t.Errorf("stored %s %s %d digits at press %d (%v), want hotp SHA1 6 at 4", kind, alg, digits, counter, ok)
	}

	// A time-based SHA-256 token replaces it, with the code it shows now.
	b32 := filepath.Join(dir, "seed32")
	raw, enc, err := mfa.GenerateSecret(mfa.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b32, []byte(enc), 0o600); err != nil {
		t.Fatal(err)
	}
	p := mfa.Params{Algorithm: mfa.SHA256, Digits: 8, Period: 60 * time.Second}
	totp := []string{"user", "assign-otp", "-dsn", dsn, "-org", org, "-email", email, "-seed-file", b32,
		"-totp-algorithm", "SHA256", "-totp-digits", "8", "-totp-period", "60s"}
	// The same seed's SHA-1 code is not this token's.
	sha1Code := mfa.Params{Digits: 8, Period: 60 * time.Second}.Code(raw, mfa.Counter(time.Now(), 60*time.Second))
	if err := run(append(totp, "-code", sha1Code)); err == nil {
		t.Error("a SHA-1 code was accepted for a SHA-256 token")
	}
	if err := run(append(totp, "-code", p.Code(raw, mfa.Counter(time.Now(), p.Period)))); err != nil {
		t.Fatalf("assign-otp SHA256: %v", err)
	}
	if kind, alg, digits, period, _, ok := stored(); !ok || kind != "totp" || alg != "SHA256" || digits != 8 || period != 60 {
		t.Errorf("stored %s %s %d digits %ds (%v), want totp SHA256 8 60s", kind, alg, digits, period, ok)
	}

	// The organisation's choice for apps, bounded.
	if err := run([]string{"instance", "totp-policy", "-dsn", dsn, "-org", org, "-totp-algorithm", "SHA512",
		"-totp-digits", "8", "-totp-period", "60s"}); err != nil {
		t.Fatalf("instance totp-policy: %v", err)
	}
	var alg string
	var digits, period int
	if err := db.QueryRow(ctx, `SELECT totp_algorithm, totp_digits, totp_period_s FROM core.organizations
		WHERE id = $1::uuid`, org).Scan(&alg, &digits, &period); err != nil || alg != "SHA512" || digits != 8 || period != 60 {
		t.Errorf("the policy reads %s %d %ds (%v)", alg, digits, period, err)
	}
	for _, bad := range [][]string{{"-totp-algorithm", "MD5"}, {"-totp-digits", "7"}, {"-totp-period", "45s"}} {
		if err := run(append([]string{"instance", "totp-policy", "-dsn", dsn, "-org", org}, bad...)); err == nil {
			t.Errorf("instance totp-policy %v was accepted", bad)
		}
	}

	// How SMS numbers are kept (4.28), in the same organisation of its own.
	numbers := func() string {
		t.Helper()
		var mode string
		if err := db.QueryRow(ctx, `SELECT sms_numbers FROM core.organizations WHERE id = $1::uuid`, org).
			Scan(&mode); err != nil {
			t.Fatal(err)
		}
		return mode
	}
	if err := run([]string{"instance", "sms-numbers", "-dsn", dsn, "-org", org, "-sms-numbers", "hashed"}); err != nil ||
		numbers() != "hashed" {
		t.Errorf("instance sms-numbers hashed: %v, now %s", err, numbers())
	}
	if err := run([]string{"instance", "sms-numbers", "-dsn", dsn, "-org", org, "-sms-numbers", "clear"}); err == nil {
		t.Error("instance sms-numbers clear was accepted")
	}
}

// A YubiKey's Yubico OTP slot is assigned only with an OTP made under the key and private
// ID given (4.27), which also says its public ID and where its counters stand; and a token
// already somebody's is not given to a second person.
func TestAssignOTPYubicoStoresOnlyAKeyItsOTPProves(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	if os.Getenv("SIGNARI_ROOT_KEY") == "" {
		t.Setenv("SIGNARI_ROOT_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var org string
	if err := db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://yubico-cli-' || gen_random_uuid() || '.test', 'Yubico CLI test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Yubico' FROM i RETURNING id::text`).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	storetest.Forget(t, db, org)
	people := make([]string, 2)
	for i := range people {
		people[i] = fmt.Sprintf("assign-yubico-%d-%d@example.test", i, time.Now().UnixNano())
		email := people[i]
		t.Cleanup(func() {
			_, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email)
		})
		pw := make([]byte, 24)
		_, _ = rand.Read(pw)
		if err := run([]string{"user", "create", "-dsn", dsn, "-org", org, "-email", email,
			"-password", base64.RawURLEncoding.EncodeToString(pw)}); err != nil {
			t.Fatalf("user create: %v", err)
		}
	}
	stored := func(email string) (kind, alg, publicID string, counter int64, ok bool) {
		t.Helper()
		err := db.QueryRow(ctx, `SELECT c.kind, c.algorithm, COALESCE(c.yubico_public_id, ''), c.last_used_counter
			FROM core.totp_credentials c JOIN core.users u ON u.id = c.user_id
			WHERE u.email = $1 AND c.confirmed_at IS NOT NULL`, email).Scan(&kind, &alg, &publicID, &counter)
		return kind, alg, publicID, counter, err == nil
	}

	// mfa's vectors from libyubikey's ykgenerate: this key and private ID, use 1 session 0.
	// Any public ID: the encrypted part does not depend on it, and a token has one holder.
	idBytes := make([]byte, 6)
	_, _ = rand.Read(idBytes)
	var publicID string
	for _, b := range idBytes {
		publicID += string("cbdefghijklnrtuv"[b>>4]) + string("cbdefghijklnrtuv"[b&15])
	}
	otp := publicID + "hfbkfjghgbjibhlvjfibfvujblhgbfnf"
	dir := t.TempDir()
	file := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := file("good", "aa:99:48:55:e4:55, 47077bb37e5298413989c9ef9fcb1dad\n")
	assign := func(email, keyFile string, more ...string) error {
		return run(append([]string{"user", "assign-otp", "-dsn", dsn, "-org", org, "-email", email,
			"-yubico", "-seed-file", keyFile}, more...))
	}
	for name, err := range map[string]error{
		"another private ID":  assign(people[0], file("wrongid", "47077bb37e5298413989c9ef9fcb1dad aa994855e456"), "-code", otp),
		"only the key":        assign(people[0], file("keyonly", "47077bb37e5298413989c9ef9fcb1dad"), "-code", otp),
		"not an OTP":          assign(people[0], good, "-code", "287082"),
		"with -hotp":          assign(people[0], good, "-code", otp, "-hotp"),
		"with no -code":       assign(people[0], good),
		"a key of 15 bytes":   assign(people[0], file("short", "aa994855e455 47077bb37e5298413989c9ef9fcb1d"), "-code", otp),
		"an OTP with no ID":   assign(people[0], good, "-code", "hfbkfjghgbjibhlvjfibfvujblhgbfnf"),
		"one character wrong": assign(people[0], good, "-code", otp[:len(otp)-1]+"c"),
	} {
		if err == nil {
			t.Errorf("%s: assigned", name)
		}
	}
	if _, _, _, _, ok := stored(people[0]); ok {
		t.Fatal("a key its OTP did not prove was stored")
	}

	if err := assign(people[0], good, "-code", otp); err != nil {
		t.Fatalf("assign-otp -yubico: %v", err)
	}
	if kind, alg, id, counter, ok := stored(people[0]); !ok || kind != "yubico" || alg != "AES128" || id != publicID ||
		counter != 0x0100 {
		t.Errorf("stored %s %s %q at %#x (%v), want yubico AES128 %q at 0x100", kind, alg, id, counter, ok, publicID)
	}
	if err := assign(people[1], good, "-code", publicID+"dvhtenbcidccjcbvrjtheicebfleckuh"); err == nil ||
		!strings.Contains(err.Error(), "another person's authenticator") {
		t.Errorf("the token given to a second person: %v", err)
	}
	if _, _, _, _, ok := stored(people[1]); ok {
		t.Error("the second person was given a token somebody holds")
	}
}
