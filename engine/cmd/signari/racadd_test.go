package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// What a connection signs in with reaches the command in a file and never on its
// command line (8.28), which anybody on the machine can read while it runs. Through
// run(), so a flag that is not there is refused as an operator would see it.
func TestRACAddReadsItsSecretsFromFiles(t *testing.T) {
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
		           VALUES ('https://rac-cli-' || gen_random_uuid() || '.test', 'RAC CLI test') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'RAC' FROM i RETURNING id::text`).
		Scan(&org); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
	password, empty, keyFile, passphrase := write("password", "from-a-file\n"), write("empty", ""),
		write("key.pem", key+"\n"), write("passphrase", "opens-the-key\n")

	add := func(slug, protocol string, more ...string) error {
		return run(append([]string{"rac", "add", "-dsn", dsn, "-org", org, "-slug", slug, "-host", "h.internal",
			"-protocol", protocol}, more...))
	}
	held := func(slug string) store.RACCredentials {
		t.Helper()
		root, err := rootKey()
		if err != nil {
			t.Fatal(err)
		}
		c, err := store.HeldRACCredentials(ctx, db, root, org, slug)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if err := add("argv", "rdp", "-login", "svc", "-login-password", "on-the-command-line"); err == nil {
		t.Error("a password was taken from the command line")
	}
	if err := add("hollow", "rdp", "-login", "svc", "-password-file", empty); err == nil ||
		!strings.Contains(err.Error(), "is empty") {
		t.Errorf("an empty file answered %v; it would register a connection that asks instead", err)
	}
	if err := add("absent", "rdp", "-password-file", filepath.Join(dir, "absent")); err == nil {
		t.Error("a file that is not there was taken for no password")
	}
	if err := add("rdpkey", "rdp", "-private-key-file", keyFile); err == nil {
		t.Error("an rdp connection took a private key")
	}
	if err := add("desk", "rdp", "-login", "svc", "-password-file", password); err != nil {
		t.Fatal(err)
	}
	if got := held("desk"); got != (store.RACCredentials{Login: "svc", Password: "from-a-file"}) {
		t.Errorf("the connection holds %+v", got)
	}
	if err := add("build", "ssh", "-login", "deploy", "-private-key-file", keyFile, "-passphrase-file", passphrase); err != nil {
		t.Fatal(err)
	}
	if got := held("build"); got != (store.RACCredentials{Login: "deploy", PrivateKey: key, Passphrase: "opens-the-key"}) {
		t.Errorf("the connection holds %+v", got)
	}
	if err := add("asks", "vnc"); err != nil {
		t.Fatal(err)
	}
	if got := held("asks"); got != (store.RACCredentials{}) {
		t.Errorf("a connection given nothing holds %+v", got)
	}

	// Never a file the engine reads a setting of its own from, whatever it is called.
	t.Setenv("SIGNARI_ROOT_KEY_FILE", password)
	if err := add("rootkey", "rdp", "-password-file", password); err == nil ||
		!strings.Contains(err.Error(), "a setting of the engine") {
		t.Errorf("the engine's own file answered %v", err)
	}
}
