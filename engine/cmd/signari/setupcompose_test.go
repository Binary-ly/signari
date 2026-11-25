package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// setup -compose writes a project whose secrets are made once (B13): a second
// run changes no file, the superuser's password stays in .env, which the
// engine never reads, and the engine's env file signs in as signari_engine.
// It refuses the flags that name what the project fixes, and uninstall
// -compose stops the project and removes what it wrote, keeping the volume
// and the root key until each is asked for and confirmed.
func TestTheComposeProjectKeepsItsSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in for docker below is a shell script")
	}
	h := testHost(t)
	dir := filepath.Join(t.TempDir(), "project")
	flags := setupFlags{compose: dir, email: "Ada@Example.com", yes: true, json: true,
		given: map[string]bool{"compose": true, "email": true, "yes": true, "json": true},
		args:  map[string]string{"compose": dir, "email": "Ada@Example.com", "yes": "true", "json": "true"}}
	run := func(f setupFlags) (setupResult, error) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		err := setupCmd(context.Background(), &stdout, &stderr, h, f)
		var res setupResult
		if jerr := json.Unmarshal(stdout.Bytes(), &res); jerr != nil {
			t.Fatalf("setup -compose -json printed %q (%v): %v\n%s", stdout.String(), err, jerr, stderr.String())
		}
		return res, err
	}
	first, err := run(flags)
	if err != nil || !first.OK || len(first.Steps) != 4 || !strings.Contains(first.Start, "docker compose up") {
		t.Fatalf("the first run: %v, %+v", err, first)
	}
	for _, s := range first.Steps {
		if s.State != "done" {
			t.Errorf("the first run's %s is %s", s.Step, s.State)
		}
	}
	if !composeProject(dir) {
		t.Error("compose.yaml does not open with its marker")
	}
	files := []string{"compose.yaml", ".env", envFileName, rootKeyFileName}
	snapshot := func() string {
		var b strings.Builder
		for _, name := range files {
			b.WriteString(mustRead(t, filepath.Join(dir, name)))
		}
		return b.String()
	}
	for _, name := range files[1:] {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want 0600", name, info, err)
		}
	}
	dotEnv, err := readEnvFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := readEnvFile(filepath.Join(dir, envFileName))
	if err != nil {
		t.Fatal(err)
	}
	login, password, database, host, err := dsnParts(engine.values["SIGNARI_DSN"])
	if err != nil || login != engineRole || password == "" || database != "signari" || host != "postgres" ||
		engine.values["SIGNARI_ADDR"] != "0.0.0.0:8080" || engine.values["SIGNARI_ISSUER"] != "http://localhost:8080" ||
		engine.values["SIGNARI_ROOT_KEY_FILE"] != filepath.Join(dir, rootKeyFileName) {
		t.Errorf("the engine's env file holds %v (%v)", engine.values, err)
	}
	pg := dotEnv.values["POSTGRES_PASSWORD"]
	if pg == "" || pg == password || strings.Contains(mustRead(t, filepath.Join(dir, envFileName)), pg) ||
		dotEnv.values["PROJECT_DIR"] != dir || dotEnv.values["PUBLISH"] != "127.0.0.1:8080" ||
		dotEnv.values["FIRST_EMAIL"] != "ada@example.com" || !strings.HasPrefix(dotEnv.values["ENGINE_IMAGE"], "signari:") {
		t.Errorf("the project's .env holds %v", dotEnv.values)
	}
	if log := mustRead(t, filepath.Join(dir, setupLogName)); strings.Contains(log, pg) || strings.Contains(log, password) {
		t.Errorf("the log holds a password:\n%s", log)
	}

	before := snapshot()
	second, err := run(flags)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range second.Steps {
		if s.State != "skipped" {
			t.Errorf("the second run's %s is %s", s.Step, s.State)
		}
	}
	if snapshot() != before {
		t.Error("the second run changed a file of the project")
	}

	for name, f := range map[string]setupFlags{
		"-superuser-dsn": {compose: dir, superuserDSN: "postgres://postgres@db.example.com/postgres",
			given: map[string]bool{"compose": true, "superuser-dsn": true}},
		"-tls files": {compose: dir, tls: tlsFiles, given: map[string]bool{"compose": true, "tls": true}},
		"-issuer":    {compose: dir, issuer: "https://login.example.com", given: map[string]bool{"compose": true, "issuer": true}},
		"-image":     {image: "signari:x", given: map[string]bool{"image": true}},
	} {
		var discard bytes.Buffer
		if err := setupCmd(context.Background(), &discard, &discard, h, f); exitCode(err) != 2 {
			t.Errorf("%s: %v, want exit 2", name, err)
		}
	}

	// The project's own setup service finds the project by its compose.yaml.
	r := &setupRun{a: setupAnswers{envFile: filepath.Join(dir, envFileName)}, inCompose: composeProject(dir)}
	if !r.inCompose || !strings.Contains(r.startCommand(), "docker compose up") {
		t.Errorf("inside the project: %v, %q", r.inCompose, r.startCommand())
	}

	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, out, err := runUninstall(t, h, uninstallFlags{compose: dir, yes: true}); err != nil {
		t.Fatalf("uninstall -compose: %v\n%s", err, out)
	}
	down := "compose -p signari down --remove-orphans\n"
	if got := mustRead(t, calls); got != down {
		t.Errorf("docker was asked %q", got)
	}
	for _, name := range []string{"compose.yaml", setupLogName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s is still there", name)
		}
	}
	// The volume stays, and with it the root key and the passwords that open
	// what is in it.
	for _, name := range []string{rootKeyFileName, ".env", envFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s went while the database's volume stays", name)
		}
	}
	all := uninstallFlags{compose: dir, yes: true, deleteRootKey: true, dropDatabase: true}
	res, _, err := runUninstall(t, h, all)
	if exitCode(err) != 2 || res.Confirm == "" {
		t.Fatalf("the volume and the key, unconfirmed: %v, %+v", err, res)
	}
	all.confirm = res.Confirm
	if _, out, err := runUninstall(t, h, all); err != nil {
		t.Fatalf("with the code: %v\n%s", err, out)
	}
	if got := mustRead(t, calls); got != down+down+"volume rm --force signari_pgdata\n" {
		t.Errorf("docker was asked %q", got)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("%s is still there once nothing in it is", dir)
	}
}
