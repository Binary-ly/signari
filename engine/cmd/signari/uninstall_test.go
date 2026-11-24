package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uninstallResult is the line -json prints.
type uninstallResult struct {
	OK      bool            `json:"ok"`
	DryRun  bool            `json:"dry_run"`
	Items   []uninstallItem `json:"items"`
	Confirm string          `json:"confirm"`
	Error   string          `json:"error"`
}

func runUninstall(t *testing.T, h setupHost, f uninstallFlags) (uninstallResult, string, error) {
	t.Helper()
	f.json = true
	var stdout, stderr bytes.Buffer
	err := uninstallCmd(context.Background(), &stdout, &stderr, h, f)
	var res uninstallResult
	if jerr := json.Unmarshal(stdout.Bytes(), &res); jerr != nil {
		t.Fatalf("-json printed %q: %v", stdout.String(), jerr)
	}
	return res, stderr.String(), err
}

// Uninstall removes exactly what the manifest lists (B14): a file beside them
// that it does not list stays, and so does its directory; the root key stays
// unless asked for, and deleting it while keeping the database takes the
// sentence saying the data becomes unreadable.
func TestUninstallRemovesWhatTheManifestListsAndNothingElse(t *testing.T) {
	h := testHost(t)
	conf := filepath.Join(h.home, "conf")
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(p string) string {
		t.Helper()
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env, key, copy := write(filepath.Join(conf, envFileName)), write(filepath.Join(conf, rootKeyFileName)),
		write(filepath.Join(conf, "fullchain.pem"))
	bin := write(filepath.Join(h.home, "signari"))
	mine := write(filepath.Join(conf, "notes.txt"))
	m := installManifest{path: manifestPath(h.euid, h.getenv, h.home)}
	for _, e := range []manifestEntry{{"dir", conf}, {"env-file", env}, {"root-key", key}, {"file", copy},
		{"binary", bin}, {"file", filepath.Join(conf, "already-gone")}} {
		m.add(e)
	}
	if err := m.write(h.euid); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(m.path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the manifest: %v, %v", info, err)
	}

	res, _, err := runUninstall(t, h, uninstallFlags{dryRun: true})
	if err != nil || !res.OK || !res.DryRun || len(res.Items) != 6 {
		t.Fatalf("a dry run: %v, %+v", err, res)
	}
	for _, p := range []string{env, key, copy, bin} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("a dry run removed %s", p)
		}
	}
	if _, _, err := runUninstall(t, h, uninstallFlags{}); exitCode(err) != 2 || !strings.Contains(err.Error(), "-yes") {
		t.Errorf("with nobody to ask and no -yes: %v", err)
	}

	res, _, err = runUninstall(t, h, uninstallFlags{yes: true})
	if err != nil || !res.OK {
		t.Fatalf("uninstall -yes: %v, %+v", err, res)
	}
	for _, p := range []string{env, copy, bin} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	for _, p := range []string{key, mine, conf} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	states := map[string]string{}
	for _, it := range res.Items {
		states[it.Kind+" "+it.Value] = it.State
	}
	if states["root-key "+key] != "kept" || states["dir "+conf] != "kept" ||
		states["file "+filepath.Join(conf, "already-gone")] != "gone" {
		t.Errorf("states %v", states)
	}
	left, err := readManifest(m.path)
	if err != nil || len(left.entries) != 2 {
		t.Fatalf("what stays listed: %+v, %v", left.entries, err)
	}

	// The key, with the database kept: the sentence, not -yes alone.
	res, out, err := runUninstall(t, h, uninstallFlags{yes: true, deleteRootKey: true})
	if exitCode(err) != 2 || !strings.Contains(out, keySentence("the database")) {
		t.Errorf("deleting the key and keeping the database without the sentence: %v\n%s", err, out)
	}
	if _, err := os.Stat(key); err != nil {
		t.Error("the key was deleted without the sentence")
	}
	if _, _, err := runUninstall(t, h, uninstallFlags{yes: true, deleteRootKey: true, confirm: res.Confirm}); exitCode(err) != 2 {
		t.Errorf("the code, where the sentence is asked for: %v", err)
	}
	if _, _, err := runUninstall(t, h, uninstallFlags{yes: true, deleteRootKey: true,
		confirm: keySentence("the database")}); err != nil {
		t.Fatalf("with the sentence: %v", err)
	}
	if _, err := os.Stat(key); err == nil {
		t.Error("the key is still there")
	}
	if err := os.Remove(mine); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runUninstall(t, h, uninstallFlags{yes: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{conf, m.path, filepath.Dir(m.path)} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there once nothing else is", p)
		}
	}
	if res, _, err := runUninstall(t, h, uninstallFlags{yes: true}); err != nil || !res.OK || len(res.Items) != 0 {
		t.Errorf("with no manifest: %v, %+v", err, res)
	}
}

// The root key and the database together take the code a first run prints,
// and a database to drop needs a superuser before anything is removed: the
// key never goes while its data stays.
func TestUninstallConfirmsTheKeyAndTheDatabaseByCode(t *testing.T) {
	h := testHost(t)
	key := filepath.Join(h.home, rootKeyFileName)
	if err := os.WriteFile(key, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := installManifest{path: manifestPath(h.euid, h.getenv, h.home)}
	m.add(manifestEntry{"root-key", key})
	m.add(manifestEntry{"database", "signari 127.0.0.1:5432"})
	m.add(manifestEntry{"roles", strings.Join(engineRoles, " ")})
	if err := m.write(h.euid); err != nil {
		t.Fatal(err)
	}
	both := uninstallFlags{yes: true, deleteRootKey: true, dropDatabase: true}
	res, _, err := runUninstall(t, h, both)
	if exitCode(err) != 2 || len(res.Confirm) != 12 {
		t.Fatalf("both, without the code: %v, %+v", err, res)
	}
	both.confirm = res.Confirm
	_, _, err = runUninstall(t, h, both)
	if err == nil || !strings.Contains(err.Error(), "nothing was removed") || !strings.Contains(err.Error(), "-superuser-dsn") {
		t.Errorf("with the code and no PostgreSQL to drop it on: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Error("the root key went while the database it opens stays")
	}
	// A code is for one key: another key takes another.
	if err := os.WriteFile(key, []byte("other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, _, err := runUninstall(t, h, both); exitCode(err) != 2 || res.Confirm == both.confirm {
		t.Errorf("the code confirmed another key: %v, %+v", err, res)
	}
}

// The manifest says what root deletes, so one anybody else may change, or
// that names what neither the installer nor setup makes, is refused.
func TestAManifestIsTrustedOnlyAsItsOwnerWroteIt(t *testing.T) {
	h := testHost(t)
	path := manifestPath(h.euid, h.getenv, h.home)
	for line, ok := range map[string]bool{
		"file /etc/signari/signari.env": true, "user signari": true, "unit " + unitPath: true,
		"binary /usr/local/bin/signari": true, "roles signari_engine signari_admin": true,
		"user root": false, "unit /etc/systemd/system/sshd.service": false, "binary /usr/bin/sudo": false,
		"file /etc": false, "file relative/path": false, "file /etc/signari/../shadow": false,
		"roles postgres": false, "database Robert'); DROP": false, "shell rm -rf /": false,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(manifestHeader+line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readManifest(path); (err == nil) != ok {
			t.Errorf("%q: %v, want ok %v", line, err, ok)
		}
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(path); err == nil || !strings.Contains(err.Error(), "chmod go-w") {
		t.Errorf("a manifest its group may write: %v", err)
	}
}
