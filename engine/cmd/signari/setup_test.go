package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/migrate"
)

// testHost is a machine with nothing on it setup could find: no PostgreSQL,
// no terminal, no name, no systemd, no proxy and no certificate, run by a user
// who is not root, so that no default puts a file in /etc or /var/log even
// where the suite runs as root.
func testHost(t *testing.T) setupHost {
	t.Helper()
	home := t.TempDir()
	return setupHost{goos: "linux", goarch: "amd64", euid: 1000, getenv: func(string) string { return "" },
		home: home, fqdn: func() string { return "" }, resolves: func(string) bool { return false },
		tcpOpen: func(string) bool { return false }, postgresUID: -1, now: time.Now}
}

// scriptedPrompter answers each question with the next of its answers, and
// records what it was asked.
type scriptedPrompter struct {
	answers []string
	asked   []string
}

func (s *scriptedPrompter) next(label, hint string) string {
	s.asked = append(s.asked, label)
	if len(label) > 74 || len(hint) > 74 {
		panic(fmt.Sprintf("a prompt longer than 74 characters: %q / %q", label, hint))
	}
	if len(s.answers) == 0 {
		return ""
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a
}

func (s *scriptedPrompter) ask(label, hint, def string, valid func(string) error) (string, error) {
	a := s.next(label, hint)
	if a == "" {
		a = def
	}
	return a, valid(a)
}

func (s *scriptedPrompter) confirm(label, hint string, def bool) (bool, error) {
	switch s.next(label, hint) {
	case "n":
		return false, nil
	case "y":
		return true, nil
	}
	return def, nil
}

func (s *scriptedPrompter) secret(label, hint string) (string, error) {
	return s.next(label, hint), nil
}

// One table of defaults, both ways (B4): a run that asks, given Enter for
// every question that offers a default, settles exactly what a run that asks
// nothing does, and writes the same env file. An installer whose defaults
// were set only where it asked would install one thing by hand and another
// from a script.
func TestAskingAndNotAskingSettleTheSameAnswers(t *testing.T) {
	for _, c := range []struct {
		name   string
		fqdn   string
		addr   string
		issuer string
	}{
		{"a host with a public name", "login.example.com", "", "https://login.example.com"},
		{"a host with none", "build-7", "", "http://localhost:8080"},
		{"a host whose name is a private network's", "box.internal", "", "http://localhost:8080"},
		{"a listen address of its own", "", "127.0.0.1:9000", "http://localhost:9000"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testHost(t)
			h.fqdn = func() string { return c.fqdn }
			h.resolves = func(string) bool { return true }
			prior := envFile{path: filepath.Join(h.home, "x", envFileName), values: map[string]string{}}

			quiet := setupFlags{email: "You@Example.com", addr: c.addr}
			without, missing, err := resolveAnswers(quiet, h, prior, nil, false)
			if err != nil || len(missing) > 0 {
				t.Fatalf("without asking: %v, missing %v", err, missing)
			}
			ask := &scriptedPrompter{answers: []string{"", "you@example.com"}}
			with, _, err := resolveAnswers(setupFlags{addr: c.addr}, h, prior, ask, false)
			if err != nil {
				t.Fatalf("asking: %v", err)
			}
			// The address, the email, and for an https:// address who ends TLS
			// (B5); nothing else that has a default.
			questions := 2
			if strings.HasPrefix(c.issuer, "https://") {
				questions = 3
			}
			if len(ask.asked) != questions {
				t.Errorf("asked %v; want %d questions", ask.asked, questions)
			}
			if without.issuer != c.issuer || with.issuer != c.issuer {
				t.Errorf("issuer %q without asking and %q with, want %q", without.issuer, with.issuer, c.issuer)
			}
			for _, pair := range [][2]string{{without.email, with.email}, {without.database, with.database},
				{without.addr, with.addr}, {without.rootKeyFile, with.rootKeyFile}, {without.envFile, with.envFile},
				{without.tls, with.tls}, {without.trustedProxies, with.trustedProxies}} {
				if pair[0] != pair[1] {
					t.Errorf("without asking %q, with %q", pair[0], pair[1])
				}
			}
			if without.email != "you@example.com" {
				t.Errorf("the email is %q; addresses are kept in lower case, as bootstrap keeps them", without.email)
			}
			r1 := &setupRun{prior: prior, a: without, engineDSN: "postgres://signari_engine:x@127.0.0.1:5432/signari"}
			r2 := &setupRun{prior: prior, a: with, engineDSN: r1.engineDSN}
			f1, _, err1 := prior.render(r1.envValues())
			f2, _, err2 := prior.render(r2.envValues())
			if err1 != nil || err2 != nil || f1 != f2 {
				t.Errorf("the two runs write different env files (%v, %v):\n%s\n---\n%s", err1, err2, f1, f2)
			}
		})
	}
}

// An answer setup needs and cannot work out is an error naming the flag when
// it cannot ask (B6), exiting 2; a dry run lists it instead; and a re-run,
// whose earlier env file says the rest, needs no email until the database says
// the first administrator has no link.
func TestAMissingAnswerNamesItsFlag(t *testing.T) {
	h := testHost(t)
	none := envFile{path: filepath.Join(h.home, envFileName), values: map[string]string{}}
	_, _, err := resolveAnswers(setupFlags{}, h, none, nil, false)
	if err == nil || !strings.HasPrefix(err.Error(), "give -email") || exitCode(err) != 2 {
		t.Errorf("no email and nobody to ask: %v (exit %d), want it to begin give -email and exit 2", err, exitCode(err))
	}
	if _, missing, err := resolveAnswers(setupFlags{}, h, none, nil, true); err != nil || len(missing) != 1 ||
		missing[0] != "email" {
		t.Errorf("a dry run: %v, missing %v; want the email listed", err, missing)
	}
	earlier := envFile{path: none.path, exists: true, values: map[string]string{"SIGNARI_ISSUER": "https://id.example.com"}}
	a, _, err := resolveAnswers(setupFlags{}, h, earlier, nil, false)
	if err != nil || a.issuer != "https://id.example.com" || a.from["issuer"] != "env file" {
		t.Errorf("a re-run: %v, issuer %q from %q", err, a.issuer, a.from["issuer"])
	}
}

// Setup never changes what an earlier run settled: a flag that disagrees with
// the env file is refused, naming both.
func TestAFlagThatDisagreesWithTheEnvFileIsRefused(t *testing.T) {
	h := testHost(t)
	earlier := envFile{path: filepath.Join(h.home, envFileName), exists: true, values: map[string]string{
		"SIGNARI_ISSUER": "https://id.example.com",
		"SIGNARI_DSN":    "postgres://signari_engine:p@127.0.0.1:5432/signari?sslmode=disable"}}
	for flag, f := range map[string]setupFlags{
		"issuer":   {issuer: "https://other.example.com"},
		"database": {database: "elsewhere"},
	} {
		_, _, err := resolveAnswers(f, h, earlier, nil, false)
		if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "-"+flag) ||
			!strings.Contains(err.Error(), earlier.path) {
			t.Errorf("-%s against the env file: %v", flag, err)
		}
	}
	if a, _, err := resolveAnswers(setupFlags{issuer: "https://id.example.com"}, h, earlier, nil, false); err != nil ||
		a.database != "signari" || a.from["database"] != "env file" {
		t.Errorf("the same issuer again: %v, database %q from %q", err, a.database, a.from["database"])
	}
}

// What serve would refuse to publish is refused here first.
func TestAnIssuerIsHeldToWhatServePublishes(t *testing.T) {
	for issuer, ok := range map[string]bool{
		"https://login.example.com":      true,
		"https://example.com/idp":        true,
		"http://localhost:8080":          true,
		"http://login.example.com":       false,
		"http://127.0.0.1:8080":          false,
		"https://login.example.com/":     false,
		"https://login.example.com?x=1":  false,
		"https://login.example.com#frag": false,
		"https://user@login.example.com": false,
		"login.example.com":              false,
		"ftp://login.example.com":        false,
		"https://it's.example.com":       false,
	} {
		if err := validIssuer(issuer); (err == nil) != ok {
			t.Errorf("validIssuer(%q) = %v, want ok %v", issuer, err, ok)
		}
	}
}

// Only a name people elsewhere could reach is offered as the issuer; nothing
// outside this machine and its resolver is asked (B11).
func TestOnlyAPublicNameIsOffered(t *testing.T) {
	for name, public := range map[string]bool{
		"login.example.com": true, "id.signari.dev.": true, "Login.Example.COM": true,
		"localhost": false, "build-7": false, "box.local": false, "box.lan": false,
		"ip-10-0-0-5.ec2.internal": false, "vm.c.project.internal": false, "x.internal.cloudapp.net": false,
		"10.0.0.5": false, "::1": false, "a.b.123": false, "bad_label.example.com": false, "host.test": false,
	} {
		if got := publicName(name); got != public {
			t.Errorf("publicName(%q) = %v, want %v", name, got, public)
		}
	}
	h := testHost(t)
	h.fqdn = func() string { return "login.example.com" }
	if got := suggestIssuer(h, "127.0.0.1:8080"); got != "http://localhost:8080" {
		t.Errorf("a public name that does not resolve gave %s", got)
	}
}

// The root key is 32 random bytes in a 0600 file serve opens, and a second
// write never replaces it (B3).
func TestTheRootKeyFileIsPrivateAndNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "made", "here", rootKeyFileName)
	key, err := newRootKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	var made []string
	if err := writeFileAtomic(path, key, true, os.Geteuid(), &made); err != nil {
		t.Fatal(err)
	}
	if len(made) != 2 || made[0] != filepath.Join(dir, "made") {
		t.Errorf("the directories it made are recorded as %v", made)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key is %v (%v), want 0600", info.Mode(), err)
	}
	if _, err := loadRootKeyFile(path); err != nil {
		t.Errorf("serve would not open the key setup wrote: %v", err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(key))); len(raw) != 32 {
		t.Errorf("the key holds %d bytes, want 32", len(raw))
	}
	other, _ := newRootKeyFile()
	if err := writeFileAtomic(path, other, true, os.Geteuid(), nil); !errors.Is(err, errFileExists) {
		t.Errorf("a second write answered %v, want errFileExists", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, key) {
		t.Error("a second write replaced the root key")
	}
	if exists, err := rootKeyFileState(path); !exists || err != nil {
		t.Errorf("the key it wrote reads as exists %v, %v", exists, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files are left beside the key: %v", entries)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := rootKeyFileState(path); err == nil || !strings.Contains(err.Error(), "never replaces") {
		t.Errorf("a key its group may read: %v; setup refuses it, as serve would, and never writes another", err)
	}
}

// The env file holds what serve reads, single-quoted so the shell and
// systemd's EnvironmentFile read the same values; a re-run adds what is
// missing and changes nothing else; and it is refused unless 0600.
func TestTheEnvFileIsWhatServeReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, envFileName)
	want := map[string]string{
		"SIGNARI_DSN":           "postgres://signari_engine:ABC234@127.0.0.1:5432/signari?sslmode=disable&x=y",
		"SIGNARI_ROOT_KEY_FILE": filepath.Join(dir, rootKeyFileName),
		"SIGNARI_ISSUER":        "https://login.example.com",
		"SIGNARI_ADDR":          "127.0.0.1:8080",
	}
	fresh := envFile{path: path, values: map[string]string{}}
	content, added, err := fresh.render(want)
	if err != nil || len(added) != len(envKeys) {
		t.Fatalf("render: %v, added %v", err, added)
	}
	for k, v := range want {
		if !strings.Contains(content, k+"='"+v+"'\n") {
			t.Errorf("the file lacks %s='%s':\n%s", k, v, content)
		}
	}
	if !strings.HasPrefix(content, "# ") || !strings.Contains(content, "0600") {
		t.Errorf("the file does not open by saying what it is:\n%s", content)
	}
	if err := writeFileAtomic(path, []byte(content), true, os.Geteuid(), nil); err != nil {
		t.Fatal(err)
	}
	back, err := readEnvFile(path)
	if err != nil || !back.exists {
		t.Fatalf("reading it back: %v", err)
	}
	for k, v := range want {
		if back.values[k] != v {
			t.Errorf("%s read back as %q, want %q", k, back.values[k], v)
		}
	}
	// The shell reads it the same, the & in the DSN included.
	if sh, err := exec.LookPath("sh"); err == nil {
		out, err := exec.Command(sh, "-c", `set -a; . "$1"; set +a; printf '%s|%s' "$SIGNARI_DSN" "$SIGNARI_ADDR"`,
			"sh", path).Output()
		if err != nil || string(out) != want["SIGNARI_DSN"]+"|"+want["SIGNARI_ADDR"] {
			t.Errorf("the shell read %q (%v)", out, err)
		}
	}
	again, added, err := back.render(want)
	if err != nil || len(added) != 0 || again != content {
		t.Errorf("rendering the same settings again changed the file (%v, added %v)", err, added)
	}
	partial := back
	partial.values = map[string]string{}
	for k, v := range back.values {
		partial.values[k] = v
	}
	delete(partial.values, "SIGNARI_ADDR")
	partial.lines = nil
	for _, l := range back.lines {
		if !strings.HasPrefix(l, "SIGNARI_ADDR=") {
			partial.lines = append(partial.lines, l)
		}
	}
	partial.lines = append(partial.lines, "SIGNARI_SMTP_HOST='mail.example.com'")
	filled, added, err := partial.render(want)
	if err != nil || len(added) != 1 || added[0] != "SIGNARI_ADDR" || !strings.Contains(filled, "SIGNARI_SMTP_HOST=") {
		t.Errorf("filling one missing setting: %v, added %v:\n%s", err, added, filled)
	}
	// A setting left blank, such as a SIGNARI_DSN= somebody emptied, is
	// missing, and its line is written again in place with the value: one line
	// for it, and the rest of the file as it was.
	blank := back
	blank.values = map[string]string{}
	for k, v := range back.values {
		blank.values[k] = v
	}
	blank.values["SIGNARI_DSN"] = ""
	blank.lines = nil
	for _, l := range back.lines {
		if strings.HasPrefix(l, "SIGNARI_DSN=") {
			l = "SIGNARI_DSN="
		}
		blank.lines = append(blank.lines, l)
	}
	refilled, added, err := blank.render(want)
	if err != nil || len(added) != 1 || added[0] != "SIGNARI_DSN" ||
		strings.Count(refilled, "SIGNARI_DSN=") != 1 || !strings.Contains(refilled, "SIGNARI_DSN='"+want["SIGNARI_DSN"]+"'\n") {
		t.Errorf("filling a blanked SIGNARI_DSN: %v, added %v:\n%s", err, added, refilled)
	}
	if strings.Index(refilled, "SIGNARI_DSN=") > strings.Index(refilled, "SIGNARI_ROOT_KEY_FILE=") {
		t.Errorf("the blanked line was not written again where it stood:\n%s", refilled)
	}
	r := &setupRun{prior: blank, engineDSN: want["SIGNARI_DSN"], a: setupAnswers{rootKeyFile: want["SIGNARI_ROOT_KEY_FILE"],
		issuer: want["SIGNARI_ISSUER"], addr: want["SIGNARI_ADDR"]}}
	if r.envComplete() {
		t.Error("an env file with SIGNARI_DSN blank reads as complete, so the step that writes it would be skipped")
	}
	conflict := map[string]string{}
	for k, v := range want {
		conflict[k] = v
	}
	conflict["SIGNARI_ISSUER"] = "https://other.example.com"
	if _, _, err := back.render(conflict); err == nil {
		t.Error("a setting the file holds with another value was written over")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnvFile(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("an env file its group may read: %v", err)
	}
}

// A superuser's password never rides on the command line (B6): a URL with one
// is refused as a flag, and taken from a file.
func TestASuperuserPasswordStaysOffTheCommandLine(t *testing.T) {
	for _, dsn := range []string{"postgres://postgres:secret@db.example.com/postgres",
		"postgres://postgres@db.example.com/postgres?password=secret"} {
		if _, err := superuserFromFlags(setupFlags{superuserDSN: dsn}); err == nil || exitCode(err) != 2 ||
			!strings.Contains(err.Error(), "PGPASSWORD") {
			t.Errorf("%s as a flag: %v", dsn, err)
		}
	}
	file := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(file, []byte("postgres://postgres:secret@db.example.com:5433/postgres\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	su, err := superuserFromFlags(setupFlags{superuserDSNFile: file})
	if err != nil || su.cfg.Password != "secret" || su.cfg.Port != 5433 || strings.Contains(su.desc, "secret") {
		t.Errorf("from a file: %+v, %v", su, err)
	}
	if _, err := superuserFromFlags(setupFlags{superuserDSN: "postgres://x@y/z", superuserDSNFile: file}); err == nil {
		t.Error("both were taken")
	}
	if _, err := superuserFromFlags(setupFlags{superuserDSN: "host=db user=postgres"}); err == nil {
		t.Error("a key=value DSN was taken, whose parts the engine's DSN cannot be made from")
	}
	if su, err := superuserFromFlags(setupFlags{}); su != nil || err != nil {
		t.Errorf("neither given: %v, %v", su, err)
	}
}

// The engine reaches the superuser's server over TCP on loopback, by address,
// without TLS there unless asked for, and keeps what a remote URL asked of TLS.
func TestTheEngineDSN(t *testing.T) {
	parse := func(raw string) *pgSuperuser {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		su, err := superuserFromURL(u)
		if err != nil {
			t.Fatal(err)
		}
		return su
	}
	for given, want := range map[string]string{
		"postgres:///postgres?host=/var/run/postgresql":        "postgres://signari_engine:PW@127.0.0.1:5433/signari?sslmode=disable",
		"postgres://postgres@localhost:5432/postgres":          "postgres://signari_engine:PW@127.0.0.1:5432/signari?sslmode=disable",
		"postgres://postgres@db.example.com/x?sslmode=require": "postgres://signari_engine:PW@db.example.com:5432/signari?sslmode=require",
	} {
		if got := engineDSN(parse(given), 5433, "signari", "PW"); got != want {
			t.Errorf("from %s:\n  got  %s\n  want %s", given, got, want)
		}
	}

	// A space in a value is written %20, not +, which pgx 5.11 and later read
	// as a +; a + is %2B; and pgx reads both back as they were given.
	su := parse("postgres://postgres@db.example.com/x?sslmode=require&options=-c%20search_path%3Dauth&application_name=a+b")
	got := engineDSN(su, 5432, "signari", "PW")
	if strings.Contains(got, "+") || !strings.Contains(got, "options=-c%20search_path%3Dauth") ||
		!strings.Contains(got, "application_name=a%2Bb") {
		t.Errorf("the engine DSN writes its query as %s", got)
	}
	cfg, err := pgx.ParseConfig(got)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RuntimeParams["options"] != "-c search_path=auth" || cfg.RuntimeParams["application_name"] != "a+b" {
		t.Errorf("pgx reads the engine DSN's query as %v", cfg.RuntimeParams)
	}
	if strings.Contains(su.desc, "+") || !strings.Contains(su.desc, "%20") {
		t.Errorf("the superuser is named %s", su.desc)
	}
}

// pg_hba.conf is judged as the server judges it: the first line that matches
// the engine's TCP connection from loopback decides, and a line setup cannot
// evaluate leaves the answer to the real sign-in.
func TestPgHbaIsJudgedByItsFirstMatchingLine(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	rule := func(kind, db, user, addr, mask, method string) hbaRule {
		return hbaRule{file: "/etc/postgresql/16/main/pg_hba.conf", line: 1, kind: kind, databases: []string{db},
			users: []string{user}, address: addr, netmask: mask, method: method}
	}
	debian := []hbaRule{rule("local", "all", "postgres", "", "", "peer"), rule("local", "all", "all", "", "", "peer"),
		rule("host", "all", "all", "127.0.0.1", "255.255.255.255", "scram-sha-256"),
		rule("host", "all", "all", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "scram-sha-256")}
	for _, c := range []struct {
		name  string
		rules []hbaRule
		want  hbaVerdict
	}{
		{"Debian's own", debian, hbaPassword},
		{"ident on loopback", []hbaRule{rule("host", "all", "all", "127.0.0.1", "255.255.255.255", "ident")}, hbaRefused},
		{"trust for everything", []hbaRule{rule("host", "all", "all", "all", "", "trust")}, hbaPassword},
		{"TLS only", []hbaRule{rule("hostssl", "all", "all", "127.0.0.1", "255.255.255.255", "scram-sha-256")}, hbaRefused},
		{"nothing for TCP", debian[:2], hbaRefused},
		{"another database first", []hbaRule{rule("host", "other", "all", "127.0.0.1", "255.255.255.255", "reject"),
			rule("host", "all", "all", "127.0.0.0", "255.0.0.0", "md5")}, hbaPassword},
		{"a reject for the role", []hbaRule{rule("host", "all", "signari_engine", "all", "", "reject")}, hbaRefused},
		{"a host name", []hbaRule{rule("host", "all", "all", "localhost", "", "scram-sha-256")}, hbaUnknown},
		{"a group", []hbaRule{rule("host", "all", "+engines", "127.0.0.1", "255.255.255.255", "md5")}, hbaUnknown},
		{"samehost", []hbaRule{rule("host", "all", "all", "samehost", "", "scram-sha-256")}, hbaPassword},
	} {
		if got, _ := judgeHBA(c.rules, "signari", engineRole, lo); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	_, r := judgeHBA([]hbaRule{rule("host", "all", "all", "127.0.0.1", "255.255.255.255", "ident")}, "signari", engineRole, lo)
	advice := hbaAdvice("signari", "/etc/postgresql/16/main/pg_hba.conf", r)
	for _, want := range []string{"host    signari    signari_engine    127.0.0.1/32    scram-sha-256", "above line 1",
		"ident", "pg_reload_conf"} {
		if !strings.Contains(advice, want) {
			t.Errorf("the advice lacks %q:\n%s", want, advice)
		}
	}
}

// The verifier setup sends is the one RFC 7677 section 3 authenticates: the
// server's signature computed from its ServerKey matches the exchange there,
// and the client proof there opens to a ClientKey whose hash is its StoredKey,
// which is the check a PostgreSQL holding this verifier makes. The suite's own
// database trusts every connection, so nothing else here would see a wrong one.
func TestTheVerifierIsTheOneRFC7677Authenticates(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	stored, server, err := scramKeys("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	auth := []byte("n=user,r=rOprNGfwEbeRWgbNEkqO," +
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
	mac := func(key []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(auth)
		return h.Sum(nil)
	}
	if got := base64.StdEncoding.EncodeToString(mac(server)); got != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Errorf("the server signature is %s", got)
	}
	proof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	signature := mac(stored)
	clientKey := make([]byte, len(proof))
	for i := range proof {
		clientKey[i] = proof[i] ^ signature[i]
	}
	if sum := sha256.Sum256(clientKey); !bytes.Equal(sum[:], stored) {
		t.Error("the RFC's client proof does not open to this StoredKey")
	}

	v, err := scramVerifierWith("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v, "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$") {
		t.Errorf("the verifier is %s", v)
	}
	random, _ := scramVerifier("pencil")
	for verifier, holds := range map[string]bool{v: true, random: true, "": false, "md5" + strings.Repeat("0", 32): false,
		"SCRAM-SHA-256$4096:x": false, strings.Replace(v, "4096", "4097", 1): false} {
		if got := scramVerifierHolds(verifier, "pencil"); got != holds {
			t.Errorf("scramVerifierHolds(%q, pencil) = %v, want %v", verifier, got, holds)
		}
	}
	if scramVerifierHolds(v, "pencil2") {
		t.Error("another password holds")
	}
}

// The log holds what a person needs after a failed run and no secret (B8):
// a password in a flag's URL, a secret inside an error, and the link's token
// are each replaced, and the file is 0600 under the state directory.
func TestTheSetupLogHoldsNoSecret(t *testing.T) {
	h := testHost(t)
	r := &setupRun{h: h, out: &bytes.Buffer{}, f: setupFlags{args: map[string]string{
		"superuser-dsn": "postgres://postgres:flag-password@db.example.com/postgres", "yes": "true",
		"email": "ada@example.com"}}}
	l, err := r.openLog()
	if err != nil || l == nil {
		t.Fatalf("opening the default log: %v", err)
	}
	r.log = l
	if want := filepath.Join(h.home, ".local", "state", "signari", setupLogName); l.path != want {
		t.Errorf("the log is %s, want %s", l.path, want)
	}
	r.password, r.rootKeyText = "engine-password-1", "root-key-text-1"
	r.link = "https://login.example.com/signup?invite=token-text-1"
	r.logStep(setupStep{name: "engine-role", what: "give it a password", state: "failed"}, h.now(),
		errors.New("refused postgres://signari_engine:engine-password-1@127.0.0.1/signari"))
	r.logStep(setupStep{name: "first-admin", what: "create the instance", state: "done"}, h.now(), nil)
	r.logStep(setupStep{name: "owner", what: "make the owner", state: "waiting", wait: ownerWait}, h.now(), nil)
	r.logf("the key was %s", r.rootKeyText)
	l.close()
	info, err := os.Stat(l.path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the log is %v (%v), want 0600", info, err)
	}
	got := mustRead(t, l.path)
	for _, secret := range []string{"flag-password", "engine-password-1", "root-key-text-1", "token-text-1"} {
		if strings.Contains(got, secret) {
			t.Errorf("the log holds %q:\n%s", secret, got)
		}
	}
	for _, want := range []string{"==== signari setup", "-email ada@example.com", " -yes",
		"postgres://postgres:…@db.example.com", "fail  engine-role", "done  first-admin",
		"signup?invite=…", "wait  owner"} {
		if !strings.Contains(got, want) {
			t.Errorf("the log lacks %q:\n%s", want, got)
		}
	}
	if lines := strings.Count(got, "\n"); lines != 6 {
		t.Errorf("%d lines, want the header's two, three steps and one more:\n%s", lines, got)
	}
	if tail := l.tail(2); len(tail) != 2 || !strings.Contains(tail[1], "the key was …") {
		t.Errorf("the log's last two lines are %q", tail)
	}
}

// A dry run prints the plan and changes nothing: no file, no directory, on a
// machine with no PostgreSQL to read either.
func TestADryRunChangesNothing(t *testing.T) {
	h := testHost(t)
	dir := t.TempDir()
	f := setupFlags{email: "you@example.com", rootKeyFile: filepath.Join(dir, "conf", rootKeyFileName),
		envFile: filepath.Join(dir, "conf", envFileName), dryRun: true, json: true,
		given: map[string]bool{"email": true, "root-key-file": true, "env-file": true, "dry-run": true, "json": true}}
	var stdout, stderr bytes.Buffer
	if err := setupCmd(context.Background(), &stdout, &stderr, h, f); err != nil {
		t.Fatalf("a dry run failed: %v\n%s", err, stderr.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a dry run made %v", entries)
	}
	if entries, _ := os.ReadDir(h.home); len(entries) != 0 {
		t.Errorf("a dry run left %v in the home directory, where its log would be", entries)
	}
	for _, want := range []string{"Plan", "create the database signari", "generate the root key",
		"Dry run: nothing was changed", "not reached: give -superuser-dsn"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the plan lacks %q:\n%s", want, stderr.String())
		}
	}
	var res setupResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("-json printed %q: %v", stdout.String(), err)
	}
	if !res.OK || !res.DryRun || res.Issuer != "http://localhost:8080" || len(res.Steps) != 8 || res.Start != "" {
		t.Errorf("the dry run's line: %+v", res)
	}
	for _, s := range res.Steps {
		if s.State != "planned" {
			t.Errorf("a dry run's step %s is %s", s.Step, s.State)
		}
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Errorf("-json printed more than one line:\n%s", stdout.String())
	}
}

// Without a terminal, a run that needs a superuser and finds none says which
// flag would give it, and changes nothing; -dsn, the engine's own connection,
// is refused rather than taken for the superuser's.
func TestARunWithNoPostgreSQLNamesTheFlag(t *testing.T) {
	h := testHost(t)
	dir := t.TempDir()
	f := setupFlags{email: "you@example.com", yes: true, envFile: filepath.Join(dir, envFileName),
		rootKeyFile: filepath.Join(dir, rootKeyFileName), given: map[string]bool{"yes": true},
		args: map[string]string{"yes": "true"}}
	var out bytes.Buffer
	err := setupCmd(context.Background(), &out, &out, h, f)
	if err == nil || !strings.HasPrefix(err.Error(), "give -superuser-dsn") || exitCode(err) != 2 {
		t.Errorf("no PostgreSQL: %v (exit %d)", err, exitCode(err))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a run refused before it began made %v", entries)
	}
	// It says where its log is, with the log's last lines, which end on why.
	logPath := filepath.Join(h.home, ".local", "state", "signari", setupLogName)
	if !strings.Contains(out.String(), "The last lines of the log, "+logPath) ||
		!strings.Contains(out.String(), "result failed: give -superuser-dsn") {
		t.Errorf("a failed run's output lacks the log's path and last lines:\n%s", out.String())
	}
	if got := mustRead(t, logPath); !strings.Contains(got, "==== signari setup") ||
		!strings.Contains(got, "flags -yes") {
		t.Errorf("the log of a failed run:\n%s", got)
	}
	f.given = map[string]bool{"dsn": true}
	if err := setupCmd(context.Background(), &out, &out, h, f); exitCode(err) != 2 || !strings.Contains(fmt.Sprint(err), "-superuser-dsn") {
		t.Errorf("-dsn: %v", err)
	}
}

// -check exits 2 for what is missing, and takes nothing it does not read.
func TestACheckOfNothingIsIncomplete(t *testing.T) {
	h := testHost(t)
	var stdout, stderr bytes.Buffer
	f := setupFlags{check: true, json: true, envFile: filepath.Join(t.TempDir(), envFileName),
		given: map[string]bool{"check": true, "json": true, "env-file": true}}
	err := setupCmd(context.Background(), &stdout, &stderr, h, f)
	if !errors.Is(err, errIncomplete) || exitCode(err) != 2 {
		t.Errorf("-check with no env file: %v (exit %d), want exit 2", err, exitCode(err))
	}
	var res struct {
		Complete bool
		Items    []checkItem
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || res.Complete || len(res.Items) != 1 {
		t.Errorf("-check -json printed %q (%v)", stdout.String(), err)
	}
	f.given["issuer"] = true
	if err := setupCmd(context.Background(), &stdout, &stderr, h, f); exitCode(err) != 2 ||
		!strings.Contains(err.Error(), "-issuer") {
		t.Errorf("-check -issuer: %v", err)
	}
}

// The plan skips what is done and has the owner's grant wait for the account
// that the first administrator's link makes.
func TestThePlanSkipsWhatIsDoneAndWaitsForTheAccount(t *testing.T) {
	now := time.Now()
	r := &setupRun{h: setupHost{now: func() time.Time { return now }}, latest: 300, keyExists: true, engineWorked: true,
		a:     setupAnswers{issuer: "https://id.example.com", email: "a@example.com", database: "signari"},
		prior: envFile{exists: true, values: map[string]string{"SIGNARI_DSN": "x", "SIGNARI_ROOT_KEY_FILE": "y", "SIGNARI_ISSUER": "z", "SIGNARI_ADDR": "w"}},
		db: dbFacts{applied: 300, instanceID: "i", signing: 2, orgID: "o", linkUntil: now.Add(time.Hour),
			linkEmail: "a@example.com"}}
	r.plan()
	for _, s := range r.steps {
		switch {
		case s.name == "owner":
			if s.skip != "" || s.wait == "" {
				t.Errorf("the owner's grant, with no account yet: skip %q, wait %q", s.skip, s.wait)
			}
		case s.skip == "":
			t.Errorf("%s is planned on a deployment that has it", s.name)
		}
	}
	r.adminID = "u"
	r.plan()
	if s := r.steps[len(r.steps)-1]; s.wait != "" || s.skip != "" {
		t.Errorf("the owner's grant, with an account: skip %q, wait %q", s.skip, s.wait)
	}
	r.db.owners = 1
	r.plan()
	if s := r.steps[len(r.steps)-1]; s.skip == "" {
		t.Error("the owner's grant is planned for an organisation that has an owner")
	}
	r.db.linkUntil = now.Add(-time.Minute)
	r.plan()
	if s := r.steps[len(r.steps)-2]; s.name != "first-admin" || s.skip != "" {
		t.Errorf("an expired link and nobody signed in: %+v", s)
	}
}

// Twice on one database, as the installer does on every run: the first run
// takes an empty database to a deployment with a link for its first
// administrator; the second changes nothing -- not a file, not a row, not the
// role's password -- and says it skipped every step; once that person has an
// account, a third makes them the owner, and a fourth again changes nothing.
func TestASecondSetupChangesNothing(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var super bool
	if err := admin.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&super); err != nil {
		t.Fatal(err)
	}
	if !super {
		t.Skip("setup needs a superuser, and SIGNARI_TEST_DSN does not sign in as one")
	}
	var verifier *string
	err = admin.QueryRow(ctx, `SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = $1`, engineRole).Scan(&verifier)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	if verifier != nil {
		t.Skip("signari_engine has a password on this cluster, which another deployment may sign in with: " +
			"setup rightly refuses to replace it, and this test will not")
	}
	// The suite signs in as signari_engine without a password, so it has none
	// again afterwards.
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `ALTER ROLE signari_engine PASSWORD NULL`)
	})
	name := fmt.Sprintf("signari_setuptest_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	dir := t.TempDir()
	tail := make([]byte, 6)
	if _, err := rand.Read(tail); err != nil {
		t.Fatal(err)
	}
	// The superuser's URL carries a password, which the log must not. A server
	// that trusts the suite's connections, as its own does, never asks for it;
	// one that does was given a password already, which is kept.
	suDSN := dsn
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if _, has := u.User.Password(); !has {
			u.User = url.UserPassword(u.User.Username(), "dsn-file-password-"+hex.EncodeToString(tail))
			suDSN = u.String()
		}
	}
	dsnFile := filepath.Join(dir, "superuser")
	if err := os.WriteFile(dsnFile, []byte(suDSN), 0o600); err != nil {
		t.Fatal(err)
	}
	issuer := "https://setup-" + hex.EncodeToString(tail) + ".test"
	keyPath, envPath := filepath.Join(dir, "conf", rootKeyFileName), filepath.Join(dir, "conf", envFileName)
	logPath := filepath.Join(dir, "log", setupLogName)
	flags := setupFlags{issuer: issuer, email: "First@Example.test", superuserDSNFile: dsnFile, database: name,
		rootKeyFile: keyPath, envFile: envPath, yes: true, json: true, logFile: logPath,
		given: map[string]bool{"issuer": true, "email": true, "superuser-dsn-file": true, "database": true,
			"root-key-file": true, "env-file": true, "yes": true, "json": true, "log-file": true},
		args: map[string]string{"issuer": issuer, "email": "First@Example.test", "superuser-dsn-file": dsnFile,
			"database": name, "root-key-file": keyPath, "env-file": envPath, "yes": "true", "json": "true",
			"log-file": logPath}}
	h := testHost(t)
	pgPassword := "pgpassword-" + hex.EncodeToString(tail)
	h.getenv = func(k string) string { return map[string]string{"PGPASSWORD": pgPassword}[k] }
	runWith := func(f setupFlags) setupResult {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if err := setupCmd(ctx, &stdout, &stderr, h, f); err != nil {
			t.Fatalf("setup: %v\n%s", err, stderr.String())
		}
		var res setupResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("setup -json printed %q: %v", stdout.String(), err)
		}
		return res
	}
	run := func() setupResult { t.Helper(); return runWith(flags) }
	states := func(res setupResult) map[string]string {
		m := map[string]string{}
		for _, s := range res.Steps {
			m[s.Step] = s.State
		}
		return m
	}

	first := run()
	if !first.OK || !strings.HasPrefix(first.Link, issuer+"/signup?invite=") || first.LinkExpires == nil {
		t.Fatalf("the first run: %+v", first)
	}
	for step, state := range states(first) {
		want := "done"
		if step == "owner" {
			want = "waiting"
		}
		if state != want {
			t.Errorf("the first run's %s step is %s, want %s", step, state, want)
		}
	}
	for _, p := range []string{keyPath, envPath} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want 0600", p, info, err)
		}
	}
	env, err := readEnvFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	login, password, database, host, err := dsnParts(env.values["SIGNARI_DSN"])
	if err != nil || login != engineRole || password == "" || database != name || host != "127.0.0.1" ||
		env.values["SIGNARI_ISSUER"] != issuer || env.values["SIGNARI_ADDR"] != "127.0.0.1:8080" ||
		env.values["SIGNARI_ROOT_KEY_FILE"] != keyPath {
		t.Errorf("the env file holds %v (%v)", env.values, err)
	}
	if strings.Contains(string(mustRead(t, envPath)), mustRead(t, dsnFile)) {
		t.Error("the superuser's connection was written to the env file")
	}

	// The engine signs in with what the env file says, as itself, and the
	// schema is what this binary serves.
	engine, err := pgx.Connect(ctx, env.values["SIGNARI_DSN"])
	if err != nil {
		t.Fatalf("the engine cannot sign in with the env file's DSN: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close(context.Background()) })
	if err := migrate.Verify(ctx, engine); err != nil {
		t.Errorf("serve's startup gate refuses the database: %v", err)
	}
	if _, _, privileged, err := roleAttrs(ctx, engine); err != nil || privileged {
		t.Errorf("the engine's role bypasses row-level security: %v, %v", privileged, err)
	}

	db, err := pgx.Connect(ctx, strings.Replace(dsn, pathOf(t, dsn), "/"+name, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	snapshot := func() string {
		t.Helper()
		var s string
		if err := db.QueryRow(ctx, `SELECT concat_ws(' ',
			(SELECT version FROM core.config_version WHERE id = true),
			(SELECT count(*) FROM core.audit_events), (SELECT count(*) FROM core.invitations),
			(SELECT count(*) FROM core.instances), (SELECT count(*) FROM core.organizations),
			(SELECT count(*) FROM core.signing_keys), (SELECT count(*) FROM core.admin_role_bindings),
			(SELECT max(version) FROM core.schema_migrations),
			(SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = 'signari_engine'))`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s + "\n" + mustRead(t, keyPath) + mustRead(t, envPath)
	}
	before := snapshot()

	second := run()
	for step, state := range states(second) {
		want := "skipped"
		if step == "owner" {
			want = "waiting"
		}
		if state != want {
			t.Errorf("the second run's %s step is %s, want %s", step, state, want)
		}
	}
	if second.Link != "" {
		t.Error("the second run printed a link: it would have withdrawn the first person's")
	}
	if after := snapshot(); after != before {
		t.Errorf("the second run changed something:\nbefore %s\nafter  %s", before, after)
	}
	check := flags
	check.check, check.given = true, map[string]bool{"check": true, "env-file": true}
	var discard bytes.Buffer
	if err := setupCmd(ctx, &discard, &discard, h, check); !errors.Is(err, errIncomplete) {
		t.Errorf("-check before anybody owns the organisation: %v\n%s", err, discard.String())
	}

	// The first person sets a password with the link, which gives them an account.
	var org string
	if err := db.QueryRow(ctx, `SELECT o.id::text FROM core.organizations o JOIN core.instances i ON i.id = o.instance_id
		WHERE i.issuer = $1`, issuer).Scan(&org); err != nil {
		t.Fatal(err)
	}
	// Before that, somebody invited later, through the Admin API, signs up
	// first. A run that names nobody makes nobody the owner: the
	// organisation's first invitation, bootstrap's, says who the first
	// administrator is, and the later one's holder is not them.
	if _, err := db.Exec(ctx, `INSERT INTO core.invitations (org_id, token_hash, email, created_at, expires_at)
		VALUES ($1::uuid, sha256(gen_random_uuid()::text::bytea), 'later@example.test', now() + interval '1 second',
		        now() + interval '1 day')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'later@example.test', sha256('l'::bytea) || sha256($1::text::bytea))`, org); err != nil {
		t.Fatal(err)
	}
	unnamed := flags
	unnamed.email, unnamed.given, unnamed.args = "", map[string]bool{}, map[string]string{}
	for k, v := range flags.given {
		if k != "email" {
			unnamed.given[k], unnamed.args[k] = v, flags.args[k]
		}
	}
	if got := states(runWith(unnamed))["owner"]; got != "waiting" {
		t.Errorf("with a later invitee signed up and the first administrator not, the owner's step is %s", got)
	}
	var anyOwner int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM core.admin_role_bindings WHERE org_id = $1::uuid
		AND role = 'org-owner'`, org).Scan(&anyOwner); err != nil || anyOwner != 0 {
		t.Fatalf("%d org-owner bindings after a run that named nobody, with only a later invitee signed up (%v)",
			anyOwner, err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'first@example.test', sha256('h'::bytea) || sha256($1::text::bytea))`, org); err != nil {
		t.Fatal(err)
	}
	third := run()
	if got := states(third)["owner"]; got != "done" {
		t.Errorf("once the first person has an account, the owner's step is %s", got)
	}
	var owners int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM core.admin_role_bindings b JOIN core.users u ON u.id = b.user_id
		WHERE b.org_id = $1::uuid AND b.role = 'org-owner' AND u.email_fold = 'first@example.test'`, org).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Errorf("%d org-owner bindings for the first person, want 1", owners)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM core.admin_role_bindings WHERE org_id = $1::uuid
		AND role = 'org-owner'`, org).Scan(&anyOwner); err != nil || anyOwner != 1 {
		t.Errorf("%d org-owner bindings in the organisation, want the first person's alone (%v)", anyOwner, err)
	}
	discard.Reset()
	if err := setupCmd(ctx, &discard, &discard, h, check); err != nil {
		t.Errorf("-check of a deployment with an owner: %v\n%s", err, discard.String())
	}
	before = snapshot()
	for step, state := range states(run()) {
		if state != "skipped" {
			t.Errorf("the fourth run's %s step is %s", step, state)
		}
	}
	if after := snapshot(); after != before {
		t.Errorf("the fourth run changed something:\nbefore %s\nafter  %s", before, after)
	}

	// Four runs in the log, each step's outcome in it, and none of the
	// secrets any run knew (B8).
	info, err := os.Stat(logPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the log: %v, %v; want 0600", info, err)
	}
	logged := mustRead(t, logPath)
	su, _ := url.Parse(suDSN)
	suPassword, _ := su.User.Password()
	for what, secret := range map[string]string{"the engine's password": password,
		"the root key": strings.TrimSpace(mustRead(t, keyPath)), "the link's token": linkToken(first.Link),
		"the superuser's password": suPassword, "PGPASSWORD": pgPassword,
		"the superuser DSN file": strings.TrimSpace(suDSN)} {
		if secret == "" {
			t.Errorf("%s is empty, so the log was not checked for it", what)
		} else if strings.Contains(logged, secret) {
			t.Errorf("the log holds %s:\n%s", what, logged)
		}
	}
	for want, n := range map[string]int{"==== signari setup": 4, "result ok": 4, "done  database": 1,
		"skip  database": 3, "done  first-admin": 1, "invite=…": 1, "wait  owner": 2, "done  owner": 1,
		"skip  owner": 1} {
		if got := strings.Count(logged, want); got != n {
			t.Errorf("the log has %q %d times, want %d:\n%s", want, got, n, logged)
		}
	}

	// The runs listed what they made, and uninstall takes it away (B14): the
	// files, the log and their directories, and, confirmed by the code, the
	// database and the root key. The roles were the cluster's before setup
	// ran, so they are neither listed nor dropped.
	m, err := readManifest(manifestPath(h.euid, h.getenv, h.home))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, e := range m.entries {
		listed[e.Kind+" "+e.Value] = true
	}
	for _, want := range []string{"root-key " + keyPath, "env-file " + envPath, "log " + logPath,
		"dir " + filepath.Dir(keyPath), "dir " + filepath.Dir(logPath),
		"database " + name + " " + dsnServer(env.values["SIGNARI_DSN"])} {
		if !listed[want] {
			t.Errorf("the manifest lacks %q: %v", want, m.entries)
		}
	}
	for e := range listed {
		if strings.HasPrefix(e, "roles") {
			t.Errorf("the manifest lists %s, which were there before setup ran", e)
		}
	}
	uf := uninstallFlags{yes: true, deleteRootKey: true, dropDatabase: true, superuserDSNFile: dsnFile}
	res, _, err := runUninstall(t, h, uf)
	if exitCode(err) != 2 || res.Confirm == "" {
		t.Fatalf("uninstall of the key and the database, unconfirmed: %v, %+v", err, res)
	}
	uf.confirm = res.Confirm
	if res, out, err := runUninstall(t, h, uf); err != nil || !res.OK {
		t.Fatalf("uninstall: %v, %+v\n%s", err, res, out)
	}
	for _, p := range []string{keyPath, envPath, logPath, filepath.Dir(keyPath), filepath.Dir(logPath)} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there after uninstall", p)
		}
	}
	var dbThere bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = $1)`,
		name).Scan(&dbThere); err != nil || dbThere {
		t.Errorf("the database is still there after uninstall -drop-database: %v", err)
	}
	var roles int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = $1`,
		engineRole).Scan(&roles); err != nil || roles != 1 {
		t.Errorf("uninstall dropped %s, which it did not make: %v", engineRole, err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pathOf is a URL DSN's path, its database.
func pathOf(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil || u.Path == "" {
		t.Skipf("SIGNARI_TEST_DSN is not a URL naming a database: %v", err)
	}
	return u.Path
}
