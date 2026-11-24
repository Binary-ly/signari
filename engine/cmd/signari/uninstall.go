package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5"
)

// `signari uninstall` takes away what the installer and `signari setup` made
// on this machine and nothing else. Each of them records what it makes, as it
// makes it, in a manifest, one thing a line, and uninstall removes exactly what
// the manifest lists: a file somebody put beside them, or a database setup
// found already there, is not its to delete.
//
// Two things are kept unless asked for by name, each confirmed: the root key
// (-delete-root-key) and the database (-drop-database), with the roles
// migration 0001 made, which are dropped only once no other database uses
// them. They are one backup, and either alone is worth nothing, so deleting
// the key and keeping the database is refused unless the person confirms it
// with a sentence saying the data becomes unreadable.

const manifestName = "install.manifest"

// manifestPath is where the manifest is kept: for root, /var/lib/signari, a
// directory root alone may write. Not /etc/signari, which belongs to the
// service's user so that it can read its key: a manifest there could be
// rewritten by that user to name what root deletes. Anybody else keeps it in
// their state directory, beside setup's log.
func manifestPath(euid int, getenv func(string) string, home string) string {
	if euid == 0 {
		return filepath.Join("/var/lib/signari", manifestName)
	}
	return filepath.Join(setupLogDir(euid, getenv, home), manifestName)
}

// manifestEntry is one thing made: its kind and where it is.
type manifestEntry struct{ Kind, Value string }

// installManifest is the manifest as read.
type installManifest struct {
	path    string
	exists  bool
	entries []manifestEntry
}

const manifestHeader = `# What the Signari installer and signari setup made on this machine, one thing
# a line. signari uninstall removes these and nothing else.
`

// engineRoles are the roles migration 0001 makes.
var engineRoles = []string{"signari_engine", "signari_admin", "signari_maintenance"}

// readManifest reads the manifest at path, which need not exist. One that
// anybody but the user running this may change, or that sits in such a
// directory, is refused: it says what to delete.
func readManifest(path string) (installManifest, error) {
	euid := os.Geteuid()
	m := installManifest{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		pi := info
		if p != path {
			if pi, err = os.Stat(p); err != nil {
				return m, err
			}
		}
		if p == path && !pi.Mode().IsRegular() {
			return m, fmt.Errorf("%s is not a regular file, so it cannot say what to delete", path)
		}
		if pi.Mode().Perm()&0o022 != 0 {
			return m, fmt.Errorf("%s may be changed by others than its owner (mode %04o), so it cannot say "+
				"what to delete: chmod go-w %s", p, pi.Mode().Perm(), p)
		}
		if uid, _, ok := dirOwner(p); ok && uid != euid {
			return m, fmt.Errorf("%s belongs to uid %d, not to the user running this, so it cannot say what "+
				"to delete", p, uid)
		}
	}
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the manifest, checked above
	if err != nil {
		return m, err
	}
	m.exists = true
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, _ := strings.Cut(line, " ")
		e := manifestEntry{kind, strings.TrimSpace(value)}
		if err := e.valid(); err != nil {
			return m, fmt.Errorf("%s, line %d: %w", path, i+1, err)
		}
		m.add(e)
	}
	return m, nil
}

// valid holds an entry to what the installer or setup makes.
func (e manifestEntry) valid() error {
	path := func() error {
		if !filepath.IsAbs(e.Value) || filepath.Clean(e.Value) != e.Value || strings.Count(e.Value, "/") < 2 {
			return fmt.Errorf("%q is not a path the installer or setup makes", e.Value)
		}
		return nil
	}
	switch e.Kind {
	case "user":
		if e.Value != "signari" {
			return fmt.Errorf("a user %q, and the installer makes signari alone", e.Value)
		}
	case "unit":
		if e.Value != unitPath {
			return fmt.Errorf("a unit %q, and the installer writes %s alone", e.Value, unitPath)
		}
	case "binary":
		if filepath.Base(e.Value) != "signari" {
			return fmt.Errorf("a binary %q, which is not signari", e.Value)
		}
		return path()
	case "database":
		name, _, _ := strings.Cut(e.Value, " ")
		return validDatabase(name)
	case "roles":
		for _, r := range strings.Fields(e.Value) {
			if !slices.Contains(engineRoles, r) {
				return fmt.Errorf("a role %q, which migration 0001 does not make", r)
			}
		}
	case "compose":
		dir, _, _ := strings.Cut(e.Value, " ")
		return manifestEntry{"dir", dir}.valid()
	case "dir", "file", "env-file", "root-key", "log":
		return path()
	default:
		return fmt.Errorf("%q is not something the installer or setup makes", e.Kind)
	}
	return nil
}

func (m *installManifest) add(e manifestEntry) {
	if !slices.Contains(m.entries, e) {
		m.entries = append(m.entries, e)
	}
}

// write puts the manifest in place whole, or removes it, and its directory
// once empty, when it lists nothing.
func (m installManifest) write(euid int) error {
	if len(m.entries) == 0 {
		if err := os.Remove(m.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		_ = os.Remove(filepath.Dir(m.path))
		return nil
	}
	var b strings.Builder
	b.WriteString(manifestHeader)
	for _, e := range m.entries {
		fmt.Fprintf(&b, "%s %s\n", e.Kind, e.Value)
	}
	if err := mkdirAllRecorded(filepath.Dir(m.path), 0o700, nil); err != nil {
		return err
	}
	return writeFileAtomic(m.path, []byte(b.String()), false, euid, nil)
}

// recordManifest adds what this run made, and is still there, to the
// manifest. A failed run records too: what it kept, the database first.
func (r *setupRun) recordManifest() {
	if r.f.dryRun || r.f.check {
		return
	}
	there := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	var add []manifestEntry
	for _, d := range r.madeDirs {
		if there(d) {
			add = append(add, manifestEntry{"dir", d})
		}
	}
	if r.createdKey && there(r.a.rootKeyFile) {
		add = append(add, manifestEntry{"root-key", r.a.rootKeyFile})
	}
	if r.createdEnv && there(r.a.envFile) {
		add = append(add, manifestEntry{"env-file", r.a.envFile})
	}
	for _, f := range r.createdFiles {
		if there(f) {
			add = append(add, manifestEntry{"file", f})
		}
	}
	if r.log != nil {
		for _, d := range r.log.madeDirs {
			add = append(add, manifestEntry{"dir", d})
		}
		if r.log.created {
			add = append(add, manifestEntry{"log", r.log.path})
		}
	}
	if r.createdDB {
		add = append(add, manifestEntry{"database", r.a.database + " " + dsnServer(r.engineDSN)})
	}
	if r.createdRoles {
		add = append(add, manifestEntry{"roles", strings.Join(engineRoles, " ")})
	}
	if len(add) == 0 {
		return
	}
	path := manifestPath(r.h.euid, r.h.getenv, r.h.home)
	m, err := readManifest(path)
	if err == nil {
		for _, e := range add {
			m.add(e)
		}
		err = m.write(r.h.euid)
	}
	if err != nil {
		fmt.Fprintf(r.out, "  What this run made could not be recorded in %s, so signari uninstall will not "+
			"remove it: %v\n", path, err)
		r.logf("could not record what this run made in %s: %v", path, err)
		return
	}
	r.logf("recorded %d made thing(s) in %s", len(add), path)
}

// dsnServer is a DSN's host and port, which name the server a database is on.
func dsnServer(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return ""
	}
	return u.Host
}

// uninstallFlags are what uninstall was given.
type uninstallFlags struct {
	dryRun, yes, json, deleteRootKey, dropDatabase bool
	confirm, superuserDSN, superuserDSNFile        string
}

// uninstallItem is one line of the plan, and what became of it.
type uninstallItem struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	What  string `json:"what"`
	// State is planned, removed, kept, gone (it was not there) or failed.
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
}

// uninstallPhase orders the removals: the service stopped before what it
// reads goes, the database before its roles and before the root key, so a
// drop that fails leaves the key with its data, and files before their
// directories.
var uninstallPhase = map[string]int{"compose": 0, "unit": 0, "file": 1, "database": 2, "roles": 3,
	"env-file": 4, "root-key": 5, "log": 6, "binary": 7, "user": 8, "dir": 9}

// uninstallPlan lays out every entry, in order, as removed or kept.
func uninstallPlan(m installManifest, f uninstallFlags) []uninstallItem {
	entries := slices.Clone(m.entries)
	slices.SortStableFunc(entries, func(a, b manifestEntry) int {
		if c := cmp.Compare(uninstallPhase[a.Kind], uninstallPhase[b.Kind]); c != 0 {
			return c
		}
		// The deepest directory first.
		return cmp.Compare(len(b.Value), len(a.Value))
	})
	var items []uninstallItem
	for _, e := range entries {
		it := uninstallItem{Kind: e.Kind, Value: e.Value, State: "planned"}
		switch e.Kind {
		case "unit":
			it.What = "stop and disable the Signari service, and delete " + e.Value
		case "env-file":
			it.What = "delete the env file " + e.Value
		case "root-key":
			it.What = "delete the root key " + e.Value
			if !f.deleteRootKey {
				it.State, it.Note = "kept", "give -delete-root-key to delete it too; without it, nothing sealed "+
					"in the database opens again"
			}
		case "database":
			name, server, _ := strings.Cut(e.Value, " ")
			it.What = "drop the database " + name + " on " + cmp.Or(server, "this machine's PostgreSQL")
			if !f.dropDatabase {
				it.State, it.Note = "kept", "give -drop-database to drop it too"
			}
		case "roles":
			it.What = "drop the roles " + strings.Join(strings.Fields(e.Value), ", ") + ", once no other " +
				"database uses them"
			if !f.dropDatabase {
				it.State, it.Note = "kept", "they go with the database"
			}
		case "log":
			it.What = "delete the log " + e.Value
		case "binary":
			it.What = "delete the binary " + e.Value
		case "user":
			it.What = "delete the system user signari"
		case "dir":
			it.What = "delete the directory " + e.Value + ", once it is empty"
		default:
			it.What = "delete " + e.Value
		}
		items = append(items, it)
	}
	return items
}

// uninstallCode is what a run with nobody to ask is confirmed with: it names
// the manifest and what cannot be had back, and the root key by its content,
// so a code printed for one key confirms the deletion of no other.
func uninstallCode(path string, items []uninstallItem) string {
	h := sha256.New()
	fmt.Fprintf(h, "signari uninstall\n%s\n", path)
	for _, it := range items {
		if it.State != "planned" || (it.Kind != "root-key" && it.Kind != "database") {
			continue
		}
		fmt.Fprintf(h, "%s %s\n", it.Kind, it.Value)
		if it.Kind == "root-key" {
			if b, err := os.ReadFile(it.Value); err == nil { // #nosec G304 G703 -- the root key the manifest names
				sum := sha256.Sum256(b)
				h.Write(sum[:])
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// keySentence is what deleting the root key while keeping the database is
// confirmed with, typed as it is.
func keySentence(database string) string {
	return "delete the root key and leave " + database + " unreadable"
}

// uninstallCmd is `signari uninstall`.
func uninstallCmd(ctx context.Context, stdout, stderr io.Writer, h setupHost, f uninstallFlags) (err error) {
	out := stdout
	if f.json {
		out = stderr
	}
	path := manifestPath(h.euid, h.getenv, h.home)
	var items []uninstallItem
	code := ""
	defer func() {
		if !f.json {
			return
		}
		res := map[string]any{"ok": err == nil, "dry_run": f.dryRun, "manifest": path, "items": items}
		if items == nil {
			res["items"] = []uninstallItem{}
		}
		if code != "" && err != nil {
			res["confirm"] = code
		}
		if err != nil {
			res["error"] = err.Error()
		}
		line, _ := json.Marshal(res)
		fmt.Fprintln(stdout, string(line))
	}()
	m, err := readManifest(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\n  signari uninstall, from %s\n", path)
	if !m.exists || len(m.entries) == 0 {
		fmt.Fprintln(out, "\n  Nothing is recorded there, so there is nothing to remove. The installer and "+
			"setup record\n  what they make from the release that has this command; remove what an earlier "+
			"one made\n  as its README says.")
		return nil
	}
	items = uninstallPlan(m, f)
	printUninstallPlan(out, items)
	if f.dryRun {
		fmt.Fprintln(out, "\n  Dry run: nothing was removed.")
		return nil
	}
	if err := confirmUninstall(out, h, f, path, items, &code); err != nil {
		return err
	}
	// A database to drop needs a superuser, found before anything goes.
	if slices.ContainsFunc(items, func(it uninstallItem) bool { return it.Kind == "database" && it.State == "planned" }) {
		conn, err := uninstallSuperuser(ctx, h, f)
		if err != nil {
			return fmt.Errorf("nothing was removed: %w", err)
		}
		_ = conn.Close(ctx)
	}
	fmt.Fprintln(out)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	var failed []string
	// The directory the manifest is in goes with the manifest, last.
	ownDir := -1
	for i := range items {
		it := &items[i]
		if it.State != "planned" {
			fmt.Fprintf(out, "  [kept] %s\n", it.What)
			continue
		}
		if it.Kind == "dir" && it.Value == filepath.Dir(path) {
			ownDir = i
			continue
		}
		if err := removeItem(ctx, h, f, it, items); err != nil {
			it.State, it.Note = "failed", err.Error()
			failed = append(failed, it.What+": "+err.Error())
			fmt.Fprintf(out, "  [failed] %s: %v\n", it.What, err)
			continue
		}
		fmt.Fprintf(out, "  [%s] %s%s\n", map[string]string{"removed": "done", "gone": "gone", "kept": "kept"}[it.State],
			it.What, map[bool]string{true: ": " + it.Note}[it.Note != ""])
	}
	// What is left stays listed, for a later run to finish.
	m.entries = nil
	for i, it := range items {
		if i != ownDir && (it.State == "kept" || it.State == "failed") {
			m.add(manifestEntry{it.Kind, it.Value})
		}
	}
	if ownDir >= 0 {
		it := &items[ownDir]
		if len(m.entries) > 0 {
			it.State, it.Note = "kept", "it holds the manifest of what is kept"
			m.add(manifestEntry{it.Kind, it.Value})
		} else {
			it.State = "removed"
		}
		fmt.Fprintf(out, "  [%s] %s\n", map[string]string{"removed": "done", "kept": "kept"}[it.State], it.What)
	}
	if err := m.write(h.euid); err != nil {
		failed = append(failed, "rewriting "+path+": "+err.Error())
	}
	if len(failed) > 0 {
		return fmt.Errorf("some of it could not be removed, and stays listed in %s for another run: %s", path,
			strings.Join(failed, "; "))
	}
	if len(m.entries) > 0 {
		fmt.Fprintf(out, "\n  Removed. What was kept stays listed in %s.\n\n", path)
	} else {
		fmt.Fprintf(out, "\n  Removed, every thing the installer and setup made here.\n\n")
	}
	return nil
}

func printUninstallPlan(w io.Writer, items []uninstallItem) {
	fmt.Fprintf(w, "\n  Removes\n")
	n := 0
	for _, it := range items {
		if it.State == "planned" {
			n++
			fmt.Fprintf(w, "    %d. %s\n", n, it.What)
		}
	}
	if n == 0 {
		fmt.Fprintln(w, "    nothing")
	}
	var kept []uninstallItem
	for _, it := range items {
		if it.State == "kept" {
			kept = append(kept, it)
		}
	}
	if len(kept) > 0 {
		fmt.Fprintf(w, "\n  Keeps\n")
		for _, it := range kept {
			fmt.Fprintf(w, "    -  %s: %s\n", strings.TrimPrefix(strings.TrimPrefix(it.What, "delete "), "drop "), it.Note)
		}
	}
}

// confirmUninstall asks, or, with nobody to ask, holds the run to -yes and,
// for what cannot be had back, to -confirm: the code a first run prints, or
// the sentence for deleting the root key while keeping the database.
func confirmUninstall(out io.Writer, h setupHost, f uninstallFlags, path string, items []uninstallItem, code *string) error {
	var key, database string
	for _, it := range items {
		switch {
		case it.Kind == "root-key" && it.State == "planned":
			key = it.Value
		case it.Kind == "database" && it.State == "planned":
			database, _, _ = strings.Cut(it.Value, " ")
		}
	}
	keptDB := ""
	if key != "" && database == "" {
		keptDB = "the database"
		for _, it := range items {
			if it.Kind == "database" {
				keptDB, _, _ = strings.Cut(it.Value, " ")
			}
		}
	}
	*code = uninstallCode(path, items)
	interactive := h.interactive && !f.yes && !f.json && !ciSet(h.getenv)
	if !interactive {
		switch {
		case keptDB != "" && f.confirm != keySentence(keptDB):
			fmt.Fprintf(out, "\n  Deleting the root key and keeping %s leaves every secret sealed in it\n"+
				"  unreadable for good. To do it anyway, run again with\n    -confirm '%s'\n", keptDB, keySentence(keptDB))
			return usageError{errors.New("give -confirm with the sentence above to delete the root key and keep " +
				"the database, or -drop-database to remove both")}
		case keptDB == "" && (key != "" || database != "") && f.confirm != *code:
			fmt.Fprintf(out, "\n  What is listed above cannot be had back. To remove it, run again with\n"+
				"    -confirm %s\n", *code)
			return usageError{errors.New("give -confirm with the code above to remove the root key or the database")}
		case !f.yes:
			return usageError{errors.New("give -yes to remove what is listed above: there is nobody at a terminal to ask")}
		}
		return nil
	}
	ask := newTermPrompter(out)
	if keptDB != "" {
		fmt.Fprintf(out, "\n  Deleting the root key and keeping %s leaves every secret sealed in it\n"+
			"  unreadable for good. To do it anyway, type:\n    %s\n", keptDB, keySentence(keptDB))
		if _, err := ask.ask("The sentence above", "", "", func(s string) error {
			return failIf(s != keySentence(keptDB), "type it as it is written")
		}); err != nil {
			return err
		}
	} else if key != "" {
		if _, err := ask.ask("Type the root key's path to delete it", key, "", func(s string) error {
			return failIf(s != key, "that is not "+key)
		}); err != nil {
			return err
		}
	}
	if database != "" {
		if _, err := ask.ask("Type the database's name to drop it", database, "", func(s string) error {
			return failIf(s != database, "that is not "+database)
		}); err != nil {
			return err
		}
	}
	ok, err := ask.confirm("Remove what is listed above?", "Nothing has been removed yet.", false)
	if err != nil {
		return err
	}
	if !ok {
		return errCancelled
	}
	return nil
}

// failIf is an error saying why when cond holds.
func failIf(cond bool, why string) error {
	if cond {
		return errors.New(why)
	}
	return nil
}

// removeItem removes one thing the manifest lists.
func removeItem(ctx context.Context, h setupHost, f uninstallFlags, it *uninstallItem, items []uninstallItem) error {
	it.State = "removed"
	remove := func(p string) error {
		err := os.Remove(p)
		if errors.Is(err, fs.ErrNotExist) {
			it.State, it.Note = "gone", "it was not there"
			return nil
		}
		return err
	}
	switch it.Kind {
	case "unit":
		if _, err := exec.LookPath("systemctl"); err == nil {
			if out, err := exec.CommandContext(ctx, "systemctl", "disable", "--now", "signari.service").CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl disable --now signari: %v: %s", err, strings.TrimSpace(string(out)))
			}
		}
		if err := remove(it.Value); err != nil {
			return err
		}
		_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
		return nil
	case "user":
		out, err := exec.CommandContext(ctx, "userdel", "signari").CombinedOutput()
		if err != nil {
			return fmt.Errorf("userdel signari: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "dir":
		err := os.Remove(it.Value)
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
			it.State, it.Note = "kept", "it holds what is kept, or what something else put there"
			return nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			it.State, it.Note = "gone", "it was not there"
			return nil
		}
		return err
	case "database":
		return dropDatabase(ctx, h, f, it)
	case "roles":
		return dropRoles(ctx, h, f, it, items)
	case "root-key":
		for _, other := range items {
			if other.Kind == "database" && other.State == "failed" {
				it.State, it.Note = "kept", "the database it opens could not be dropped"
				return nil
			}
		}
	}
	return remove(it.Value)
}

// uninstallSuperuser reaches PostgreSQL as a role that may drop databases:
// the one given, else the PostgreSQL on this machine, as setup finds it.
func uninstallSuperuser(ctx context.Context, h setupHost, f uninstallFlags) (*pgx.Conn, error) {
	su, err := superuserFromFlags(setupFlags{superuserDSN: f.superuserDSN, superuserDSNFile: f.superuserDSNFile})
	if err != nil {
		return nil, err
	}
	if su == nil {
		su = localPostgres(h)
	}
	if su == nil {
		return nil, errors.New("give -superuser-dsn (or -superuser-dsn-file) for a role that may drop databases: " +
			"there is no PostgreSQL on this machine to use")
	}
	su.cfg.Database = "postgres"
	return connectAs(ctx, su.cfg, "")
}

func dropDatabase(ctx context.Context, h setupHost, f uninstallFlags, it *uninstallItem) error {
	name, _, _ := strings.Cut(it.Value, " ")
	conn, err := uninstallSuperuser(ctx, h, f)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var there bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = $1)`,
		name).Scan(&there); err != nil {
		return err
	}
	if !there {
		it.State, it.Note = "gone", "it was not there"
		return nil
	}
	_, err = conn.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	return err
}

// dropRoles drops migration 0001's roles once no database left owns anything
// of theirs or grants them anything; a role somebody else's database still
// uses is kept, naming that database.
func dropRoles(ctx context.Context, h setupHost, f uninstallFlags, it *uninstallItem, items []uninstallItem) error {
	for _, other := range items {
		if other.Kind == "database" && other.State == "failed" {
			it.State, it.Note = "kept", "the database is still there"
			return nil
		}
	}
	conn, err := uninstallSuperuser(ctx, h, f)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	roles := strings.Fields(it.Value)
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT d.datname FROM pg_catalog.pg_shdepend s
		  JOIN pg_catalog.pg_database d ON d.oid = s.dbid
		 WHERE s.refclassid = 'pg_catalog.pg_authid'::regclass
		   AND s.refobjid IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = ANY($1))
		UNION
		SELECT datname FROM pg_catalog.pg_database
		 WHERE datdba IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = ANY($1))
		 ORDER BY 1`, roles)
	if err != nil {
		return err
	}
	using, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(using) > 0 {
		it.State, it.Note = "kept", "the database(s) "+strings.Join(using, ", ")+" still use them"
		return nil
	}
	for _, role := range roles {
		if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize()); err != nil {
			return err
		}
	}
	return nil
}
