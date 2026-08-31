package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Anything the engine READS for a decision must be writable by somebody.
//
// # The defect this exists to catch
//
// `TestEveryConfigurableCapabilityIsReachable` checks that a function has a
// caller. It passed while TEN capabilities were unusable, because each one's
// loader genuinely had a call site — on the request path, running on every
// request, querying a table no operator could put a row in.
//
// That failure is invisible in the worst way. There is no error and no warning:
// the loader finds nothing, returns the documented default, and the feature
// reads as "configured off" rather than "impossible to configure". It survives
// unit tests, because a test inserts its own fixture row and then proves the
// reader works. It survives a code review, because every individual file is
// correct. What is missing is a file nobody wrote.
//
// The ten:
//
//	core.webauthn_policy             approved-authenticator lists
//	core.idp_attribute_map           federated claim to local attribute
//	core.directory_group_map         which directory group grants which local group
//	core.radius_group_authorization  VLAN and Filter-Id per group
//	core.scim_group_links            outbound group provisioning
//	core.users.locale                the language a security notice is written in
//	core.providers.allowed_claims    what a token hook may add
//	core.admin_tokens.client_ids     object-scoped admin tokens
//	core.admin_tokens.group_ids      the same
//	core.scim_targets.scope_group_id limiting a target to one group
//
// A function being called is not the same as a capability being reachable, and
// the difference is exactly one table nobody can write to.

// sqlIdent matches a schema-qualified core table.
var (
	createTable = regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?core\.([a-z_]+)`)
	addColumn   = regexp.MustCompile(`(?is)ALTER TABLE\s+core\.([a-z_]+)(.*?);`)
	addColName  = regexp.MustCompile(`(?i)ADD COLUMN\s+(?:IF NOT EXISTS\s+)?([a-z_]+)`)
)

// sourceFiles returns every non-test Go and PHP file that could touch the
// database, with its repo-relative path.
//
// Migrations are excluded deliberately: a migration's own INSERT is schema
// setup, not a write path an operator can reach. A default row shipped by a
// migration is the shape that makes a dead table look alive.
func sourceFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{"engine", "admin"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			switch {
			case strings.HasSuffix(path, "_test.go"):
				return nil
			case strings.Contains(path, "/migrations/"):
				return nil
			case strings.Contains(path, "/vendor/"):
				return nil
			case strings.HasSuffix(path, ".go"), strings.HasSuffix(path, ".php"):
			default:
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, path)
			out[rel] = string(src)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func coreTables(t *testing.T, root string) []string {
	t.Helper()
	dir := filepath.Join(root, "engine", "migrations", "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, m := range createTable.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = true
		}
	}
	var out []string
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// migrationSeeds reports whether a migration inserts rows into this table.
//
// The singleton-state shape: one row created with the schema, updated forever
// after, never inserted again. Treating that as unwritable would be a false
// alarm on a correct design, and a guard that cries wolf is one somebody
// silences.
func migrationSeeds(t *testing.T, root, table string) bool {
	t.Helper()
	dir := filepath.Join(root, "engine", "migrations", "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := regexp.MustCompile(`(?i)INSERT INTO (?:core\.)?` + table + `\b`)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if seed.Match(src) {
			return true
		}
	}
	return false
}

// TestEveryTableTheEngineReadsCanBeWritten.
//
// The rule is one sentence: if code reads a table, code must also write it.
// A table with neither is merely unused and is caught by review; a table with a
// reader and no writer is a feature that cannot be turned on.
func TestEveryTableTheEngineReadsCanBeWritten(t *testing.T) {
	root := repoRoot(t)
	files := sourceFiles(t, root)

	for _, table := range coreTables(t, root) {
		read := regexp.MustCompile(`(?i)(?:FROM|JOIN)\s+core\.` + table + `\b`)
		// The property is "code can change what this table says", which two
		// different statements satisfy and one does not:
		//
		//   INSERT / COPY  creates rows. Always a write path.
		//   UPDATE         changes rows that already exist. A write path only if
		//                  something puts a row there — which for a singleton
		//                  state table is its own migration, by design.
		//   DELETE         removes rows. NEVER sufficient on its own: a table you
		//                  can only delete from is exactly as unpopulatable as
		//                  one with no writer, and counting it would let that
		//                  case read as covered.
		insert := regexp.MustCompile(`(?i)(?:INSERT INTO|COPY)\s+core\.` + table + `\b`)
		update := regexp.MustCompile(`(?i)UPDATE\s+core\.` + table + `\b`)

		var readers []string
		var canCreate, canChange bool
		for rel, body := range files {
			if read.MatchString(body) {
				readers = append(readers, rel)
			}
			if insert.MatchString(body) {
				canCreate = true
			}
			if update.MatchString(body) {
				canChange = true
			}
		}
		if len(readers) == 0 || canCreate {
			continue
		}
		// An UPDATE-only table is fine when a migration seeds the row it updates.
		// `core.audit_stream_state` is the shape: one row, created by its own
		// migration, moved forward and never re-created. It is not the shape this
		// test is looking for, and failing it would be wrong.
		if canChange && migrationSeeds(t, root, table) {
			continue
		}
		sort.Strings(readers)
		t.Errorf("core.%s is read by %d file(s) and no code can put a row in it.\n\n"+
			"  read from: %s\n\n"+
			"Nothing an operator can run puts a row in it, so the loader finds "+
			"nothing on every request and returns the default. That is not a "+
			"feature that is switched off — it is a feature that cannot be "+
			"switched on, and it reports no error either way.\n\n"+
			"Add a write path (a CLI verb, an admin API handler, or a config-as-code "+
			"apply step) and document it.",
			table, len(readers), strings.Join(readers, ", "))
	}
}

// TestEveryColumnAddedForBehaviourCanBeWritten.
//
// Columns added by ALTER TABLE are checked the same way, against the statements
// that actually write their table rather than against a bare mention. A column
// named only inside a SELECT is read-only by definition, and a read-only setting
// is a setting nobody can set.
func TestEveryColumnAddedForBehaviourCanBeWritten(t *testing.T) {
	root := repoRoot(t)
	files := sourceFiles(t, root)

	dir := filepath.Join(root, "engine", "migrations", "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// table -> columns added after the table was created.
	added := map[string][]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, m := range addColumn.FindAllStringSubmatch(string(src), -1) {
			for _, c := range addColName.FindAllStringSubmatch(m[2], -1) {
				added[m[1]] = append(added[m[1]], strings.ToLower(c[1]))
			}
		}
	}

	for table, cols := range added {
		// The text of every write statement against this table, across the tree.
		// Bounded at the statement, so a column mentioned in the next query does
		// not count as written by this one.
		// Non-greedy to the first statement terminator: a `;` in SQL, or the
		// backtick that closes a Go raw string. Without the bound, one INSERT
		// would swallow the rest of the file and every column would look written.
		stmt := regexp.MustCompile(`(?is)(?:INSERT INTO|UPDATE|COPY)\s+core\.` + table + `\b(.*?)(?:;|` + "`" + `)`)
		var writes strings.Builder
		for _, body := range files {
			for _, m := range stmt.FindAllStringSubmatch(body, -1) {
				writes.WriteString(strings.ToLower(m[1]))
				writes.WriteString("\n")
			}
		}
		written := writes.String()

		// And whether anything reads it at all. A column neither read nor
		// written is unused, which is a different (and lesser) problem.
		var allSrc strings.Builder
		for _, body := range files {
			allSrc.WriteString(strings.ToLower(body))
		}
		everything := allSrc.String()

		for _, col := range cols {
			word := regexp.MustCompile(`\b` + regexp.QuoteMeta(col) + `\b`)
			if !word.MatchString(everything) {
				continue // never referenced; not this test's subject
			}
			if word.MatchString(written) {
				continue
			}
			t.Errorf("core.%s.%s is read by the code and set by no INSERT or UPDATE.\n\n"+
				"A column the engine consults and nothing writes always holds its "+
				"default, so the behaviour it governs is fixed at whatever that "+
				"default happens to be — silently, and identically in every "+
				"deployment.\n\n"+
				"Add a write path and document it, or drop the column.",
				table, col)
		}
	}
}
