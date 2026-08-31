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
// caller. It passed while twelve capabilities were unusable, because each one's
// loader genuinely had a call site — on the request path, running on every
// request, querying a table or column no operator could put a row in.
//
// That failure is invisible in the worst way. There is no error and no warning:
// the loader finds nothing, returns the documented default, and the feature
// reads as "configured off" rather than "impossible to configure". It survives
// unit tests, because a test inserts its own fixture row and then proves the
// reader works — the fixture IS the write path the product does not have.
//
// # The first version of this test covered half the schema and said so
//
// It matched `core.<table>` only. **Fifty-seven of the hundred and thirteen core
// tables are created unqualified** — `CREATE TABLE saml_providers (`, relying on
// search_path — so the guard was blind to `clients`, `users`, `sessions`,
// `saml_providers` and fifty-three others while reporting a clean run. It also
// looked only at columns added by `ALTER TABLE … ADD COLUMN`, missing every
// column declared in the original `CREATE TABLE`.
//
// `core.saml_providers.attributes` sat in exactly that blind spot: a column whose
// own comment records that it was dead for months, given a reader, and still
// unwritable. A guard that reports "clean" over the case it was written for is
// worse than no guard, because it converts an open question into a settled one.
//
// # What is exempt, and why each exemption is narrow
//
//   - Database-owned defaults (`now()`, `gen_random_uuid()`, serial, identity).
//     The database supplies the value; no code should.
//   - A table whose singleton row its own migration seeds, and which code
//     UPDATEs. `core.audit_stream_state` is the shape: one row, created with the
//     schema, moved forward and never re-created.
//   - The named backlog below. Every entry is a real finding, recorded rather
//     than hidden, and the list may only shrink.
//
// DELETE is never a write path. A table you can only delete from is exactly as
// unpopulatable as one with no writer, and counting it would let that case read
// as covered.

// knownUnwritable is the backlog this guard found and this change did not close.
//
// It is here rather than suppressed because the alternative to an explicit list
// is a narrower test that reports clean — which is how the first version of this
// file missed the column it was written for. Anything NOT on this list fails the
// build, so no new one can be added quietly.
//
// Each entry says what is fixed at its default as a result. **Delete entries as
// they are closed; never add one to make a build pass.**
var knownUnwritable = map[string]string{
	// The engine's own runtime state, not operator configuration. These are
	// written by nothing because the feature that would write them is absent,
	// which is a different repair from adding a command.
	"access_tokens.token_hash":       "the table is never inserted into, so the admin API's active-token count is structurally always zero",
	"access_tokens.client_id":        "same table",
	"access_tokens.user_id":          "same table",
	"access_tokens.org_id":           "same table",
	"access_tokens.sid":              "same table",
	"access_tokens.scopes":           "same table",
	"access_tokens.resources":        "same table",
	"access_tokens.expires_at":       "same table",
	"access_tokens.revoked_at":       "same table",
	"sessions.ip_hash":               "never recorded at sign-in, so the admin session list always reports no address",
	"sessions.user_agent":            "the same; the list always shows an empty user agent",
	"audit_events.detail_enc":        "known: zero readers and zero writers, already named in the plan's documentation-honesty item",
	"providers.wrap_key_ref":         "sealing context for provider credentials; no provider stores a secret yet",
	"credential_nonces.org_id":       "written by the nonce path, which does not yet scope by organisation",
	"registration_tokens.revoked_at": "a registration token can be spent but not revoked before it is",

	// Reported by the console through core_v1 and enforced NOWHERE on the request
	// path. A command to set these would be the same defect from the other side:
	// a suspension switch that suspends nothing is worse than an absent one,
	// because an operator would believe the organisation was out of service.
	// Closing this means enforcement first, at every sign-in and token path, then
	// the command.
	"organizations.status": "a suspended organisation is still served; nothing on the request path reads it",
	"instances.status":     "the same for an issuer",

	// Per-client protocol settings with no command. Each is a real gap; they
	// cluster into a small number of `client set-*` verbs.
	"clients.access_token_ttl_s":                   "per-client token lifetime is fixed at 300s in every deployment",
	"clients.refresh_token_ttl_s":                  "per-client refresh lifetime fixed at 30 days",
	"clients.id_token_signed_alg":                  "per-client ID token algorithm fixed at ES256",
	"clients.pkce_methods":                         "fixed at S256",
	"clients.require_pushed_authorization":         "PAR cannot be required per client",
	"clients.may_exchange":                         "RFC 8693 token exchange cannot be granted per client",
	"clients.exchange_audiences":                   "nor its audience list bounded",
	"clients.first_party":                          "first-party consent skipping cannot be granted",
	"clients.frontchannel_logout_uri":              "front-channel logout cannot be registered",
	"clients.frontchannel_logout_session_required": "nor its sid requirement changed",
	"clients.issuer_alias":                         "a client cannot be pinned to an issuer alias",

	// Tables with no create path at all.
	"client_post_logout_redirect_uris.client_id":    "no command registers a post-logout redirect URI",
	"client_post_logout_redirect_uris.redirect_uri": "the same",
	"instance_issuer_aliases.instance_id":           "issuer aliases cannot be registered, so issuer migration is unavailable",
	"instance_issuer_aliases.issuer":                "the same",
	"instance_issuer_aliases.retire_after":          "the same",
	"migration_sources.kind":                        "delegated verification against an old provider cannot be configured",
	"migration_sources.org_id":                      "the same",
	"migration_sources.display_name":                "the same",
	"migration_sources.token_endpoint":              "the same",
	"migration_sources.client_id":                   "the same",
	"migration_sources.client_secret_enc":           "the same",
	"migration_sources.scope":                       "the same",
	"migration_sources.enabled":                     "the same",
	"proxy_hosts.host":                              "no command registers a forward-auth host",
	"proxy_hosts.org_id":                            "the same",
	"proxy_hosts.enabled":                           "the same",
	"projects.slug":                                 "projects cannot be created",
	"projects.org_id":                               "the same",
	"projects.display_name":                         "the same",

	// Enable/disable switches with no command.
	"outposts.enabled":           "an outpost cannot be taken out of service without deleting it",
	"prompts.enabled":            "a prompt cannot be switched off",
	"rac_connections.enabled":    "a remote-access connection cannot be disabled",
	"rac_connections.parameters": "protocol parameters cannot be set",
	"ssf_streams.status":         "a Shared Signals stream cannot be paused",

	// Smaller policy settings.
	"client_attesters.description":             "cosmetic",
	"credential_configurations.format":         "fixed at dc+sd-jwt",
	"federation_config.contacts":               "federation entity contacts cannot be published",
	"federation_config.trust_anchor_hints":     "nor trust anchor hints",
	"federation_config.lifetime_seconds":       "nor the entity statement lifetime",
	"registration_policies.allow_confidential": "dynamic registration cannot be allowed to mint confidential clients",
	"signup_rules.require_verified_email":      "self-signup email verification cannot be relaxed",
}

var (
	createTable = regexp.MustCompile(`(?is)CREATE TABLE (?:IF NOT EXISTS )?(?:core\.)?([a-z_]+)\s*\((.*?)\n\);`)
	alterTable  = regexp.MustCompile(`(?is)ALTER TABLE\s+(?:core\.)?([a-z_]+)(.*?);`)
	addColName  = regexp.MustCompile(`(?i)ADD COLUMN\s+(?:IF NOT EXISTS\s+)?([a-z_]+)\s+([a-z_]+(?:\[\])?)([^,]*)`)
	colDecl     = regexp.MustCompile(`(?i)^([a-z_]+)\s+([a-z_]+(?:\[\])?)\b(.*)$`)
	// Values the database supplies. A column with one of these is not
	// configuration and no code should be setting it.
	dbOwned = regexp.MustCompile(`(?i)now\(\)|gen_random_uuid\(\)|nextval|uuid_generate|current_timestamp|generated always as identity`)
)

var notAColumn = map[string]bool{
	"PRIMARY": true, "UNIQUE": true, "CHECK": true, "CONSTRAINT": true,
	"FOREIGN": true, "EXCLUDE": true, "LIKE": true,
}

// schemaColumn is one column and enough of its declaration to judge it.
type schemaColumn struct {
	table, column, typ, rest string
}

// readSchema parses every core table and column out of the migrations.
//
// Both spellings, because the migrations use both: `CREATE TABLE core.x` and
// `CREATE TABLE x` relying on search_path. Matching only the first is the bug
// that made the first version of this file blind to half the schema.
func readSchema(t *testing.T, root string) (tables []string, columns []schemaColumn) {
	t.Helper()
	dir := filepath.Join(root, "engine", "migrations", "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	seen := map[string]bool{}
	for _, n := range names {
		body, rerr := os.ReadFile(filepath.Join(dir, n))
		if rerr != nil {
			t.Fatal(rerr)
		}
		src := string(body)

		for _, m := range createTable.FindAllStringSubmatch(src, -1) {
			seen[m[1]] = true
			for _, line := range strings.Split(m[2], "\n") {
				line = strings.TrimSpace(strings.SplitN(line, "--", 2)[0])
				cm := colDecl.FindStringSubmatch(line)
				if cm == nil || notAColumn[strings.ToUpper(cm[1])] {
					continue
				}
				columns = append(columns, schemaColumn{m[1], cm[1], strings.ToLower(cm[2]), cm[3]})
			}
		}
		for _, m := range alterTable.FindAllStringSubmatch(src, -1) {
			seen[m[1]] = true
			for _, cm := range addColName.FindAllStringSubmatch(m[2], -1) {
				columns = append(columns, schemaColumn{m[1], cm[1], strings.ToLower(cm[2]), cm[3]})
			}
		}
	}
	for name := range seen {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	return tables, columns
}

// sourceFiles returns every non-test Go and PHP file that could touch the
// database.
//
// Migrations are excluded deliberately: a migration's own INSERT is schema
// setup, not a write path an operator can reach.
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
			case strings.HasSuffix(path, "_test.go"),
				strings.Contains(path, "/migrations/"),
				strings.Contains(path, "/vendor/"),
				strings.Contains(path, "/node_modules/"):
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
func TestEveryTableTheEngineReadsCanBeWritten(t *testing.T) {
	root := repoRoot(t)
	files := sourceFiles(t, root)
	tables, _ := readSchema(t, root)

	for _, table := range tables {
		read := regexp.MustCompile(`(?i)(?:FROM|JOIN)\s+core\.` + table + `\b`)
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
		if canChange && migrationSeeds(t, root, table) {
			continue
		}
		// A table every one of whose columns is a known finding is already
		// recorded; reporting it again as a table adds noise, not information.
		if tableFullyKnown(t, root, files, table) {
			continue
		}
		sort.Strings(readers)
		t.Errorf("core.%s is read by %d file(s) and no code can put a row in it.\n\n"+
			"  read from: %s\n\n"+
			"Nothing an operator can run creates a row, so the loader finds nothing "+
			"on every request and returns the default. That is not a feature that is "+
			"switched off — it is a feature that cannot be switched on, and it reports "+
			"no error either way.\n\n"+
			"Add a write path and document it.",
			table, len(readers), strings.Join(readers, ", "))
	}
}

// tableFullyKnown reports whether the table's inability to hold a row is already
// described, column by column, in the backlog — in which case reporting the
// table as well only repeats what is recorded.
//
// It asks about the columns that WOULD FAIL, not every column. The first version
// required all of them, so one column the code happens to UPDATE — a counter
// like `migration_sources.delegated_successes` — was enough to make the whole
// table report twice.
func tableFullyKnown(t *testing.T, root string, files map[string]string, table string) bool {
	t.Helper()
	_, cols := readSchema(t, root)

	var everything strings.Builder
	for _, body := range files {
		everything.WriteString(strings.ToLower(body))
		everything.WriteString("\n")
	}
	all := everything.String()

	stmt := regexp.MustCompile(`(?is)(?:INSERT INTO|UPDATE|COPY)\s+core\.` + table + `\b(.*?)(?:;|` + "`" + `)`)
	var w strings.Builder
	for _, body := range files {
		for _, m := range stmt.FindAllStringSubmatch(body, -1) {
			w.WriteString(strings.ToLower(m[1]))
			w.WriteString("\n")
		}
	}
	written := w.String()

	var anyFailing bool
	for _, c := range cols {
		if c.table != table {
			continue
		}
		if dbOwned.MatchString(c.rest) || c.typ == "bigserial" || c.typ == "serial" ||
			c.typ == "smallserial" {
			continue
		}
		word := regexp.MustCompile(`\b` + regexp.QuoteMeta(c.column) + `\b`)
		if !word.MatchString(all) || word.MatchString(written) {
			continue // unreferenced, or genuinely written
		}
		anyFailing = true
		if _, ok := knownUnwritable[c.table+"."+c.column]; !ok {
			return false
		}
	}
	return anyFailing
}

// TestEveryColumnTheEngineReadsCanBeWritten.
//
// Every column of every core table, however it was declared — not only the ones
// added by ALTER TABLE, which is what the first version checked and why it
// missed `saml_providers.attributes`.
func TestEveryColumnTheEngineReadsCanBeWritten(t *testing.T) {
	root := repoRoot(t)
	files := sourceFiles(t, root)
	_, columns := readSchema(t, root)

	var all strings.Builder
	for _, body := range files {
		all.WriteString(strings.ToLower(body))
		all.WriteString("\n")
	}
	everything := all.String()

	// The text of every write statement per table, gathered once. Non-greedy to
	// the first terminator — a `;` in SQL or the backtick closing a Go raw string
	// — so one INSERT does not swallow the file and make every column look
	// written.
	writes := map[string]string{}
	writeFor := func(table string) string {
		if v, ok := writes[table]; ok {
			return v
		}
		stmt := regexp.MustCompile(`(?is)(?:INSERT INTO|UPDATE|COPY)\s+core\.` + table + `\b(.*?)(?:;|` + "`" + `)`)
		var b strings.Builder
		for _, body := range files {
			for _, m := range stmt.FindAllStringSubmatch(body, -1) {
				b.WriteString(strings.ToLower(m[1]))
				b.WriteString("\n")
			}
		}
		writes[table] = b.String()
		return writes[table]
	}

	stale := map[string]bool{}
	for k := range knownUnwritable {
		stale[k] = true
	}

	for _, c := range columns {
		if dbOwned.MatchString(c.rest) || c.typ == "bigserial" || c.typ == "serial" ||
			c.typ == "smallserial" {
			continue
		}
		word := regexp.MustCompile(`\b` + regexp.QuoteMeta(c.column) + `\b`)
		if !word.MatchString(everything) {
			continue // never referenced anywhere; unused, not unwritable
		}
		if word.MatchString(writeFor(c.table)) {
			continue
		}
		key := c.table + "." + c.column
		if _, known := knownUnwritable[key]; known {
			delete(stale, key)
			continue
		}
		t.Errorf("core.%s is read by the code and set by no INSERT or UPDATE.\n\n"+
			"A column the engine consults and nothing writes always holds its "+
			"default, so the behaviour it governs is fixed at whatever that default "+
			"happens to be — silently, and identically in every deployment.\n\n"+
			"Add a write path and document it, drop the column, or record it in "+
			"knownUnwritable with what stays fixed as a result.", key)
	}

	// An entry that no longer describes anything means the gap was closed and
	// the list was not. Left alone it accumulates until nobody trusts it.
	for key := range stale {
		t.Errorf("knownUnwritable lists %q, which now has a write path.\n\n"+
			"Remove the entry. A backlog that keeps closed items is one people stop "+
			"reading, and this list is only useful while every line is still true.", key)
	}
}
