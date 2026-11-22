package migrate

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// compatibleMarker, on a line of a migration's leading comment, declares that
// a binary built for the version before it can run against the database it
// leaves (3.03). The ledger records the declaration, because that earlier
// binary has never seen the file. Every database used to need the exact
// version its binary was built for, so during a rolling upgrade a pod of the
// previous release that restarted crash-looped, and the only rollback was a
// restore.
//
// A declaration is checked when the migration is loaded: such a file may only
// add. A new table and whatever is defined on it, a column that is nullable or
// has a default, an index that is not unique, a new function or view, a
// comment, a grant. Anything that changes what already exists -- a column an
// older binary writes made NOT NULL, a constraint or trigger on a table it
// writes, a policy, a view or a function it reads replaced, a row it reads
// written -- is refused, naming the statement.
const compatibleMarker = "-- signari:compatible-with-previous"

// CompatibleWithPrevious reports whether the migration declares the marker.
func (m Migration) CompatibleWithPrevious() bool {
	for _, line := range strings.Split(m.SQL, "\n") {
		t := strings.TrimSpace(line)
		if t == compatibleMarker {
			return true
		}
		if t != "" && !strings.HasPrefix(t, "--") {
			return false
		}
	}
	return false
}

var (
	reCreateTable  = regexp.MustCompile(`(?i)^CREATE TABLE (?:IF NOT EXISTS )?core\.([a-z0-9_]+)\b`)
	reCreateIndex  = regexp.MustCompile(`(?i)^CREATE (UNIQUE )?INDEX (?:CONCURRENTLY )?(?:IF NOT EXISTS )?(?:[a-z0-9_]+ )?ON (?:ONLY )?core\.([a-z0-9_]+)\b`)
	reAlterTable   = regexp.MustCompile(`(?i)^ALTER TABLE (?:IF EXISTS )?(?:ONLY )?core\.([a-z0-9_]+) (.*)$`)
	reAddColumn    = regexp.MustCompile(`(?i)^ADD COLUMN (?:IF NOT EXISTS )?[a-z0-9_]+ `)
	reOnNewTable   = regexp.MustCompile(`(?i)^(?:CREATE POLICY [a-z0-9_]+|CREATE (?:CONSTRAINT )?TRIGGER [a-z0-9_]+ .*?) ON core\.([a-z0-9_]+)\b`)
	reInsertInto   = regexp.MustCompile(`(?i)^INSERT INTO core\.([a-z0-9_]+)\b`)
	reAlwaysAdds   = regexp.MustCompile(`(?i)^(?:SET (?:LOCAL )?[a-z_.]+ (?:=|TO) |CREATE FUNCTION core(?:_v1)?\.|CREATE VIEW core(?:_v1)?\.|COMMENT ON |GRANT )`)
	reNotNull      = regexp.MustCompile(`(?i)\bNOT NULL\b`)
	reDefault      = regexp.MustCompile(`(?i)\bDEFAULT\b`)
	reSecondClause = regexp.MustCompile(`(?i),\s*(?:ADD|ALTER|DROP|RENAME)\s`)
	reSpace        = regexp.MustCompile(`\s+`)
)

// checkCompatible refuses a marked migration that does anything but add.
func checkCompatible(m Migration) error {
	if m.Tier() == TierBootstrap {
		return fmt.Errorf("the bootstrap cannot be %s", compatibleMarker)
	}
	created := map[string]bool{}
	for _, raw := range splitStatements(m.SQL) {
		s := reSpace.ReplaceAllString(strings.TrimSpace(raw), " ")
		if s == "" {
			continue
		}
		refuse := func(why string) error {
			return fmt.Errorf("it is marked %s, and %.70q %s", compatibleMarker, s, why)
		}
		switch {
		case reAlwaysAdds.MatchString(s):
		case reCreateTable.MatchString(s):
			created[strings.ToLower(reCreateTable.FindStringSubmatch(s)[1])] = true
		case reCreateIndex.MatchString(s):
			g := reCreateIndex.FindStringSubmatch(s)
			if g[1] != "" && !created[strings.ToLower(g[2])] {
				return refuse("refuses writes an earlier binary makes to a table it already has")
			}
		case reAlterTable.MatchString(s):
			g := reAlterTable.FindStringSubmatch(s)
			if created[strings.ToLower(g[1])] {
				break
			}
			rest := g[2]
			if !reAddColumn.MatchString(rest) || reSecondClause.MatchString(rest) {
				return refuse("changes a table an earlier binary already uses; only one ADD COLUMN per statement adds")
			}
			if reNotNull.MatchString(rest) && !reDefault.MatchString(rest) {
				return refuse("adds a NOT NULL column with no default, which an earlier binary's inserts leave empty")
			}
		case reOnNewTable.MatchString(s):
			if !created[strings.ToLower(reOnNewTable.FindStringSubmatch(s)[1])] {
				return refuse("changes what an earlier binary may do to a table it already has")
			}
		case reInsertInto.MatchString(s):
			if !created[strings.ToLower(reInsertInto.FindStringSubmatch(s)[1])] {
				return refuse("writes rows an earlier binary reads without knowing them")
			}
		default:
			return refuse("is not one of the statements that only add")
		}
	}
	return nil
}

// splitStatements splits SQL on the semicolons that end statements, skipping
// comments and leaving quoted strings, quoted identifiers and dollar-quoted
// bodies whole.
func splitStatements(sql string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == '-' && i+1 < len(sql) && sql[i+1] == '-':
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				i = len(sql)
			} else {
				i += end + 4
			}
			cur.WriteByte(' ')
			continue
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(sql) {
				if sql[j] == c {
					if j+1 < len(sql) && sql[j+1] == c {
						j += 2
						continue
					}
					break
				}
				j++
			}
			cur.WriteString(sql[i:min(j+1, len(sql))])
			i = j + 1
			continue
		case c == '$':
			if tag := dollarTag(sql[i:]); tag != "" {
				end := strings.Index(sql[i+len(tag):], tag)
				if end < 0 {
					cur.WriteString(sql[i:])
					i = len(sql)
				} else {
					stop := i + len(tag) + end + len(tag)
					cur.WriteString(sql[i:stop])
					i = stop
				}
				continue
			}
		case c == ';':
			out = append(out, cur.String())
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(c)
		i++
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

var reDollarTag = regexp.MustCompile(`^\$[A-Za-z_]*\$`)

func dollarTag(s string) string { return reDollarTag.FindString(s) }

// ledgerColumns reports which of the ledger's later columns exist, so a
// migration applied before the one that added a column can still be recorded.
func ledgerColumns(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (map[string]bool, error) {
	var names []string
	err := q.QueryRow(ctx, `
		SELECT COALESCE(array_agg(attname::text), '{}') FROM pg_catalog.pg_attribute
		WHERE attrelid = to_regclass('core.schema_migrations') AND attnum > 0 AND NOT attisdropped`).
		Scan(&names)
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, n := range names {
		has[n] = true
	}
	return has, nil
}
