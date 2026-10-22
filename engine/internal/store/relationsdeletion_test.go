package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// A deleted person or group takes its relation tuples with it (0.12). Before
// migration 0179 nothing did: a group made again under a deleted one's name
// held all its grants, and a person's tuples outlived them under their id,
// address and username, which the next account to take one inherits.
func TestADeletedPersonOrGroupTakesItsRelationsWithIt(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	var orgID string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).
		Scan(&orgID); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	stamp := time.Now().UnixNano()
	email := fmt.Sprintf("Rel-%d@Example.test", stamp)
	username := fmt.Sprintf("rel-%d", stamp)
	var userID string
	must(t, tx.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email, username)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4, $5) RETURNING id::text`,
		orgID, []byte(email), []byte(username), email, username).Scan(&userID))

	grant := func(styp, sid, otyp, oid string) {
		t.Helper()
		must(t, GrantRelation(ctx, tx, orgID, Relation{SubjectType: styp, SubjectID: sid, Relation: "viewer",
			ObjectType: otyp, ObjectID: oid}, ""))
	}
	doc := fmt.Sprintf("doc-%d", stamp)
	other := fmt.Sprintf("someone-else-%d", stamp)
	grant("user", userID, "document", doc)
	grant("user", strings.ToLower(email), "document", doc+"-by-address")
	grant("user", strings.ToUpper(username), "document", doc+"-by-username")
	grant("user", other, "user", userID)
	grant("user", other, "document", doc)

	count := func(where string, args ...any) int {
		t.Helper()
		var n int
		must(t, tx.QueryRow(ctx, `SELECT count(*) FROM core.relations WHERE org_id = $1::uuid AND `+where,
			append([]any{orgID}, args...)...).Scan(&n))
		return n
	}
	_, err = tx.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`, userID)
	must(t, err)
	if n := count(`(object_id LIKE $2 OR subject_id IN ($3, $4, $5) OR object_id = $3)`,
		doc+"%", userID, strings.ToLower(email), strings.ToUpper(username)); n != 1 {
		t.Errorf("%d tuple(s) left after the person was deleted, want only somebody else's 1", n)
	}
	if count(`subject_id = $2 AND object_id = $3`, other, doc) != 1 {
		t.Error("somebody else's tuple went with the person")
	}

	// A group, deleted and made again under its name, holds none of its grants.
	name := fmt.Sprintf("rel-group-%d", stamp)
	var groupID string
	must(t, tx.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, 'g') RETURNING id::text`, orgID, name).Scan(&groupID))
	grant("group", name, "document", doc)
	grant("user", other, "group", name)
	_, err = tx.Exec(ctx, `DELETE FROM core.groups WHERE id = $1::uuid`, groupID)
	must(t, err)
	must(t, tx.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, 'g again') RETURNING id::text`, orgID, name).Scan(&groupID))
	held, err := HoldsAny(ctx, tx, orgID, "user", "a-new-member", []string{"viewer"}, "document", doc, []string{name})
	must(t, err)
	if held != "" {
		t.Errorf("a group made again under a deleted one's name holds its grant %q", held)
	}
	if n := count(`(subject_type = 'group' AND subject_id = $2) OR (object_type = 'group' AND object_id = $2)`, name); n != 0 {
		t.Errorf("%d tuple(s) of the deleted group are left", n)
	}
}

// keptAfterDeletion are the columns that name a person by text, with no foreign
// key, and are meant to outlive their account.
var keptAfterDeletion = map[string]string{
	"audit_events.subject_id": "the trail outlives the account: deleting one does not erase the record of it",
	"audit_events.actor_id":   "the same",
	"subject_keys.subject_id": "the evidence an erasure happened, and the refusal ever to mint the key again",
}

// No foreign key removes what a column names by text, so each such column is
// either cleared by a trigger on core.users when a person goes, or declared in
// keptAfterDeletion. Derived from the schema, so a table added later that names
// a person this way fails here.
func TestEveryColumnNamingAPersonWithoutAKeyIsClearedOrKept(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)

	var cleared string
	must(t, conn.QueryRow(ctx, `
		SELECT coalesce(string_agg(p.prosrc, ' '), '') FROM pg_trigger tg
		  JOIN pg_proc p ON p.oid = tg.tgfoid
		 WHERE tg.tgrelid = 'core.users'::regclass AND NOT tg.tgisinternal`).Scan(&cleared))

	rows, err := conn.Query(ctx, `
		SELECT c.table_name, c.column_name FROM information_schema.columns c
		  JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		 WHERE c.table_schema = 'core' AND t.table_type = 'BASE TABLE'
		   AND c.column_name ~ '^(user_id|subject_id|actor_id|requesting_party)$|_user_id$'
		   AND NOT EXISTS (
		       SELECT 1 FROM pg_constraint k
		         JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = ANY (k.conkey)
		        WHERE k.contype = 'f' AND k.confrelid = 'core.users'::regclass
		          AND k.conrelid = ('core.' || c.table_name)::regclass AND a.attname = c.column_name)`)
	must(t, err)
	defer rows.Close()
	var left []string
	seen := 0
	for rows.Next() {
		var table, col string
		must(t, rows.Scan(&table, &col))
		seen++
		if keptAfterDeletion[table+"."+col] == "" && !strings.Contains(cleared, "core."+table) {
			left = append(left, table+"."+col)
		}
	}
	must(t, rows.Err())
	if seen < 3 {
		t.Fatalf("found %d columns naming a person without a key; the query is not matching", seen)
	}
	sort.Strings(left)
	if len(left) > 0 {
		t.Errorf("columns name a person with no foreign key, and nothing clears them when the person "+
			"is deleted:\n  %s\n\nClear them in a trigger on core.users, as migration 0179 does for "+
			"core.relations, or put them in keptAfterDeletion with the reason they outlive the account.",
			strings.Join(left, "\n  "))
	}
}
