package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A person's whole life through the API, created, renamed, re-addressed,
// deactivated and erased, leaves the audit trail holding the evidence of each
// step and none of the identifiers they could ask to have erased (3.23).
// Erasure leans on that: the trail is append-only and nothing in it is
// encrypted, so anything personal written there would survive the shred.
func TestAnErasedPersonLeavesNoIdentifierInTheAuditTrail(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()

	var org string
	if err := s.db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://scan-' || gen_random_uuid() || '.test', 'T') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 's' || substr(gen_random_uuid()::text, 1, 8), 'Org' FROM i
		RETURNING id::text`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	var start int64
	if err := s.db.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM core.audit_events`).Scan(&start); err != nil {
		t.Fatal(err)
	}

	tag := fmt.Sprint(time.Now().UnixNano())
	identifiers := []string{
		"ada" + tag + "@example.test", "ada.lovelace" + tag + "@example.test",
		"alovelace" + tag, "Ada Lovelace" + tag, "Augusta" + tag, "Byron" + tag,
	}
	rec := call(t, s, http.MethodPost, "/admin/users", testToken, map[string]any{
		"email": identifiers[0], "username": identifiers[2], "org_id": org,
	})
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("creating the user: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("no id in %s", rec.Body.String())
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = s.db.Exec(c, `DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, created.ID)
		_, _ = s.db.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, created.ID)
	})
	// A subject key, as enrolling a second factor mints one.
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.subject_keys (subject_id, wrapped_dek, wrap_key_ref)
		VALUES ($1::uuid, decode(md5(gen_random_uuid()::text), 'hex'), 'test-root')`, created.ID); err != nil {
		t.Fatal(err)
	}
	for _, patch := range []map[string]any{
		{"display_name": identifiers[3], "given_name": identifiers[4], "surname": identifiers[5]},
		{"email": identifiers[1]},
		{"active": false},
	} {
		if rec := call(t, s, http.MethodPatch, "/admin/users/"+created.ID, testToken, patch); rec.Code != http.StatusOK {
			t.Fatalf("PATCH %v: %d %s", patch, rec.Code, rec.Body.String())
		}
	}
	if code, body := erase(t, s, created.ID, `{"confirm_subject_id":"`+created.ID+`"}`); code != http.StatusOK {
		t.Fatalf("erasing: %d %v", code, body)
	}

	rows, err := s.db.Query(ctx, `
		SELECT id, event_type, COALESCE(subject_id::text, ''), concat_ws(' ', event_type,
		       org_id::text, subject_id::text, actor_id::text, client_id, correlation_id::text,
		       retention_class, detail::text, admin_token_id::text)
		  FROM core.audit_events WHERE id > $1 ORDER BY id`, start)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	evidence := map[string]bool{}
	for rows.Next() {
		var id int64
		var typ, subject, text string
		if err := rows.Scan(&id, &typ, &subject, &text); err != nil {
			t.Fatal(err)
		}
		if subject == created.ID {
			evidence[typ] = true
		}
		for _, who := range identifiers {
			if strings.Contains(strings.ToLower(text), strings.ToLower(who)) {
				t.Errorf("audit entry %d (%s) still holds %q after the erasure", id, typ, who)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"admin.user_created", "admin.user_updated", "admin.subject_erased"} {
		if !evidence[want] {
			t.Errorf("the trail has no %s for the person: the evidence was lost, not only the identifiers", want)
		}
	}
}

// Erasing a person leaves none of their identifiers anywhere in core, and a
// person who never enrolled a second factor can be erased at all (3.37). The
// shred touched only what was sealed under the subject's key, so the account,
// with the address and the names, stayed; and without a key the request was
// refused as unknown, "nothing here to destroy".
func TestAnErasedPersonLeavesNoIdentifierAnywhere(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	var org string
	if err := s.db.QueryRow(ctx, `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://wipe-' || gen_random_uuid() || '.test', 'T') RETURNING id)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'w' || substr(gen_random_uuid()::text, 1, 8), 'Org' FROM i
		RETURNING id::text`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	tag := fmt.Sprint(time.Now().UnixNano())
	identifiers := []string{"grace" + tag + "@example.test", "ghopper" + tag, "Grace Hopper" + tag, "Brewster" + tag}
	rec := call(t, s, http.MethodPost, "/admin/users", testToken, map[string]any{
		"email": identifiers[0], "username": identifiers[1], "org_id": org,
	})
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("creating the user: %d %s", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = s.db.Exec(c, `DELETE FROM core.subject_keys WHERE subject_id = $1::uuid`, created.ID)
		_, _ = s.db.Exec(c, `DELETE FROM core.users WHERE id = $1::uuid`, created.ID)
	})
	if rec := call(t, s, http.MethodPatch, "/admin/users/"+created.ID, testToken, map[string]any{
		"display_name": identifiers[2], "surname": identifiers[3]}); rec.Code != http.StatusOK {
		t.Fatalf("renaming: %d %s", rec.Code, rec.Body.String())
	}
	// Signed in, so erasure has a session to end.
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ('wipe-' || $1, $2::uuid, $1::uuid, now(), now() + interval '1 hour')`, created.ID, org); err != nil {
		t.Fatal(err)
	}

	code, body := erase(t, s, created.ID, `{"confirm_subject_id":"`+created.ID+`","deactivate":true}`)
	if code != http.StatusOK || body["account_deleted"] != true || body["key_shredded"] != false {
		t.Fatalf("erasing a person who never held a key: %d %v", code, body)
	}
	var erased bool
	if err := s.db.QueryRow(ctx, `SELECT erased_at IS NOT NULL AND wrapped_dek IS NULL
		FROM core.subject_keys WHERE subject_id = $1::uuid`, created.ID).Scan(&erased); err != nil || !erased {
		t.Errorf("no erased subject_keys row survives as the evidence: %v", err)
	}
	if code, _ := erase(t, s, created.ID, `{"confirm_subject_id":"`+created.ID+`"}`); code != http.StatusConflict {
		t.Errorf("a second erasure gave %d, want 409: the first left no record", code)
	}

	// Every text column of every core table.
	cols, err := s.db.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'core' AND data_type IN ('text', 'character varying', 'jsonb', 'json')
		  AND table_name IN (SELECT table_name FROM information_schema.tables
		                     WHERE table_schema = 'core' AND table_type = 'BASE TABLE')`)
	if err != nil {
		t.Fatal(err)
	}
	type col struct{ table, column string }
	var all []col
	for cols.Next() {
		var c col
		if err := cols.Scan(&c.table, &c.column); err != nil {
			t.Fatal(err)
		}
		all = append(all, c)
	}
	cols.Close()
	if len(all) < 100 {
		t.Fatalf("only %d text columns in core; the scan is reading the wrong thing", len(all))
	}
	patterns := make([]string, len(identifiers))
	for i, id := range identifiers {
		patterns[i] = "%" + strings.ToLower(id) + "%"
	}
	for _, c := range all {
		var n int
		if err := s.db.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM core.%q WHERE lower(%q::text) LIKE ANY($1)`,
			c.table, c.column), patterns).Scan(&n); err != nil {
			t.Fatalf("scanning core.%s.%s: %v", c.table, c.column, err)
		}
		if n > 0 {
			t.Errorf("core.%s.%s still holds an identifier of the erased person (%d row(s))", c.table, c.column, n)
		}
	}
}
