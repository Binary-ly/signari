package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/audit"
)

// The export's list of places, held to the schema. A new table that names a
// person -- by a foreign key to core.users, by being erased along with such a
// row, or by a column named for one with no key at all -- fails here until the
// export either takes the person's rows from it or says, in notAbout, that the
// column names the one who acted rather than the one the row is about.
func TestTheExportCoversEveryTableKeyedByAPerson(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)

	covered := map[string]bool{}  // "table.by"
	exported := map[string]bool{} // tables
	for _, sec := range exportSections {
		covered[sec.table+"."+sec.by] = true
		exported[sec.table] = true
	}

	var missing []string
	need := func(place, why string) {
		if !covered[place] && notAbout[place] == "" {
			missing = append(missing, place+" ("+why+")")
		}
	}

	// Every foreign key to core.users.
	rows, err := conn.Query(ctx, `
		SELECT c.conrelid::regclass::text, a.attname
		FROM pg_constraint c
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
		WHERE c.contype = 'f' AND c.confrelid = 'core.users'::regclass`)
	must(t, err)
	keyed := map[string]bool{} // "table.column" with a key to users
	fkCount := 0
	for rows.Next() {
		var table, col string
		must(t, rows.Scan(&table, &col))
		table = strings.TrimPrefix(table, "core.")
		keyed[table+"."+col] = true
		fkCount++
		need(table+"."+col, "a foreign key to core.users")
	}
	rows.Close()
	if fkCount < 40 {
		t.Fatalf("found only %d foreign keys to core.users; the catalogue query is not matching", fkCount)
	}

	// Every table erased along with a row the export takes by its person: a
	// row of theirs kept under another of theirs.
	rows, err = conn.Query(ctx, `
		SELECT c.conrelid::regclass::text, c.confrelid::regclass::text
		FROM pg_constraint c WHERE c.contype = 'f' AND c.confdeltype = 'c'`)
	must(t, err)
	type edge struct{ child, parent string }
	var cascades []edge
	for rows.Next() {
		var e edge
		must(t, rows.Scan(&e.child, &e.parent))
		cascades = append(cascades, edge{strings.TrimPrefix(e.child, "core."), strings.TrimPrefix(e.parent, "core.")})
	}
	rows.Close()
	about := map[string]bool{}
	for _, sec := range exportSections {
		if keyed[sec.table+"."+sec.by] {
			about[sec.table] = true
		}
	}
	for grew := true; grew; {
		grew = false
		for _, e := range cascades {
			if about[e.parent] && !about[e.child] && e.parent != "users" {
				about[e.child] = true
				grew = true
				if !exported[e.child] {
					missing = append(missing, e.child+" (erased with a person's "+e.parent+" row)")
				}
			}
		}
	}

	// Every column named for a person that has no foreign key.
	rows, err = conn.Query(ctx, `
		SELECT c.table_name, c.column_name FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'core' AND t.table_type = 'BASE TABLE'
		  AND c.column_name ~ '^(user_id|subject_id|actor_id|requesting_party)$|_user_id$'`)
	must(t, err)
	for rows.Next() {
		var table, col string
		must(t, rows.Scan(&table, &col))
		if !keyed[table+"."+col] {
			need(table+"."+col, "named for a person, with no foreign key")
		}
	}
	rows.Close()

	// And every section names a real table and a real way to its rows, so a
	// typo cannot cover a place by spelling it.
	for _, sec := range exportSections {
		var ok bool
		must(t, conn.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			               WHERE table_schema = 'core' AND table_name = $1 AND column_name = $2)
			    OR EXISTS (SELECT 1 FROM information_schema.tables
			               WHERE table_schema = 'core' AND table_name = $2)`, sec.table, sec.by).Scan(&ok))
		if !ok {
			t.Errorf("section %s.%s: no such column, and %q is no table", sec.table, sec.by, sec.by)
		}
	}
	for place := range notAbout {
		if !keyed[place] && place != "audit_events.actor_id" {
			t.Errorf("notAbout names %s, which is not a key to a person: remove it", place)
		}
	}

	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d place(s) keep a person's rows and the export does not look there:\n  %s\n\n"+
			"Add a section to exportSections, or, if the column names the one who acted rather than "+
			"the one the row is about, an entry in notAbout saying whose row it is.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// exportedDespiteName are text columns in exported tables whose names sound
// like a credential and are not one.
var exportedDespiteName = map[string]string{
	"authorization_codes.nonce":            "the application's own value, sent in the clear on its request",
	"preauthorized_codes.access_token_jti": "the identifier of an access token, not the token",
	"subject_keys.wrap_key_ref":            "names the root key that wraps it, not the key",
	"outbox.subject_key":                   "the delivery's ordering key",
	"audit_events.admin_token_id":          "which administrator token acted, by id",
	"audit_events.hash_version":            "which way the entry is hashed",
}

// Text columns are not withheld by type the way bytea is, so one that holds a
// credential is withheld by name. This finds the names that sound like one and
// requires each to be withheld or to say why not.
func TestEveryCredentialLikeColumnInTheExportIsDecided(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	exported := map[string]bool{}
	for _, sec := range exportSections {
		exported[sec.table] = true
	}
	credential := regexp.MustCompile(`(^|_)(hash|secret|verifier|password|key|token|nonce|ref)(_|$)`)
	rows, err := conn.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'core' AND data_type <> 'bytea'`)
	must(t, err)
	defer rows.Close()
	var undecided []string
	for rows.Next() {
		var table, col string
		must(t, rows.Scan(&table, &col))
		place := table + "." + col
		if exported[table] && credential.MatchString(col) &&
			withheldText[place] == "" && exportedDespiteName[place] == "" {
			undecided = append(undecided, place)
		}
	}
	sort.Strings(undecided)
	if len(undecided) > 0 {
		t.Errorf("exported columns named like a credential, neither withheld nor explained:\n  %s\n\n"+
			"Put each in withheldText if it holds one, or in exportedDespiteName with the reason it does not.",
			strings.Join(undecided, "\n  "))
	}
}

// A person's export holds their rows, unsealed attributes and the facts of their
// credentials, and none of the credentials themselves nor anybody else's rows.
func TestAPersonsExportHoldsTheirRowsAndNoSecret(t *testing.T) {
	ctx, orgID, userID := profileFixture(t)
	conn := connect(t)
	root := profileRoot(t)
	stamp := time.Now().UnixNano()

	var clientID string
	if err := conn.QueryRow(ctx, `SELECT client_id FROM core.clients ORDER BY created_at LIMIT 1`).
		Scan(&clientID); err != nil {
		t.Skipf("no client to have signed in to: %v", err)
	}

	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	hash := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$exportsalt%d$exporthashvalue", stamp)
	_, err = tx.Exec(ctx, `INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, userID, orgID, hash)
	must(t, err)
	sid := fmt.Sprintf("export-sid-%d", stamp)
	_, err = tx.Exec(ctx, `INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after, cookie_hash)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '1 hour', $4)`,
		sid, orgID, userID, sha256Bytes("export-cookie-"+sid))
	must(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)`, sid, clientID)
	must(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO core.recovery_codes (user_id, org_id, code_hash)
		VALUES ($1::uuid, $2::uuid, $3)`, userID, orgID, sha256Bytes(fmt.Sprintf("code-%d", stamp)))
	must(t, err)

	attr := fmt.Sprintf("home_address_%d", stamp)
	_, err = DeclareAttribute(ctx, tx, orgID, Attribute{Name: attr, ValueType: "string", Personal: true})
	must(t, err)
	must(t, SetUserAttribute(ctx, tx, userID, orgID, attr, "12 Rue de la Paix", root))

	_, err = tx.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'user', $2, 'owner', 'document', $3)`, orgID, userID, fmt.Sprintf("doc-%d", stamp))
	must(t, err)
	must(t, audit.Write(ctx, tx, audit.Event{Type: "user.created", OrgID: orgID, SubjectID: userID}))

	// Somebody else's, which this person made: an invitation to another
	// address, and a grant to another person.
	invitee := fmt.Sprintf("invitee-%d@example.test", stamp)
	_, err = tx.Exec(ctx, `INSERT INTO core.invitations (org_id, token_hash, expires_at, email, created_by)
		VALUES ($1::uuid, $2, now() + interval '1 day', $3, $4::uuid)`,
		orgID, sha256Bytes(invitee), invitee, userID)
	must(t, err)
	other := fmt.Sprintf("other-person-%d", stamp)
	_, err = tx.Exec(ctx, `INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id, granted_by)
		VALUES ($1::uuid, 'user', $2, 'viewer', 'document', 'shared', $3::uuid)`, orgID, other, userID)
	must(t, err)

	exp, err := ExportSubject(ctx, tx, userID, root)
	must(t, err)
	raw, err := json.Marshal(exp)
	must(t, err)
	doc := string(raw)

	for _, sec := range exportSections {
		if _, ok := exp.Tables[sec.table]; !ok {
			t.Errorf("the export has no %s section; an absent section reads as not looked at", sec.table)
		}
	}
	for table, want := range map[string]int{
		"users": 1, "password_credentials": 1, "sessions": 1, "session_clients": 1,
		"recovery_codes": 1, "user_attributes": 1, "relations": 1, "audit_events": 1, "invitations": 0,
	} {
		if got := len(exp.Tables[table]); got != want {
			t.Errorf("%s: %d row(s), want %d", table, got, want)
		}
	}
	if got := exp.Tables["session_clients"]; len(got) == 1 && got[0]["client_id"] != clientID {
		t.Errorf("session_clients names %v, want %s", got[0]["client_id"], clientID)
	}

	// The credentials are facts, never values.
	if strings.Contains(doc, "exporthashvalue") {
		t.Error("the export holds the password's hash")
	}
	for table, col := range map[string]string{
		"password_credentials": "hash", "sessions": "cookie_hash", "recovery_codes": "code_hash",
		"user_attributes": "value_sealed",
	} {
		if !slices.Contains(exp.Withheld[table], col) {
			t.Errorf("withheld[%s] = %v, want it to name %s", table, exp.Withheld[table], col)
		}
		for _, row := range exp.Tables[table] {
			if _, there := row[col]; there {
				t.Errorf("%s.%s is in the export", table, col)
			}
		}
	}
	if _, there := exp.Tables["users"][0]["user_handle"]; !there {
		t.Error("users.user_handle is public key material and should be exported")
	}

	// The sealed attribute, unsealed.
	var found bool
	for _, a := range exp.Attributes {
		if a.Name == attr && a.Value == "12 Rue de la Paix" && a.Readable {
			found = true
		}
	}
	if !found {
		t.Errorf("the personal attribute is not in the export unsealed: %+v", exp.Attributes)
	}

	// Nobody else's.
	if strings.Contains(doc, invitee) {
		t.Error("the export holds the address of somebody this person invited")
	}
	if strings.Contains(doc, other) {
		t.Error("the export holds a grant this person made to somebody else")
	}
}

func TestAnExportOfNobodyIsRefused(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	for _, id := range []string{"not-a-uuid", "00000000-0000-4000-8000-000000000000"} {
		if _, err := ExportSubject(ctx, tx, id, profileRoot(t)); err != ErrSubjectUnknown {
			t.Errorf("%s: %v, want ErrSubjectUnknown", id, err)
		}
	}
	if _, err := ExportSubject(ctx, tx, "00000000-0000-4000-8000-000000000000", nil); err == nil {
		t.Error("an export with no root key was attempted; its attributes would be missing")
	}
}

func sha256Bytes(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
