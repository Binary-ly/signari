package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
)

// Everything kept about one person, for them (5.08).
//
// The right of access and the right to portability ask for the same thing: what
// is held about a person, in a form a machine can read. Nothing produced it, so
// an operator answering a request had to know every table, and the schema has
// fifty that name a person. ExportSubject is that answer, for the person at
// /account/export and for an operator through `signari export subject` and the
// Admin API.
//
// exportSections is the list of places, and it cannot go stale quietly:
// TestTheExportCoversEveryTableKeyedByAPerson derives the places from the schema
// -- every foreign key to core.users, every table erased along with one of those
// rows, every column named for a person with no foreign key -- and fails on any
// this list neither exports nor names in notAbout.
//
// What is withheld is withheld by rule: every bytea column except the public key
// material in publicBytes (hashes of codes and tokens, sealed secrets, the
// wrapped subject key), and the text columns in withheldText, which hold a
// credential. A password hash handed to a person is a password hash on whatever
// laptop the file ends up on. The export lists what it withheld, so that a
// password is set, or a code outstanding, is still there as a fact. Personal
// attributes are sealed too, and are the person's data rather than a
// credential, so they are unsealed into Attributes.

// ExportFormat names the document's shape, for whoever reads it next.
const ExportFormat = "signari-subject-export/1"

// SubjectExport is the document.
type SubjectExport struct {
	Format     string    `json:"format"`
	SubjectID  string    `json:"subject_id"`
	ExportedAt time.Time `json:"exported_at"`
	// Tables holds the person's rows, by table, every section present even
	// when empty, so an empty list says "nothing here" rather than "not looked".
	Tables map[string][]map[string]any `json:"tables"`
	// Attributes are the person's attribute values, unsealed.
	Attributes []ExportedAttribute `json:"attributes"`
	// Withheld names, by table, the columns left out of Tables.
	Withheld map[string][]string `json:"withheld"`
}

// ExportedAttribute is one attribute value.
type ExportedAttribute struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Value       string `json:"value"`
	Readable    bool   `json:"readable"`
}

// Rows counts the rows in the export, for the record of it.
func (e *SubjectExport) Rows() int {
	n := 0
	for _, rows := range e.Tables {
		n += len(rows)
	}
	return n
}

// exportSection is one place a person's rows are kept.
type exportSection struct {
	table string
	// by ties a row to the person: a column of the table, or for a row kept
	// under another of theirs, that parent table.
	by string
	// where selects their rows, as a condition on t with $1 the person's id.
	// Empty means t.<by> = $1::uuid.
	where string
}

var exportSections = []exportSection{
	{table: "users", by: "id"},

	// Sign-in methods.
	{table: "password_credentials", by: "user_id"},
	{table: "password_history", by: "user_id"},
	{table: "webauthn_credentials", by: "user_id"},
	{table: "passkey_links", by: "user_id"},
	{table: "totp_credentials", by: "user_id"},
	{table: "totp_enrolments", by: "user_id"},
	{table: "email_otp_credentials", by: "user_id"},
	{table: "sms_otp_credentials", by: "user_id"},
	{table: "duo_enrollments", by: "user_id"},
	{table: "duo_challenges", by: "user_id"},
	{table: "recovery_codes", by: "user_id"},
	{table: "recovery_code_failures", by: "user_id"},
	{table: "recovery_requests", by: "user_id"},
	{table: "trusted_devices", by: "user_id"},
	{table: "email_verifications", by: "user_id"},
	{table: "email_changes", by: "user_id"},
	{table: "email_sign_in_codes", by: "user_id"},
	{table: "federated_identities", by: "user_id"},
	{table: "federated_logins", by: "link_user_id"},

	// Sessions, and what each one reached.
	{table: "sessions", by: "user_id"},
	{table: "session_clients", by: "sessions",
		where: "t.sid IN (SELECT sid FROM core.sessions WHERE user_id = $1::uuid)"},
	{table: "saml_session_participants", by: "sessions",
		where: "t.sid IN (SELECT sid FROM core.sessions WHERE user_id = $1::uuid)"},
	{table: "saml_name_ids", by: "user_id"},
	{table: "saml_logout_progress", by: "user_id"},
	{table: "auth_locations", by: "user_id"},
	{table: "impersonations", by: "subject_id"},
	{table: "rac_sessions", by: "user_id"},

	// What applications were given.
	{table: "consents", by: "user_id"},
	{table: "authorization_codes", by: "user_id"},
	{table: "refresh_token_families", by: "user_id"},
	{table: "refresh_tokens", by: "refresh_token_families",
		where: "t.family_id IN (SELECT id FROM core.refresh_token_families WHERE user_id = $1::uuid)"},
	{table: "device_authorizations", by: "user_id"},
	{table: "preauthorized_codes", by: "user_id"},
	{table: "uma_permission_tickets", by: "requesting_party"},
	{table: "uma_pending_requests", by: "requesting_party"},
	{table: "uma_claims_interactions", by: "requesting_party"},
	{table: "ssf_received", by: "user_id"},

	// The profile, membership and provisioning.
	{table: "user_attributes", by: "user_id"},
	{table: "prompt_responses", by: "user_id"},
	{table: "group_members", by: "user_id"},
	{table: "relations", by: "subject_id", where: "t.subject_type = 'user' AND t.subject_id = $1"},
	{table: "invitations", by: "used_by"},
	{table: "scim_links", by: "user_id"},
	{table: "scim_source_links", by: "user_id"},
	{table: "directory_links", by: "user_id"},

	// Kept about the person rather than for them: the record of what happened
	// to their account, the key their data is sealed under, notices on the way.
	{table: "audit_events", by: "subject_id"},
	{table: "subject_keys", by: "subject_id"},
	{table: "outbox", by: "payload",
		where: "t.topic = '" + AccountNoticeTopic + "' AND t.payload->>'user_id' = $1"},
}

// notAbout are the columns that name a person as the one who acted, not the one
// the row is about. Exporting by them would hand a person somebody else's data.
var notAbout = map[string]string{
	"sessions.impersonator_id":        "the session is the impersonated person's",
	"impersonations.actor_id":         "the impersonation is recorded for the person impersonated",
	"group_members.added_by":          "the membership is the member's",
	"invitations.created_by":          "the address invited is the invitee's",
	"relations.granted_by":            "the grant is its subject's",
	"authorization_models.updated_by": "an organisation's model, not a person's data",
	"uma_pending_requests.decided_by": "the request is the requesting party's",
	"audit_events.actor_id":           "an entry is about its subject; what a person did to others is theirs",
}

// publicBytes are the bytea columns that are public key material, exported.
var publicBytes = map[string]bool{
	"users.user_handle":                  true,
	"webauthn_credentials.aaguid":        true,
	"webauthn_credentials.credential_id": true,
	"webauthn_credentials.public_key":    true,
}

// withheldText are the text columns that hold a credential.
var withheldText = map[string]string{
	"password_credentials.hash":      "the password's hash",
	"password_history.hash":          "an earlier password's hash",
	"federated_logins.code_verifier": "the proof for a provider sign-in still under way",
	"federated_logins.nonce":         "binds a provider sign-in still under way",
	"sms_otp_credentials.code_ref":   "the gateway's handle for checking a code",
}

// ExportSubject gathers everything kept about subjectID. Run it in a
// REPEATABLE READ transaction, so the sections agree with each other, and
// write the record of the export in another: audit.Write reads the chain's
// head under its lock, and in a snapshot taken before the lock that head is
// stale.
func ExportSubject(ctx context.Context, tx pgx.Tx, subjectID string, root *keys.RootKey) (*SubjectExport, error) {
	id, ok := CanonicalUUID(subjectID)
	if !ok {
		return nil, ErrSubjectUnknown
	}
	// Refused rather than exported without them: an export that leaves out the
	// personal attributes is the incomplete answer this exists to replace.
	if root == nil {
		return nil, errors.New("exporting needs the root key: personal attributes are sealed under it")
	}

	byteCols := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT table_name || '.' || column_name FROM information_schema.columns
		WHERE table_schema = 'core' AND data_type = 'bytea'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return nil, err
		}
		byteCols[c] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := &SubjectExport{
		Format: ExportFormat, SubjectID: id, ExportedAt: time.Now().UTC().Truncate(time.Second),
		Tables: map[string][]map[string]any{}, Attributes: []ExportedAttribute{},
		Withheld: map[string][]string{},
	}
	for _, sec := range exportSections {
		where := sec.where
		if where == "" {
			where = "t." + sec.by + " = $1::uuid"
		}
		found, err := exportRows(ctx, tx, `SELECT to_jsonb(t)::text FROM core.`+sec.table+` t WHERE `+where, id)
		if err != nil {
			return nil, fmt.Errorf("exporting %s: %w", sec.table, err)
		}
		withheld := map[string]bool{}
		for _, row := range found {
			for col := range row {
				qualified := sec.table + "." + col
				if (byteCols[qualified] && !publicBytes[qualified]) || withheldText[qualified] != "" {
					delete(row, col)
					withheld[col] = true
				}
			}
		}
		out.Tables[sec.table] = found
		if len(withheld) > 0 {
			cols := make([]string, 0, len(withheld))
			for c := range withheld {
				cols = append(cols, c)
			}
			sort.Strings(cols)
			out.Withheld[sec.table] = cols
		}
	}

	if len(out.Tables["users"]) == 0 && len(out.Tables["subject_keys"]) == 0 {
		return nil, ErrSubjectUnknown
	}
	if len(out.Tables["users"]) == 1 {
		orgID, _ := out.Tables["users"][0]["org_id"].(string)
		values, err := UserAttributes(ctx, tx, id, orgID, root)
		if err != nil {
			return nil, fmt.Errorf("exporting attributes: %w", err)
		}
		for _, v := range values {
			out.Attributes = append(out.Attributes, ExportedAttribute{
				Name: v.Name, DisplayName: v.DisplayName, Value: v.Value, Readable: v.Readable,
			})
		}
	}
	return out, nil
}

// exportRows runs a query of to_jsonb rows. Numbers stay json.Number, so an
// identifier past 2^53 is not rounded on the way out.
func exportRows(ctx context.Context, tx pgx.Tx, query, id string) ([]map[string]any, error) {
	rows, err := tx.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := []map[string]any{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.UseNumber()
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			return nil, err
		}
		found = append(found, row)
	}
	return found, rows.Err()
}
