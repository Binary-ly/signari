package keys

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Every encrypted column must be classified, or rotation destroys it.
//
// # The failure this prevents
//
// A root-sealed column that `rootSealedColumns` does not know about is not
// re-wrapped. After the rotation its contents can never be opened again — the
// ciphertext is intact, and the only key that opens it has been retired by an
// operator who was told the rotation succeeded. There is no error, no log line,
// and nothing to notice until somebody needs that secret, which for an
// integration credential may be months later.
//
// That is why this is a build-failing test with an explicit classification for
// every bytea column in the schema, rather than a list somebody remembers to
// update. Adding a sealed secret without deciding what happens to it during a
// rotation should stop the build, and now does.
//
// # The four classifications
//
//   - rootSealed:    re-wrapped by RewrapRoot. Listed in rewrap.go.
//   - subjectSealed: sealed under a subject's DEK. NOT re-wrapped directly, and
//     must not be: the DEK itself is root-sealed and is in the
//     list, so re-wrapping it carries everything under it.
//   - oneWay:        a hash. Nothing can open it, so a root key change is
//     irrelevant to it.
//   - public:        public keys, certificates, identifiers. Not secret.
//   - unused:        the column exists and no code reads or writes it.

var columnClass = map[string]string{
	// Root-sealed. Must match rootSealedColumns exactly; asserted below.
	"signing_keys.wrapped_private":      "rootSealed",
	"subject_keys.wrapped_dek":          "rootSealed",
	"directory_sources.credentials_enc": "rootSealed",
	"duo_integrations.secret_enc":       "rootSealed",
	"event_subscriptions.secret_sealed": "rootSealed",
	"identity_providers.client_secret":  "rootSealed",
	"rac_connections.secrets_enc":       "rootSealed",
	"radius_clients.secret_enc":         "rootSealed",
	"scim_targets.token":                "rootSealed",
	"scim_targets.credentials_enc":      "rootSealed",
	"ssf_streams.auth_token":            "rootSealed",

	// Sealed under the subject's own DEK. Re-wrapping the DEK covers these, and
	// touching them here would try to open them with the wrong key.
	"totp_credentials.secret_enc": "subjectSealed",

	// One-way. A root key change cannot affect something nothing can open.
	"access_tokens.token_hash":                      "oneWay",
	"admin_tokens.token_hash":                       "oneWay",
	"attestation_challenges.challenge_hash":         "oneWay",
	"audit_events.entry_hash":                       "oneWay",
	"audit_events.prev_hash":                        "oneWay",
	"authorization_codes.code_hash":                 "oneWay",
	"clients.registration_token_hash":               "oneWay",
	"credential_nonces.nonce_hash":                  "oneWay",
	"device_authorizations.device_code_hash":        "oneWay",
	"device_authorizations.user_code_hash":          "oneWay",
	"email_otp_credentials.code_hash":               "oneWay",
	"federated_logins.binding_hash":                 "oneWay",
	"federated_logins.state_hash":                   "oneWay",
	"federation_trust_marks_issued.trust_mark_hash": "oneWay",
	"invitations.token_hash":                        "oneWay",
	"outposts.token_hash":                           "oneWay",
	"preauthorized_codes.code_hash":                 "oneWay",
	"preauthorized_codes.tx_code_hash":              "oneWay",
	"pushed_requests.uri_hash":                      "oneWay",
	"recovery_codes.code_hash":                      "oneWay",
	"recovery_requests.cancel_hash":                 "oneWay",
	"recovery_requests.token_hash":                  "oneWay",
	"refresh_tokens.successor_hash":                 "oneWay",
	"refresh_tokens.token_hash":                     "oneWay",
	"registration_tokens.token_hash":                "oneWay",
	"saml_logout_progress.token_hash":               "oneWay",
	"scim_sources.token_hash":                       "oneWay",
	"sessions.cookie_hash":                          "oneWay",
	"sessions.ip_hash":                              "oneWay",
	"sms_otp_credentials.code_hash":                 "oneWay",
	"uma_claims_interactions.handle_hash":           "oneWay",
	"uma_claims_interactions.ticket_hash":           "oneWay",
	"uma_permission_tickets.ticket_hash":            "oneWay",

	// Public or non-secret material.
	"clients.tls_thumbprint":             "public",
	"signing_keys.certificate":           "public",
	"users.user_handle":                  "public",
	"webauthn_credentials.aaguid":        "public",
	"webauthn_credentials.credential_id": "public",
	"webauthn_credentials.public_key":    "public",

	// Columns nothing reads or writes. Recorded rather than left unclassified so
	// that this test does not have to be edited if one of them is ever wired up
	// -- it will fail then, which is the moment somebody must decide how a
	// rotation treats it.
	"audit_events.detail_enc":             "unused",
	"migration_sources.client_secret_enc": "unused",
	"providers.token_wrapped":             "unused",
}

func TestEveryEncryptedColumnIsClassified(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `
		SELECT c.table_name, c.column_name
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'core' AND t.table_type = 'BASE TABLE'
		  AND c.data_type = 'bytea'
		ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var found []string
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		found = append(found, table+"."+column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no bytea columns found in schema core; this test is passing " +
			"vacuously, which is worse than not existing")
	}

	for _, col := range found {
		if columnClass[col] == "" {
			t.Errorf("core.%s holds bytes and is not classified.\n\n"+
				"Decide what a ROOT KEY ROTATION does to it:\n"+
				"  rootSealed    -- add it to rootSealedColumns in rewrap.go AND here\n"+
				"  subjectSealed -- sealed under a subject DEK; the DEK is re-wrapped, so this follows\n"+
				"  oneWay        -- a hash; nothing can open it\n"+
				"  public        -- not secret\n\n"+
				"Getting this wrong is not a bug that surfaces: an unclassified "+
				"root-sealed column survives the rotation as ciphertext nobody "+
				"can ever open again, and the operator is told the rotation "+
				"succeeded.", col)
		}
	}

	// The other direction. A classification for a column that no longer exists
	// is a note describing a decision about nothing, and it hides the fact that
	// the real column was renamed -- which would show up as unclassified above
	// only if somebody read past the first failure.
	present := map[string]bool{}
	for _, c := range found {
		present[c] = true
	}
	for col := range columnClass {
		if !present[col] {
			t.Errorf("columnClass names core.%s, which is not a bytea column in "+
				"the schema. If it was renamed, the new name is unclassified.", col)
		}
	}
}

// Every column the rotation names must exist, with the key it addresses rows by.
//
// This was found by running the rotation, not by reading it: `ssf_streams` was
// listed with a key column of `stream_id`, and its primary key is `id`. The
// failure was clean — the transaction rolled back and nothing was written — but
// it surfaced only because a live dry run was attempted, and the fix for
// "surfaced only by running it" is a test that runs it.
//
// It matters more than a typo normally would. A rotation that dies partway is
// safe here because it is one transaction; a rotation that cannot START is an
// operator who has generated a new key, scheduled a maintenance window, and has
// nothing to do in it.
func TestEverySealedColumnAndItsKeyExist(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for _, c := range rootSealedColumns {
		for _, col := range []string{c.column, c.key} {
			var n int
			if err := pool.QueryRow(ctx, `
				SELECT count(*) FROM information_schema.columns
				WHERE table_schema='core' AND table_name=$1 AND column_name=$2`,
				c.table, col).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("the rotation addresses core.%s.%s, which does not exist. "+
					"The rotation would fail before writing anything — safe, but "+
					"only discovered during the maintenance window it was "+
					"scheduled for.", c.table, col)
			}
		}
		if c.refColumn == "" {
			continue
		}
		var n int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_schema='core' AND table_name=$1 AND column_name=$2`,
			c.table, c.refColumn).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("core.%s has no %s column to record which root key wrapped it",
				c.table, c.refColumn)
		}
	}
}

// The classification table and the rotation list must agree.
//
// Two lists in two files describing one fact is exactly the drift this
// repository keeps writing tests against. If rewrap.go gains a column and this
// test's table does not, the rotation would quietly cover something the
// classification says nothing about — and worse in the other direction, a column
// marked rootSealed here but missing from rewrap.go reads as covered and is not.
func TestTheRotationListMatchesTheClassification(t *testing.T) {
	var classified []string
	for col, class := range columnClass {
		if class == "rootSealed" {
			classified = append(classified, col)
		}
	}
	actual := RootSealedColumns()

	sort.Strings(classified)
	sort.Strings(actual)

	if strings.Join(classified, ",") != strings.Join(actual, ",") {
		t.Fatalf("the rotation covers:\n  %s\nthe classification says rootSealed:\n  %s\n"+
			"A column in one and not the other is either rotated without being "+
			"classified, or believed covered and silently left behind.",
			strings.Join(actual, "\n  "), strings.Join(classified, "\n  "))
	}
}

// A rotation must refuse to run when the new key cannot be told apart.
func TestARotationWithTheSameRefIsRefused(t *testing.T) {
	a, err := NewRootKey("same", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	b[0] = 1
	second, err := NewRootKey("same", b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RewrapRoot(context.Background(), nil, a, second); err == nil {
		t.Fatal("a rotation to a key with the same ref was accepted. Stored rows " +
			"would not record which key wrapped them, so a later rotation could " +
			"not tell which rows it had already done.")
	}
}

// Sealing and opening round-trips through the two key generations.
//
// The property a rotation depends on and the one worth stating: a blob re-sealed
// under the new key opens with the new key and NOT with the old. If the old key
// still opened it, retiring the old key would not actually retire anything,
// which is the entire point of rotating.
func TestReSealedMaterialOpensOnlyWithTheNewKey(t *testing.T) {
	oldSecret, newSecret := make([]byte, 32), make([]byte, 32)
	oldSecret[0], newSecret[0] = 1, 2
	old, err := NewRootKey("v1", oldSecret)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewRootKey("v2", newSecret)
	if err != nil {
		t.Fatal(err)
	}

	for _, ctxName := range []string{"", "duo_secret"} {
		sealed, err := sealWith(old, []byte("the secret"), ctxName)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := openWith(old, sealed, ctxName)
		if err != nil {
			t.Fatalf("context %q: the old key could not open its own blob: %v", ctxName, err)
		}
		resealed, err := sealWith(next, plain, ctxName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openWith(next, resealed, ctxName); err != nil {
			t.Errorf("context %q: the new key cannot open what it just sealed: %v", ctxName, err)
		}
		if _, err := openWith(old, resealed, ctxName); err == nil {
			t.Errorf("context %q: the OLD key still opens the re-sealed blob. "+
				"Retiring it would retire nothing.", ctxName)
		}
	}
}
