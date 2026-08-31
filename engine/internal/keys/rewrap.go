package keys

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Root key rotation.
//
// # Why this had to exist
//
// SIGNARI_ROOT_KEY protects every signing key and every organisation secret in
// the deployment, and until this file there was no way to change it. A root key
// that cannot be rotated is one that, once exposed — in a shell history, a CI
// log, a copied environment file — stays exposed for the life of the
// deployment. The only remedy available was to re-key the entire installation
// from scratch, which invalidates every token ever issued.
//
// The schema anticipated this: `signing_keys.key_ref` and
// `subject_keys.wrap_key_ref` name WHICH root key wrapped each blob, precisely
// so a rotation can tell them apart without trial decryption. The machinery to
// use those columns was never written.
//
// # One transaction, all or nothing
//
// Every blob is re-wrapped in a single transaction. A partial rotation is not a
// degraded state, it is an unopenable database: half the rows readable with the
// old key, half with the new, and no single key that opens the deployment. There
// is no resume, because a resume needs to know which rows were done, and the
// only honest record of that is the transaction that either committed or did
// not.
//
// This does mean the transaction is as large as the deployment's secret count.
// That is acceptable because these are configuration rows — signing keys,
// integration credentials, per-subject DEKs — numbering in the thousands, not
// the request-path tables.
//
// # The completeness problem, which is the dangerous one
//
// A root-sealed column this list does not know about is not re-wrapped, and
// after rotation its contents can never be opened again. Silently. The secret is
// still there, still ciphertext, and the key that opens it has been retired by
// an operator who was told the rotation succeeded.
//
// So `TestEveryEncryptedColumnIsClassified` enumerates every bytea column in
// schema `core` and fails unless each is accounted for here — as root-sealed, as
// sealed under a subject key (which follows automatically, because the subject
// DEK is itself re-wrapped), as a one-way hash, or as public material. Adding a
// new sealed secret without classifying it fails the build rather than the
// rotation.

// sealedColumn is one place root-sealed material lives.
type sealedColumn struct {
	table  string
	column string
	// key is the primary key column, used to address a row for the update.
	key string
	// context is the domain separator passed to Seal/Open, or "" for the two
	// columns sealed before contexts existed (signing keys and subject DEKs).
	// Re-sealing with a different context than the value was sealed under would
	// produce a blob nothing can open, so this must match the reader exactly.
	context string
	// refColumn names which root key wrapped the row, where the schema has one.
	// Updated alongside the blob so a later rotation can tell them apart.
	refColumn string
}

// rootSealedColumns is every column sealed DIRECTLY under the root key.
//
// Not here on purpose: anything sealed under a SUBJECT key. `totp_credentials.
// secret_enc` is the example — it is sealed with the subject's own DEK, and that
// DEK is `subject_keys.wrapped_dek`, which IS in this list. Re-wrapping the DEK
// carries everything sealed under it, so touching the TOTP secret as well would
// be an attempt to open it with the wrong key.
var rootSealedColumns = []sealedColumn{
	{table: "signing_keys", column: "wrapped_private", key: "kid", refColumn: "key_ref"},
	{table: "subject_keys", column: "wrapped_dek", key: "subject_id", refColumn: "wrap_key_ref"},

	{table: "directory_sources", column: "credentials_enc", key: "id", context: "directory-credentials"},
	{table: "duo_integrations", column: "secret_enc", key: "org_id", context: "duo_secret"},
	{table: "event_subscriptions", column: "secret_sealed", key: "id", context: "event-subscription"},
	{table: "identity_providers", column: "client_secret", key: "id", context: "idp_client_secret"},
	{table: "rac_connections", column: "secrets_enc", key: "id", context: "rac-connection-secret"},
	{table: "radius_clients", column: "secret_enc", key: "id", context: "radius-client-secret"},
	{table: "scim_targets", column: "token", key: "id", context: "scim_token"},
	{table: "scim_targets", column: "credentials_enc", key: "id", context: "provision_credentials"},
	{table: "ssf_streams", column: "auth_token", key: "id", context: "ssf-stream-token"},
}

// RewrapReport says what a rotation did, per column.
type RewrapReport struct {
	Table   string
	Column  string
	Rows    int
	Skipped int
}

// RewrapRoot re-seals every root-wrapped blob from `old` to `next`.
//
// Runs inside the caller's transaction so the caller decides whether to commit;
// `signari keys rewrap-root` uses that to offer a dry run that does the entire
// job and rolls back, which is the only way to find out whether a rotation would
// succeed without betting the deployment on it.
func RewrapRoot(ctx context.Context, tx pgx.Tx, old, next *RootKey) ([]RewrapReport, error) {
	if old == nil || next == nil {
		return nil, fmt.Errorf("both the current and the new root key are required")
	}
	if old.Ref() == next.Ref() {
		// Refusing rather than proceeding. Identical refs after a rotation make
		// the two keys indistinguishable in the rows, so a later rotation cannot
		// tell which blobs it has already done -- and a failed rotation cannot
		// be diagnosed at all.
		return nil, fmt.Errorf("the new root key has the same ref %q as the current one; "+
			"set SIGNARI_NEW_ROOT_KEY_REF to something distinct so stored rows "+
			"record which key wrapped them", old.Ref())
	}

	var reports []RewrapReport
	for _, c := range rootSealedColumns {
		rep, err := rewrapColumn(ctx, tx, c, old, next)
		if err != nil {
			return nil, err
		}
		reports = append(reports, rep)
	}
	return reports, nil
}

func rewrapColumn(ctx context.Context, tx pgx.Tx, c sealedColumn, old, next *RootKey) (RewrapReport, error) {
	rep := RewrapReport{Table: c.table, Column: c.column}

	// Read every non-null blob. FOR UPDATE so a concurrent write cannot seal a
	// new value with the old key between this read and the update -- which would
	// leave exactly one unopenable row, the hardest possible thing to notice.
	rows, err := tx.Query(ctx, fmt.Sprintf(
		`SELECT %s::text, %s FROM core.%s WHERE %s IS NOT NULL FOR UPDATE`,
		c.key, c.column, c.table, c.column))
	if err != nil {
		return rep, fmt.Errorf("reading core.%s.%s: %w", c.table, c.column, err)
	}

	type row struct {
		id     string
		sealed []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.sealed); err != nil {
			rows.Close()
			return rep, fmt.Errorf("scanning core.%s: %w", c.table, err)
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, fmt.Errorf("reading core.%s.%s: %w", c.table, c.column, err)
	}

	for _, r := range batch {
		plain, err := openWith(old, r.sealed, c.context)
		if err != nil {
			// Already rotated? A blob the NEW key opens is one a previous
			// interrupted attempt got to. Reported as skipped rather than
			// treated as success, because if this happens the operator needs to
			// know the database was in a mixed state -- which should be
			// impossible given the single transaction, and therefore matters.
			if _, nerr := openWith(next, r.sealed, c.context); nerr == nil {
				rep.Skipped++
				continue
			}
			return rep, fmt.Errorf(
				"core.%s.%s row %s cannot be opened with the current root key: %w\n"+
					"Nothing has been written; the transaction will roll back. Either "+
					"SIGNARI_ROOT_KEY is not the key this deployment is using, or this "+
					"row was sealed under a key that is already gone",
				c.table, c.column, r.id, err)
		}

		resealed, err := sealWith(next, plain, c.context)
		if err != nil {
			return rep, fmt.Errorf("re-sealing core.%s row %s: %w", c.table, r.id, err)
		}

		set := fmt.Sprintf("%s = $1", c.column)
		args := []any{resealed, r.id}
		if c.refColumn != "" {
			set += fmt.Sprintf(", %s = $3", c.refColumn)
			args = append(args, next.Ref())
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`UPDATE core.%s SET %s WHERE %s::text = $2`, c.table, set, c.key), args...); err != nil {
			return rep, fmt.Errorf("writing core.%s row %s: %w", c.table, r.id, err)
		}
		rep.Rows++
	}
	return rep, nil
}

// openWith unseals with or without a context, matching how it was sealed.
func openWith(r *RootKey, sealed []byte, ctxName string) ([]byte, error) {
	if ctxName == "" {
		return r.open(sealed)
	}
	return r.Open(sealed, ctxName)
}

func sealWith(r *RootKey, plain []byte, ctxName string) ([]byte, error) {
	if ctxName == "" {
		return r.seal(plain)
	}
	return r.Seal(plain, ctxName)
}

// RootSealedColumns reports what a rotation covers, for the completeness test
// and for the command's output.
func RootSealedColumns() []string {
	out := make([]string, 0, len(rootSealedColumns))
	for _, c := range rootSealedColumns {
		out = append(out, c.table+"."+c.column)
	}
	return out
}
