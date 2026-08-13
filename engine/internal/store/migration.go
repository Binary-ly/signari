package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
)

// migrationSecretContext binds an encrypted client secret to its purpose, so a
// blob moved between columns fails to decrypt rather than silently becoming a
// different secret.
const migrationSecretContext = "migration_source_secret"

// PendingMigration is a user who exists here but whose password still lives at
// the old provider.
type PendingMigration struct {
	UserID string
	OrgID  string
	Source delegated.Source
}

// LookupMigrationCandidate finds a user with no usable local credential whose
// organisation has delegated authentication configured.
//
// The distinction from lookupCredential is the whole point: "no such user" and
// "a user we imported but have no password for" look identical at the login
// form and must be handled completely differently.
//
// Returns ok=false for everything else -- an unknown identifier, a user with a
// local hash, a disabled source. No fallback, no guessing: delegation is
// attempted only where it was explicitly configured.
func LookupMigrationCandidate(ctx context.Context, db *pgxpool.Pool, identifier string,
	root *keys.RootKey) (*PendingMigration, bool, error) {

	var p PendingMigration
	var secretEnc []byte

	err := db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text,
		       ms.id::text, ms.kind, ms.display_name, ms.token_endpoint,
		       ms.client_id, ms.client_secret_enc, ms.scope
		FROM core.users u
		JOIN core.migration_sources ms ON ms.org_id = u.org_id
		LEFT JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status = 'active'
		  AND u.migration_state = 'pending'
		  AND ms.enabled
		  -- No local credential to check. A user who HAS one is authenticated
		  -- locally; delegating for them would send their password to a third
		  -- party we no longer need to ask.
		  AND pc.user_id IS NULL
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))`,
		identifier).Scan(&p.UserID, &p.OrgID, &p.Source.ID, &p.Source.Kind,
		&p.Source.DisplayName, &p.Source.TokenEndpoint, &p.Source.ClientID,
		&secretEnc, &p.Source.Scope)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("looking up migration candidate: %w", err)
	}

	if len(secretEnc) > 0 {
		// Unwrapped with the ROOT key, not a subject key: this secret belongs to
		// the organisation's migration configuration, not to any person, and it
		// must survive a user being crypto-shredded.
		secret, err := root.Open(secretEnc, migrationSecretContext)
		if err != nil {
			return nil, false, fmt.Errorf("unwrapping the migration source secret "+
				"(is the root key correct?): %w", err)
		}
		p.Source.ClientSecret = string(secret)
	}
	return &p, true, nil
}

// CompleteMigration records a successful delegated sign-in.
//
// Writes the local hash, flips the user to 'complete', and stamps migrated_at --
// all in the caller's transaction, alongside the session being created. If any
// of it rolled back while the session committed, the user would be signed in and
// still have no local credential, and would be delegated again next time. The
// old provider would then have to stay alive forever, which is the one thing
// this feature exists to avoid.
func CompleteMigration(ctx context.Context, tx pgx.Tx, userID, orgID, sourceID, hash string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, source_system, is_current)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id', 'migrated', true)
		ON CONFLICT (user_id) DO UPDATE SET
			hash = EXCLUDED.hash, algorithm = 'argon2id', is_current = true, updated_at = now()`,
		userID, orgID, hash); err != nil {
		return fmt.Errorf("storing the migrated credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.users
		SET migration_state = 'complete', migrated_at = now(), migration_source_id = $2::uuid
		WHERE id = $1::uuid`, userID, sourceID); err != nil {
		return fmt.Errorf("marking the user migrated: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.migration_sources
		SET delegated_successes = delegated_successes + 1, last_used_at = now(), last_error = NULL
		WHERE id = $1::uuid`, sourceID); err != nil {
		return fmt.Errorf("counting the delegated success: %w", err)
	}
	return nil
}

// RecordDelegationFailure counts a failure against the SOURCE, not the user.
//
// Separate from the per-account login throttle on purpose: a source that is
// down, misconfigured or rate-limiting us produces failures that say nothing
// about any user, and charging them to the user would lock out an entire
// organisation during someone else's outage.
func RecordDelegationFailure(ctx context.Context, db *pgxpool.Pool, sourceID, reason string) {
	_, _ = db.Exec(ctx, `
		UPDATE core.migration_sources
		SET delegated_failures = delegated_failures + 1, last_used_at = now(), last_error = $2
		WHERE id = $1::uuid`, sourceID, reason)
}
