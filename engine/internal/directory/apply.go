package directory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Applying a plan to the local directory.

// LoadLocal reads the users this source has previously linked, plus the
// organisation's active count for the ceiling.
func LoadLocal(ctx context.Context, db *pgxpool.Pool, sourceID, orgID string) ([]LocalUser, error) {
	rows, err := db.Query(ctx, `
		SELECT u.id::text, COALESCE(l.remote_id,''), COALESCE(u.email,''),
		       COALESCE(l.remote_name,''), u.status = 'active'
		FROM core.users u
		LEFT JOIN core.directory_links l ON l.user_id = u.id AND l.source_id = $1::uuid
		WHERE u.org_id = $2::uuid`, sourceID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LocalUser
	for rows.Next() {
		var l LocalUser
		if err := rows.Scan(&l.UserID, &l.RemoteID, &l.Email, &l.Name, &l.Active); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Apply writes a plan.
//
// Refuses outright if the plan is not safe. The check is repeated here rather
// than trusted from the caller: this is the function that does the damage, and a
// safety rule enforced only at the call site is one a future caller forgets.
func Apply(ctx context.Context, db *pgxpool.Pool, sourceID, orgID string, p *Plan) error {
	if !p.Safe() {
		return fmt.Errorf("refusing to apply: %s", p.Refused)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, a := range p.Actions {
		switch a.Kind {
		case "create":
			var userID string
			if err := tx.QueryRow(ctx, `
				INSERT INTO core.users (org_id, email, user_handle, status)
				VALUES ($1::uuid, $2,
				        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
				               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
				        'active')
				ON CONFLICT (org_id, lower(email)) WHERE email IS NOT NULL
				DO UPDATE SET status = 'active', updated_at = now()
				RETURNING id::text`, orgID, a.Email).Scan(&userID); err != nil {
				return fmt.Errorf("creating %s: %w", a.Email, err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.directory_links (source_id, user_id, org_id, remote_id,
				                                  remote_email, remote_name)
				VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
				ON CONFLICT (source_id, remote_id) DO UPDATE SET
					user_id = EXCLUDED.user_id, remote_email = EXCLUDED.remote_email,
					remote_name = EXCLUDED.remote_name, last_seen_at = now()`,
				sourceID, userID, orgID, a.RemoteID, a.Email, a.Name); err != nil {
				return fmt.Errorf("linking %s: %w", a.Email, err)
			}

		case "update":
			if _, err := tx.Exec(ctx, `
				UPDATE core.users SET email = $2, updated_at = now() WHERE id = $1::uuid`,
				a.UserID, a.Email); err != nil {
				return fmt.Errorf("updating %s: %w", a.Email, err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE core.directory_links
				SET remote_email = $3, remote_name = $4, last_seen_at = now()
				WHERE source_id = $1::uuid AND remote_id = $2`,
				sourceID, a.RemoteID, a.Email, a.Name); err != nil {
				return err
			}

		case "deactivate":
			// Sessions go with the account. Deactivating a user who stays signed
			// in everywhere is not a deactivation, it is a note.
			if _, err := tx.Exec(ctx, `
				UPDATE core.users SET status = 'deactivated', updated_at = now()
				WHERE id = $1::uuid`, a.UserID); err != nil {
				return fmt.Errorf("deactivating %s: %w", a.Email, err)
			}
			// 'user_deactivated', not 'admin'. core.sessions constrains this
			// column to a fixed vocabulary, and 'admin' is not in it -- so this
			// statement failed, the transaction rolled back, and the
			// deactivation it was part of never happened. A departed employee
			// stayed active AND stayed signed in, which is the precise outcome
			// this code exists to prevent.
			//
			// It passed its tests because none of them gave the user a session,
			// so this statement matched zero rows and never checked the value.
			if _, err := tx.Exec(ctx, `
				UPDATE core.sessions SET revoked_at = now(),
				       revocation_reason = 'user_deactivated'
				WHERE user_id = $1::uuid AND revoked_at IS NULL`, a.UserID); err != nil {
				return fmt.Errorf("revoking sessions for %s: %w", a.Email, err)
			}

		case "reactivate":
			if _, err := tx.Exec(ctx, `
				UPDATE core.users SET status = 'active', updated_at = now()
				WHERE id = $1::uuid`, a.UserID); err != nil {
				return fmt.Errorf("reactivating %s: %w", a.Email, err)
			}

		case "report-missing":
			// Reported only, by design. See the migration.
		}
	}

	create, update, deactivate, _ := p.Counts()
	if _, err := tx.Exec(ctx, `
		UPDATE core.directory_sources
		SET last_sync_at = now(), last_error = NULL, last_created = $2,
		    last_updated = $3, last_deactivated = $4, updated_at = now()
		WHERE id = $1::uuid`, sourceID, create, update, deactivate); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RecordFailure notes why a sync did not complete.
func RecordFailure(ctx context.Context, db *pgxpool.Pool, sourceID string, cause error) {
	_, _ = db.Exec(ctx, `
		UPDATE core.directory_sources SET last_error = $2, updated_at = now()
		WHERE id = $1::uuid`, sourceID, cause.Error())
}
