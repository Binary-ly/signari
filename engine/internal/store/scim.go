package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/scim"
)

// LoadSCIMTargets returns the provisioning targets, secrets unsealed.
func LoadSCIMTargets(ctx context.Context, conn *pgx.Conn, root *keys.RootKey, only string) ([]scim.Target, error) {
	rows, err := conn.Query(ctx, `
		SELECT id::text, org_id::text, slug, display_name, base_url, token,
		       dry_run, on_deactivate
		FROM core.scim_targets
		WHERE enabled AND ($1 = '' OR slug = $1)
		ORDER BY slug`, only)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []scim.Target
	for rows.Next() {
		var t scim.Target
		var sealed []byte
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Slug, &t.DisplayName, &t.BaseURL,
			&sealed, &t.DryRun, &t.OnDeactivate); err != nil {
			return nil, err
		}
		plain, err := root.Open(sealed, "scim_token")
		if err != nil {
			return nil, fmt.Errorf("unsealing the token for target %q: %w", t.Slug, err)
		}
		t.Token = string(plain)
		out = append(out, t)
	}
	return out, rows.Err()
}

// SCIMDesiredUser is what a target SHOULD hold for one of our users.
type SCIMDesiredUser struct {
	UserID      string
	UserName    string
	DisplayName string
	Email       string
	Active      bool
	// RemoteID is empty when this user has never been provisioned to the target.
	RemoteID string
	Synced   bool
}

// SCIMDesiredState lists what a target should hold, from our side.
//
// # Why every user, not a queue of changes
//
// The obvious design is an event queue: user deactivated, enqueue a
// deprovision. It is also how deprovisioning silently fails -- an event dropped
// during a restart, exhausted after its last retry, or enqueued while the
// target was misconfigured leaves a live account for somebody who has left, and
// nothing will ever try again because the event is gone.
//
// Reconciling from desired state has no such hole. Whatever went wrong last
// time, the next pass sees the same disagreement and fixes it.
func SCIMDesiredState(ctx context.Context, conn *pgx.Conn, target scim.Target) ([]SCIMDesiredUser, error) {
	rows, err := conn.Query(ctx, `
		SELECT u.id::text,
		       COALESCE(NULLIF(u.username,''), u.email, u.id::text),
		       COALESCE(u.email,''),
		       u.status = 'active',
		       COALESCE(l.remote_id,''),
		       l.last_synced_at IS NOT NULL
		FROM core.users u
		LEFT JOIN core.scim_links l
		       ON l.user_id = u.id AND l.target_id = $1::uuid
		WHERE u.org_id = $2::uuid
		  -- Users never provisioned AND already inactive are skipped: there is
		  -- nothing at the target to correct, and listing them would bury the
		  -- rows that need action.
		  AND (l.remote_id IS NOT NULL OR u.status = 'active')
		ORDER BY u.created_at`, target.ID, target.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SCIMDesiredUser
	for rows.Next() {
		var d SCIMDesiredUser
		if err := rows.Scan(&d.UserID, &d.UserName, &d.Email, &d.Active,
			&d.RemoteID, &d.Synced); err != nil {
			return nil, err
		}
		d.DisplayName = d.UserName
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordSCIMLink stores the id a target assigned to one of our users.
func RecordSCIMLink(ctx context.Context, conn *pgx.Conn, targetID, userID, orgID, remoteID string, active bool) error {
	_, err := conn.Exec(ctx, `
		INSERT INTO core.scim_links
			(target_id, user_id, org_id, remote_id, should_be_active, last_synced_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, now())
		ON CONFLICT (target_id, user_id) DO UPDATE
			SET remote_id = EXCLUDED.remote_id,
			    should_be_active = EXCLUDED.should_be_active,
			    last_synced_at = now()`,
		targetID, userID, orgID, remoteID, active)
	return err
}

// MarkSCIMIntent records what we want the remote account to be, WITHOUT
// claiming it has happened.
//
// last_synced_at is deliberately not touched. The intent and the confirmation
// are separate facts, and collapsing them is what makes a failed deprovision
// look like a completed one.
func MarkSCIMIntent(ctx context.Context, conn *pgx.Conn, targetID, userID string, active bool) error {
	_, err := conn.Exec(ctx, `
		UPDATE core.scim_links SET should_be_active = $3
		WHERE target_id = $1::uuid AND user_id = $2::uuid`, targetID, userID, active)
	return err
}

// ConfirmSCIMSync records that the target now agrees.
func ConfirmSCIMSync(ctx context.Context, conn *pgx.Conn, targetID, userID string) error {
	_, err := conn.Exec(ctx, `
		UPDATE core.scim_links SET last_synced_at = now()
		WHERE target_id = $1::uuid AND user_id = $2::uuid`, targetID, userID)
	return err
}

// DropSCIMLink forgets a remote account, used after a delete.
func DropSCIMLink(ctx context.Context, conn *pgx.Conn, targetID, userID string) error {
	_, err := conn.Exec(ctx, `
		DELETE FROM core.scim_links WHERE target_id = $1::uuid AND user_id = $2::uuid`,
		targetID, userID)
	return err
}

// AddSCIMTarget registers a provisioning target.
func AddSCIMTarget(ctx context.Context, conn *pgx.Conn, root *keys.RootKey,
	orgID, slug, name, baseURL, token, onDeactivate string, dryRun bool) error {

	sealed, err := root.Seal([]byte(token), "scim_token")
	if err != nil {
		return fmt.Errorf("sealing the target token: %w", err)
	}
	_, err = conn.Exec(ctx, `
		INSERT INTO core.scim_targets
			(org_id, slug, display_name, base_url, token, on_deactivate, dry_run)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)`,
		orgID, slug, name, baseURL, sealed, onDeactivate, dryRun)
	if err != nil && errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return err
}
