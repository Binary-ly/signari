package directory

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
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

	// A kind at a time, in the order the plan sorts them, and each in a few
	// statements however many people it names (7.16): a first sync of a large
	// directory was three round trips a person. "report-missing" is reported
	// only, by design. See the migration.
	kinds := map[string][]Action{}
	for _, a := range p.Actions {
		kinds[a.Kind] = append(kinds[a.Kind], a)
	}
	skippedCreates, err := applyCreates(ctx, tx, orgID, sourceID, kinds["create"])
	if err != nil {
		return err
	}
	if err := applyDeactivations(ctx, tx, kinds["deactivate"]); err != nil {
		return err
	}
	if err := applyReactivations(ctx, tx, kinds["reactivate"]); err != nil {
		return err
	}
	skippedUpdates, err := applyUpdates(ctx, tx, orgID, sourceID, kinds["update"])
	if err != nil {
		return err
	}

	create, update, deactivate, _ := p.Counts()
	create -= skippedCreates
	update -= skippedUpdates
	if _, err := tx.Exec(ctx, `
		UPDATE core.directory_sources
		SET last_sync_at = now(), last_error = NULL, last_created = $2,
		    last_updated = $3, last_deactivated = $4, updated_at = now()
		WHERE id = $1::uuid`, sourceID, create, update, deactivate); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// lastOfEachRemote keeps one action per remote id, the later one, in the order
// they first came. A paged fetch can return somebody twice, which a statement a
// person took in its stride, and one statement may not touch a row twice.
func lastOfEachRemote(actions []Action) []Action {
	at := make(map[string]int, len(actions))
	out := make([]Action, 0, len(actions))
	for _, a := range actions {
		if i, ok := at[a.RemoteID]; ok {
			out[i] = a
			continue
		}
		at[a.RemoteID] = len(out)
		out = append(out, a)
	}
	return out
}

// exceptPrivileged returns the actions that may go ahead, recording the rest.
// An action on a person who may act as other users (store.PrivilegedUser) would
// adopt or re-address them, so it is skipped, and the audit trail says so.
// Skipped rather than failing the run: one administrator who shares an address
// with a directory entry must not stop everybody else's provisioning.
// Deactivation is never skipped -- a departed administrator must stop getting
// in. userOf names the person an action would touch, "" for nobody yet.
func exceptPrivileged(ctx context.Context, tx pgx.Tx, orgID, sourceID string, actions []Action,
	userOf func(Action) string) (kept []Action, skipped int, err error) {

	ids := make([]string, 0, len(actions))
	for _, a := range actions {
		if id := userOf(a); id != "" {
			ids = append(ids, id)
		}
	}
	privileged := map[string]bool{}
	if len(ids) > 0 {
		if privileged, err = store.PrivilegedUsers(ctx, tx, ids); err != nil {
			return nil, 0, err
		}
	}
	kept = make([]Action, 0, len(actions))
	for _, a := range actions {
		id := userOf(a)
		if !privileged[id] {
			kept = append(kept, a)
			continue
		}
		skipped++
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "directory.privileged_skipped", OrgID: orgID, SubjectID: id,
			Detail: map[string]any{"source_id": sourceID, "action": a.Kind, "remote_id": a.RemoteID},
		}); err != nil {
			return nil, 0, err
		}
	}
	return kept, skipped, nil
}

// accountsAt names the account at each address, as the unique index compares
// them, which PostgreSQL's lower() decides and Go's ToLower does not always
// match.
func accountsAt(ctx context.Context, tx pgx.Tx, orgID string, addresses []string) (map[string]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT a.address, u.id::text
		  FROM unnest($2::text[]) AS a(address)
		  JOIN core.users u ON u.org_id = $1::uuid AND lower(u.email) = lower(a.address)`, orgID, addresses)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string, len(addresses))
	for rows.Next() {
		var address, id string
		if err := rows.Scan(&address, &id); err != nil {
			return nil, err
		}
		out[address] = id
	}
	return out, rows.Err()
}

// applyCreates brings in the people the directory has and this deployment has
// not linked, and answers how many it skipped.
func applyCreates(ctx context.Context, tx pgx.Tx, orgID, sourceID string, actions []Action) (int, error) {
	if len(actions) == 0 {
		return 0, nil
	}
	actions = lastOfEachRemote(actions)
	addresses := make([]string, len(actions))
	for i, a := range actions {
		addresses[i] = a.Email
	}
	// Two entries with one address are two people claiming one account, and a
	// source links a person once. Said here, by address, rather than as what
	// one statement touching a row twice would say.
	var shared string
	err := tx.QueryRow(ctx, `
		SELECT min(a) FROM unnest($1::text[]) AS a GROUP BY lower(a) HAVING count(*) > 1 LIMIT 1`,
		addresses).Scan(&shared)
	if err == nil {
		return 0, fmt.Errorf("two directory entries have the address %s, and a person is linked once", shared)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("comparing addresses: %w", err)
	}

	// An existing account with this address is adopted, as a person who signed
	// up before the sync began -- unless they may act as other users. A
	// directory describes the people it manages, not the administrators of
	// this deployment, and an adopted administrator's address would then be the
	// directory's to change.
	existing, err := accountsAt(ctx, tx, orgID, addresses)
	if err != nil {
		return 0, fmt.Errorf("looking up accounts: %w", err)
	}
	actions, skipped, err := exceptPrivileged(ctx, tx, orgID, sourceID, actions,
		func(a Action) string { return existing[a.Email] })
	if err != nil {
		return 0, err
	}
	if len(actions) == 0 {
		return skipped, nil
	}
	addresses, remoteIDs, names := make([]string, len(actions)), make([]string, len(actions)), make([]string, len(actions))
	for i, a := range actions {
		addresses[i], remoteIDs[i], names[i] = a.Email, a.RemoteID, a.Name
	}

	// A person the directory brings in has no password here. When the
	// organisation is migrating off a provider (2.01), they are created pending
	// on that source, so their first sign-in is verified there and leaves a
	// local hash; otherwise they could not sign in with a password at all. An
	// adopted account keeps the state it had.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.users (org_id, email, user_handle, status,
		                        migration_state, migration_source_id)
		SELECT $1::uuid, a.address,
		       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
		       'active',
		       CASE WHEN ms.id IS NULL THEN 'none' ELSE 'pending' END, ms.id
		  FROM unnest($2::text[]) AS a(address)
		  LEFT JOIN core.migration_sources ms ON ms.org_id = $1::uuid AND ms.enabled
		ON CONFLICT (org_id, lower(email)) WHERE email IS NOT NULL
		DO UPDATE SET status = 'active', updated_at = now()`, orgID, addresses); err != nil {
		return 0, fmt.Errorf("creating %d people: %w", len(addresses), err)
	}
	accounts, err := accountsAt(ctx, tx, orgID, addresses)
	if err != nil {
		return 0, fmt.Errorf("reading back the accounts: %w", err)
	}
	userIDs := make([]string, len(actions))
	for i, a := range actions {
		id, ok := accounts[a.Email]
		if !ok {
			return 0, fmt.Errorf("creating %s: no account afterwards", a.Email)
		}
		userIDs[i] = id
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.directory_links (source_id, user_id, org_id, remote_id,
		                                  remote_email, remote_name)
		SELECT $1::uuid, t.user_id, $2::uuid, t.remote_id, t.email, t.name
		  FROM unnest($3::uuid[], $4::text[], $5::text[], $6::text[]) AS t(user_id, remote_id, email, name)
		ON CONFLICT (source_id, remote_id) DO UPDATE SET
			user_id = EXCLUDED.user_id, remote_email = EXCLUDED.remote_email,
			remote_name = EXCLUDED.remote_name, last_seen_at = now()`,
		sourceID, orgID, userIDs, remoteIDs, addresses, names); err != nil {
		return 0, fmt.Errorf("linking %d people: %w", len(userIDs), err)
	}
	return skipped, nil
}

// applyDeactivations switches people off and ends their sessions. The status
// is one statement; the sessions stay one person at a time, since that is what
// tells each application they have gone, and the deactivation ceiling bounds
// how many it can be.
func applyDeactivations(ctx context.Context, tx pgx.Tx, actions []Action) error {
	if len(actions) == 0 {
		return nil
	}
	ids := make([]string, len(actions))
	for i, a := range actions {
		ids[i] = a.UserID
	}
	// Sessions go with the account. Deactivating a user who stays signed in
	// everywhere is not a deactivation, it is a note.
	if _, err := tx.Exec(ctx, `
		UPDATE core.users SET status = 'deactivated', updated_at = now()
		WHERE id = ANY($1::uuid[])`, ids); err != nil {
		return fmt.Errorf("deactivating %d people: %w", len(ids), err)
	}
	for _, a := range actions {
		// Through TerminateSessions, not an UPDATE of its own. The UPDATE
		// that was here first wrote 'admin', which core.sessions' fixed
		// vocabulary refuses, so the transaction rolled back and the
		// departed employee stayed active and signed in; its tests never
		// gave the user a session. Once that was fixed it still told no
		// application, so they stayed signed in at every relying party
		// they had reached.
		if _, err := store.TerminateSessions(ctx, tx, "", a.UserID, store.ReasonUserDeactivated); err != nil {
			return fmt.Errorf("ending the sessions of %s: %w", a.Email, err)
		}
	}
	return nil
}

func applyReactivations(ctx context.Context, tx pgx.Tx, actions []Action) error {
	if len(actions) == 0 {
		return nil
	}
	ids := make([]string, len(actions))
	for i, a := range actions {
		ids[i] = a.UserID
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.users SET status = 'active', updated_at = now()
		WHERE id = ANY($1::uuid[])`, ids); err != nil {
		return fmt.Errorf("reactivating %d people: %w", len(ids), err)
	}
	return nil
}

// applyUpdates writes what changed about people already linked, and answers
// how many it skipped.
func applyUpdates(ctx context.Context, tx pgx.Tx, orgID, sourceID string, actions []Action) (int, error) {
	if len(actions) == 0 {
		return 0, nil
	}
	actions, skipped, err := exceptPrivileged(ctx, tx, orgID, sourceID, lastOfEachRemote(actions),
		func(a Action) string { return a.UserID })
	if err != nil {
		return 0, err
	}
	if len(actions) == 0 {
		return skipped, nil
	}
	ids, remoteIDs, addresses, names := make([]string, len(actions)), make([]string, len(actions)),
		make([]string, len(actions)), make([]string, len(actions))
	for i, a := range actions {
		ids[i], remoteIDs[i], addresses[i], names[i] = a.UserID, a.RemoteID, a.Email, a.Name
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.users u SET email = t.email, updated_at = now()
		  FROM unnest($1::uuid[], $2::text[]) AS t(id, email)
		 WHERE u.id = t.id`, ids, addresses); err != nil {
		return 0, fmt.Errorf("updating %d people: %w", len(ids), err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.directory_links l
		   SET remote_email = t.email, remote_name = t.name, last_seen_at = now()
		  FROM unnest($2::text[], $3::text[], $4::text[]) AS t(remote_id, email, name)
		 WHERE l.source_id = $1::uuid AND l.remote_id = t.remote_id`,
		sourceID, remoteIDs, addresses, names); err != nil {
		return 0, fmt.Errorf("recording what was seen: %w", err)
	}
	return skipped, nil
}

// RecordFailure notes why a sync did not complete.
func RecordFailure(ctx context.Context, db *pgxpool.Pool, sourceID string, cause error) {
	_, _ = db.Exec(ctx, `
		UPDATE core.directory_sources SET last_error = $2, updated_at = now()
		WHERE id = $1::uuid`, sourceID, cause.Error())
}
