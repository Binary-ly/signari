package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// A provisioning target's settings as `signari scim` and the Admin API
// change them (6.07). Registering one, and anything that calls it, is in
// internal/provision.

var (
	// ErrSCIMTargetUnknown is a slug the organisation gave no target.
	ErrSCIMTargetUnknown = errors.New("no provisioning target of that slug in the organisation")
	// ErrScopeGroupUnknown is a scope naming no group in the organisation.
	ErrScopeGroupUnknown = errors.New("no group of that name in the organisation")
)

// SetSCIMTargetEnabled takes a target in or out of service. Disabled, syncs
// skip it and its configuration, links and remote ids are kept: deleting it
// would take the links, and the accounts at the far end would be unreachable
// rather than merely unmanaged.
func SetSCIMTargetEnabled(ctx context.Context, q Execer, orgID, slug string, enabled bool) error {
	tag, err := q.Exec(ctx, `UPDATE core.scim_targets SET enabled = $3 WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSCIMTargetUnknown
	}
	return nil
}

// SetSCIMTargetScope limits a target to one group's members, or with "" lets
// it provision everybody in the organisation. Narrowing deprovisions, at the
// next sync, the people who fall out of scope; widening provisions the ones
// who come in. The column is ON DELETE RESTRICT, so deleting the group cannot
// widen the target as a side effect.
func SetSCIMTargetScope(ctx context.Context, q outpostDB, orgID, slug, group string) error {
	var groupID any
	if group = strings.TrimSpace(group); group != "" {
		id, err := GroupIDNamed(ctx, q, orgID, group)
		if err != nil {
			return err
		}
		if id == "" {
			return ErrScopeGroupUnknown
		}
		groupID = id
	}
	tag, err := q.Exec(ctx, `UPDATE core.scim_targets SET scope_group_id = $3::uuid
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, groupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSCIMTargetUnknown
	}
	return nil
}

// SCIMTargetRow is one target as an administrator sees it, without its
// token or credentials.
type SCIMTargetRow struct {
	ID, Slug, Name, Kind, BaseURL, OnDeactivate, ScopeGroup string
	DryRun, Enabled                                         bool
	Linked, ShouldBeGone                                    int
	CreatedAt                                               time.Time
}

// SCIMTargets lists an organisation's targets by slug, with how many people
// each holds and how many of them it still holds and should not.
func SCIMTargets(ctx context.Context, q Querier, orgID string) ([]SCIMTargetRow, error) {
	rows, err := q.Query(ctx, `
		SELECT t.id::text, t.slug, t.display_name, COALESCE(NULLIF(t.kind, ''), 'scim'), t.base_url,
		       t.on_deactivate, COALESCE(g.name, ''), t.dry_run, t.enabled,
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id),
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id AND NOT l.should_be_active),
		       t.created_at
		  FROM core.scim_targets t
		  LEFT JOIN core.groups g ON g.id = t.scope_group_id
		 WHERE t.org_id = $1::uuid ORDER BY t.slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SCIMTargetRow
	for rows.Next() {
		var t SCIMTargetRow
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Kind, &t.BaseURL, &t.OnDeactivate, &t.ScopeGroup,
			&t.DryRun, &t.Enabled, &t.Linked, &t.ShouldBeGone, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
