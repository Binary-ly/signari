package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
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
	// Impersonate and TargetDomain are a Google target's administrator and
	// domain, "" for any other kind.
	Impersonate, TargetDomain string
	DryRun, Enabled           bool
	Linked, ShouldBeGone      int
	CreatedAt                 time.Time
}

// SCIMTargets lists an organisation's targets by slug, with how many people
// each holds and how many of them it still holds and should not.
func SCIMTargets(ctx context.Context, q Querier, orgID string) ([]SCIMTargetRow, error) {
	rows, err := q.Query(ctx, `
		SELECT t.id::text, t.slug, t.display_name, COALESCE(NULLIF(t.kind, ''), 'scim'), t.base_url,
		       t.on_deactivate, COALESCE(g.name, ''), COALESCE(t.impersonate, ''), COALESCE(t.target_domain, ''),
		       t.dry_run, t.enabled,
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
			&t.Impersonate, &t.TargetDomain, &t.DryRun, &t.Enabled, &t.Linked, &t.ShouldBeGone,
			&t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SCIMTargetSecret is what a target holds to authenticate there, opened: a
// SCIM target's bearer token, or a native one's credentials. So a plan can say
// whether the one a configuration file names differs; never shown.
func SCIMTargetSecret(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, root *keys.RootKey, orgID, slug string) (string, error) {
	var kind string
	var token, creds []byte
	if err := q.QueryRow(ctx, `SELECT COALESCE(NULLIF(kind, ''), 'scim'), token, COALESCE(credentials_enc, ''::bytea)
		FROM core.scim_targets WHERE org_id = $1::uuid AND slug = $2`, orgID, slug).Scan(&kind, &token, &creds); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSCIMTargetUnknown
		}
		return "", err
	}
	if root == nil {
		return "", fmt.Errorf("target %q's secret is sealed and no root key is loaded", slug)
	}
	sealed, purpose := token, "scim_token"
	if kind != "scim" {
		sealed, purpose = creds, "provision_credentials"
	}
	if len(sealed) == 0 {
		return "", nil
	}
	plain, err := root.Open(sealed, purpose)
	if err != nil {
		return "", fmt.Errorf("target %q's secret does not open: %w", slug, err)
	}
	return string(plain), nil
}
