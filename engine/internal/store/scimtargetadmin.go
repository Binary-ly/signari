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

// SetSCIMTargetScope limits a target to these groups' members, or with none lets
// it provision everybody in the organisation. Narrowing deprovisions, at the next
// sync, the people who fall out of scope; widening provisions the ones who come
// in. A group held here cannot be deleted, so deleting one cannot widen the target
// as a side effect.
//
// One statement, so the CLI, which writes outside a transaction, cannot leave a
// target between the two and provisioning everybody. It leaves out of the delete
// what the insert would put back, because the two see one snapshot.
func SetSCIMTargetScope(ctx context.Context, q outpostDB, orgID, slug string, groups []string) error {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		if group = strings.TrimSpace(group); group == "" {
			continue
		}
		id, err := GroupIDNamed(ctx, q, orgID, group)
		if err != nil {
			return err
		}
		if id == "" {
			return fmt.Errorf("%w: %s", ErrScopeGroupUnknown, group)
		}
		ids = append(ids, id)
	}
	tag, err := q.Exec(ctx, `
		WITH target AS (
			SELECT id, org_id FROM core.scim_targets WHERE org_id = $1::uuid AND slug = $2
		), dropped AS (
			DELETE FROM core.scim_target_scope_groups s USING target
			 WHERE s.target_id = target.id AND s.group_id <> ALL($3::uuid[])
		), added AS (
			INSERT INTO core.scim_target_scope_groups (target_id, group_id, org_id)
			SELECT target.id, g, target.org_id FROM target, unnest($3::uuid[]) g
			ON CONFLICT DO NOTHING
		)
		UPDATE core.scim_targets t SET updated_at = now() FROM target WHERE t.id = target.id`,
		orgID, slug, ids)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSCIMTargetUnknown
	}
	return nil
}

// SetSCIMTargetRecreate says whether a sync gives somebody a new account when
// the one linked to them is gone from the target.
func SetSCIMTargetRecreate(ctx context.Context, q Execer, orgID, slug string, recreate bool) error {
	tag, err := q.Exec(ctx, `UPDATE core.scim_targets SET recreate_missing = $3
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, recreate)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSCIMTargetUnknown
	}
	return nil
}

// SetSCIMTargetCompatibility says what a target needs that the protocol does not
// say it should.
func SetSCIMTargetCompatibility(ctx context.Context, q Execer, orgID, slug string, compatibility []string) error {
	tag, err := q.Exec(ctx, `UPDATE core.scim_targets SET compatibility = $3
		WHERE org_id = $1::uuid AND slug = $2`, orgID, slug, compatibility)
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
	ID, Slug, Name, Kind, BaseURL, OnDeactivate string
	// ScopeGroups are the groups it is limited to, by name; none is everybody.
	ScopeGroups []string
	// Impersonate and TargetDomain are a Google target's administrator and
	// domain, "" for any other kind.
	Impersonate, TargetDomain string
	DryRun, Enabled           bool
	RecreateMissing           bool
	Linked, ShouldBeGone      int
	CreatedAt                 time.Time
	// OAuthTokenURL, OAuthClientID and OAuthScope are the client credentials
	// grant it authenticates with, "" for a bearer token.
	OAuthTokenURL, OAuthClientID, OAuthScope string
	// OAuthClientAuth is how that client authenticates, "" with no grant.
	OAuthClientAuth string
	// OAuthAuthorizeURL is where somebody signs in for the authorization code
	// grant, "" for any other, and OAuthAuthorizedAt when somebody last did, nil
	// until then.
	OAuthAuthorizeURL string
	OAuthAuthorizedAt *time.Time
	// Compatibility names what it needs that the protocol does not say it should.
	Compatibility []string
}

// OAuthGrant names the grant a target authenticates with, "" for a bearer token.
func (t SCIMTargetRow) OAuthGrant() string {
	switch {
	case t.OAuthAuthorizeURL != "":
		return "authorization_code"
	case t.OAuthTokenURL != "":
		return "client_credentials"
	}
	return ""
}

// SCIMTargets lists an organisation's targets by slug, with how many people
// each holds and how many of them it still holds and should not.
func SCIMTargets(ctx context.Context, q Querier, orgID string) ([]SCIMTargetRow, error) {
	rows, err := q.Query(ctx, `
		SELECT t.id::text, t.slug, t.display_name, COALESCE(NULLIF(t.kind, ''), 'scim'), t.base_url,
		       t.on_deactivate,
		       ARRAY(SELECT g.name FROM core.scim_target_scope_groups s JOIN core.groups g ON g.id = s.group_id
		              WHERE s.target_id = t.id ORDER BY g.name),
		       COALESCE(t.impersonate, ''), COALESCE(t.target_domain, ''),
		       t.dry_run, t.enabled, t.recreate_missing,
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id),
		       (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id AND NOT l.should_be_active),
		       t.created_at, COALESCE(t.oauth_token_url, ''), COALESCE(t.oauth_client_id, ''),
		       COALESCE(t.oauth_scope, ''), t.compatibility,
		       CASE WHEN t.oauth_token_url IS NULL THEN '' ELSE t.oauth_client_auth END,
		       COALESCE(t.oauth_authorize_url, ''), t.oauth_authorized_at
		  FROM core.scim_targets t
		 WHERE t.org_id = $1::uuid ORDER BY t.slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SCIMTargetRow
	for rows.Next() {
		var t SCIMTargetRow
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Kind, &t.BaseURL, &t.OnDeactivate, &t.ScopeGroups,
			&t.Impersonate, &t.TargetDomain, &t.DryRun, &t.Enabled, &t.RecreateMissing, &t.Linked,
			&t.ShouldBeGone, &t.CreatedAt, &t.OAuthTokenURL, &t.OAuthClientID, &t.OAuthScope,
			&t.Compatibility, &t.OAuthClientAuth, &t.OAuthAuthorizeURL, &t.OAuthAuthorizedAt); err != nil {
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
