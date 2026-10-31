package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// A provider's groups as this deployment's (8.14). A remote name grants a local group
// because an operator said so and for no other reason; 0223 says why.

// ErrIdPGroupImpersonates is a mapping onto a group whose members may act as other
// users: whoever administers the provider could add themselves.
var ErrIdPGroupImpersonates = errors.New("that group's members may impersonate others, so no provider may grant it")

// ErrIdPGroupUnknown is a mapping onto a group the organisation does not have.
var ErrIdPGroupUnknown = errors.New("the organisation has no group of that name")

// idpGroupEnds finds what a mapping connects.
func idpGroupEnds(ctx context.Context, q outpostDB, orgID, slug, group string) (providerID, groupID string, err error) {
	if err := q.QueryRow(ctx, `SELECT id::text FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&providerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrProviderUnknown
		}
		return "", "", err
	}
	if groupID, err = GroupIDNamed(ctx, q, orgID, group); err != nil {
		return "", "", err
	}
	if groupID == "" {
		return "", "", ErrIdPGroupUnknown
	}
	return providerID, groupID, nil
}

// SetIdPGroupMap says a provider's group grants a local one.
func SetIdPGroupMap(ctx context.Context, q outpostDB, orgID, slug, remote, group string) error {
	providerID, groupID, err := idpGroupEnds(ctx, q, orgID, slug, group)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO core.idp_group_map (provider_id, org_id, remote_group, group_id)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid) ON CONFLICT DO NOTHING`, providerID, orgID, remote, groupID)
	switch {
	case err != nil && strings.Contains(err.Error(), "remote_group_check"):
		return idpInvalid{"a remote group is 1 to 512 characters"}
	case err != nil && strings.Contains(err.Error(), "grants impersonation"):
		return ErrIdPGroupImpersonates
	}
	return err
}

// RemoveIdPGroupMap stops it. Nobody leaves the group for that: a provider no longer
// governs a group it is not mapped to, and who is in it is then an administrator's.
func RemoveIdPGroupMap(ctx context.Context, q outpostDB, orgID, slug, remote, group string) error {
	providerID, groupID, err := idpGroupEnds(ctx, q, orgID, slug, group)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `DELETE FROM core.idp_group_map
		WHERE provider_id = $1::uuid AND remote_group = $2 AND group_id = $3::uuid`, providerID, remote, groupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrIdPMappingUnknown
	}
	return nil
}

// groupClaimValues reads a claim as group names: a list, or the one name a provider
// with one to report sends as a string. ok is false when the claim is absent.
func groupClaimValues(rawClaims []byte, claim string) (names []string, ok bool, err error) {
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, false, fmt.Errorf("reading the provider's claims: %w", err)
	}
	value, present := claims[claim]
	if !present {
		return nil, false, nil
	}
	switch v := value.(type) {
	case string:
		return []string{v}, true, nil
	case []any:
		for _, item := range v {
			if name, isString := item.(string); isString {
				names = append(names, name)
			}
		}
		return names, true, nil
	}
	return nil, true, nil
}

// ApplyIdPGroups makes the groups this provider governs what its claim says for this
// person, in the sign-in's transaction, so that a group lost upstream ends at the next
// sign-in. Only groups a mapping names: a membership elsewhere is none of its business.
//
// A claim that is absent changes nothing, where one present and empty leaves every
// governed group. Providers omit a claim for reasons that say nothing about membership,
// one with too many groups to fit in a token among them, and reading that as "in nothing"
// would throw everybody out at once.
func ApplyIdPGroups(ctx context.Context, tx pgx.Tx, userID, orgID, providerID string, rawClaims []byte) (joined, left int, err error) {
	if len(rawClaims) == 0 {
		return 0, 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT m.remote_group, m.group_id::text, p.group_claim
		FROM core.idp_group_map m JOIN core.identity_providers p ON p.id = m.provider_id
		WHERE m.provider_id = $1::uuid AND m.org_id = $2::uuid`, providerID, orgID)
	if err != nil {
		return 0, 0, fmt.Errorf("reading the provider's group mapping: %w", err)
	}
	type mapping struct{ remote, group string }
	var mapped []mapping
	var claim string
	for rows.Next() {
		var m mapping
		if err := rows.Scan(&m.remote, &m.group, &claim); err != nil {
			rows.Close()
			return 0, 0, err
		}
		mapped = append(mapped, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(mapped) == 0 {
		return 0, 0, nil
	}
	names, present, err := groupClaimValues(rawClaims, claim)
	if err != nil || !present {
		return 0, 0, err
	}

	want := map[string]bool{}
	for _, m := range mapped {
		want[m.group] = want[m.group] || slices.Contains(names, m.remote)
	}
	for group, member := range want {
		if member {
			tag, err := tx.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
				VALUES ($1::uuid, $2::uuid, $3::uuid) ON CONFLICT DO NOTHING`, group, userID, orgID)
			if err != nil {
				return 0, 0, fmt.Errorf("adding to a group the provider grants: %w", err)
			}
			joined += int(tag.RowsAffected())
			continue
		}
		tag, err := tx.Exec(ctx, `DELETE FROM core.group_members
			WHERE group_id = $1::uuid AND user_id = $2::uuid AND org_id = $3::uuid`, group, userID, orgID)
		if err != nil {
			return 0, 0, fmt.Errorf("removing from a group the provider no longer grants: %w", err)
		}
		left += int(tag.RowsAffected())
	}
	return joined, left, nil
}
