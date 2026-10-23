package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/radius"
)

// RADIUS clients and group authorisation as `signari radius` and the Admin
// API write them (6.07). The listener reads both per minute, so neither needs
// a restart.

// SealContextRADIUSSecret binds a sealed RADIUS shared secret to its column.
const SealContextRADIUSSecret = "radius-client-secret"

var (
	// ErrRADIUSNetworkTaken is a range the organisation already registered a
	// device for: two entries for one range with different secrets is a
	// configuration nobody can reason about.
	ErrRADIUSNetworkTaken = errors.New("a RADIUS client for that network is already registered in the organisation")
	// ErrRADIUSClientUnknown is a device the organisation did not register.
	ErrRADIUSClientUnknown = errors.New("no RADIUS client of that id in the organisation")
	// ErrRADIUSNothingAuthorised is a group authorisation with neither a VLAN
	// nor a Filter-Id, a row somebody believes is doing something.
	ErrRADIUSNothingAuthorised = errors.New("a RADIUS authorisation needs a VLAN, a Filter-Id or both")
	// ErrVLANRange is a VLAN id outside RFC 3580 section 3.31's 1 to 4094.
	ErrVLANRange = errors.New("a VLAN id is 12 bits: 1 to 4094 (RFC 3580 section 3.31)")
	// ErrFilterIDLength is a Filter-Id longer than one RADIUS attribute holds.
	ErrFilterIDLength = errors.New("a Filter-Id is at most 253 characters")
	// ErrRADIUSNotAuthorised is a group that carries no RADIUS authorisation.
	ErrRADIUSNotAuthorised = errors.New("that group carries no RADIUS authorisation")
)

// AddRADIUSClient registers a device permitted to send Access-Requests from
// network, sealing its shared secret. The network is normalised before it is
// checked and stored, so an IPv4-mapped spelling of every address is refused
// like the plain one; the stored form is returned.
func AddRADIUSClient(ctx context.Context, q outpostDB, root *keys.RootKey, orgID, name, network,
	secret string) (id, stored string, err error) {
	if err := radius.ValidSecret(secret); err != nil {
		return "", "", err
	}
	ipnet, err := radius.ClientNetwork(network)
	if err != nil {
		return "", "", fmt.Errorf("network %w", err)
	}
	if root == nil {
		return "", "", fmt.Errorf("a RADIUS shared secret is sealed under SIGNARI_ROOT_KEY, which is not loaded")
	}
	sealed, err := root.Seal([]byte(secret), SealContextRADIUSSecret)
	if err != nil {
		return "", "", fmt.Errorf("sealing the shared secret: %w", err)
	}
	stored = ipnet.String()
	if err := q.QueryRow(ctx, `
		INSERT INTO core.radius_clients (org_id, name, network, secret_enc)
		VALUES ($1::uuid, $2, $3::cidr, $4)
		RETURNING id::text`, orgID, name, stored, sealed).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return "", "", ErrRADIUSNetworkTaken
		}
		return "", "", err
	}
	return id, stored, nil
}

// SetRADIUSClientEnabled revokes or restores a device's access. Running
// listeners pick it up within a minute. It does not end sessions already
// established through the device: RADIUS cannot reach back into a switch.
func SetRADIUSClientEnabled(ctx context.Context, q Execer, orgID, id string, enabled bool) error {
	tag, err := q.Exec(ctx, `UPDATE core.radius_clients SET enabled = $3, updated_at = now()
		WHERE org_id = $1::uuid AND id = $2::uuid`, orgID, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRADIUSClientUnknown
	}
	return nil
}

// RADIUSClient is one registered device, without its secret.
type RADIUSClient struct {
	ID, Name, Network string
	Enabled           bool
}

// RADIUSClients lists an organisation's devices by name.
func RADIUSClients(ctx context.Context, q Querier, orgID string) ([]RADIUSClient, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, host(network) || '/' || masklen(network), enabled
		  FROM core.radius_clients WHERE org_id = $1::uuid ORDER BY name, network`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RADIUSClient
	for rows.Next() {
		var c RADIUSClient
		if err := rows.Scan(&c.ID, &c.Name, &c.Network, &c.Enabled); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetRADIUSAuthorization places a group's members on a VLAN, a Filter-Id or
// both, at a priority for somebody in several authorised groups; 0 and ""
// leave either out. Replaces what the group carried.
func SetRADIUSAuthorization(ctx context.Context, q Execer, orgID, groupID string, vlan int, filterID string,
	priority int) error {
	filterID = strings.TrimSpace(filterID)
	if vlan == 0 && filterID == "" {
		return ErrRADIUSNothingAuthorised
	}
	var vlanArg, filterArg any
	if vlan != 0 {
		vlanArg = vlan
	}
	if filterID != "" {
		filterArg = filterID
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO core.radius_group_authorization
		    (org_id, group_id, vlan_id, filter_id, priority)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5)
		ON CONFLICT (org_id, group_id) DO UPDATE
		   SET vlan_id = EXCLUDED.vlan_id, filter_id = EXCLUDED.filter_id,
		       priority = EXCLUDED.priority`,
		orgID, groupID, vlanArg, filterArg, priority); err != nil {
		switch {
		case strings.Contains(err.Error(), "radius_group_authorization_vlan_id_check"):
			return ErrVLANRange
		case strings.Contains(err.Error(), "radius_group_authorization_filter_id_check"):
			return ErrFilterIDLength
		}
		return err
	}
	return nil
}

// RemoveRADIUSAuthorization takes a group's VLAN and Filter-Id away. Members
// already connected keep theirs until they are re-authorised.
func RemoveRADIUSAuthorization(ctx context.Context, q Execer, orgID, groupID string) error {
	tag, err := q.Exec(ctx, `DELETE FROM core.radius_group_authorization
		WHERE org_id = $1::uuid AND group_id = $2::uuid`, orgID, groupID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRADIUSNotAuthorised
	}
	return nil
}

// RADIUSAuthorization is what one group's members are given at Access-Accept.
type RADIUSAuthorization struct {
	GroupID, Group string
	VLAN           *int
	FilterID       string
	Priority       int
}

// RADIUSAuthorizations lists an organisation's authorised groups, highest
// priority first, among the groups given; nil means every group.
func RADIUSAuthorizations(ctx context.Context, q Querier, orgID string, groups []string) ([]RADIUSAuthorization, error) {
	rows, err := q.Query(ctx, `
		SELECT a.group_id::text, g.name, a.vlan_id, COALESCE(a.filter_id, ''), a.priority
		  FROM core.radius_group_authorization a
		  JOIN core.groups g ON g.id = a.group_id
		 WHERE a.org_id = $1::uuid AND ($2::uuid[] IS NULL OR a.group_id = ANY($2::uuid[]))
		 ORDER BY a.priority DESC, a.group_id`, orgID, groups)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RADIUSAuthorization
	for rows.Next() {
		var a RADIUSAuthorization
		if err := rows.Scan(&a.GroupID, &a.Group, &a.VLAN, &a.FilterID, &a.Priority); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
