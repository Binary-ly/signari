package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Outposts as `signari outpost` and the Admin API register them (6.07): a
// remote protocol server holding a token bound to one protocol and no
// database credentials.

// OutpostKinds are the protocols an outpost token can be bound to, as the
// outposts_kind_check constraint names them.
var OutpostKinds = []string{"ldap", "radius", "proxy", "desktop", "pdp"}

var (
	// ErrOutpostKind is a kind no outpost serves. The token is bound to one
	// protocol, so a leaked token costs that protocol rather than all of them.
	ErrOutpostKind = errors.New("an outpost is ldap, radius, proxy, desktop or pdp")
	// ErrOutpostExists is a name the organisation already gave an outpost.
	ErrOutpostExists = errors.New("an outpost of that name already exists in the organisation")
	// ErrOutpostUnknown is a name the organisation gave no outpost.
	ErrOutpostUnknown = errors.New("no outpost of that name in the organisation")
	// ErrSearchGroupNotLDAP is a search group on an outpost that never
	// searches the directory.
	ErrSearchGroupNotLDAP = errors.New("a search group applies to an LDAP outpost only")
	// ErrSearchGroupUnknown is a search group naming no group in the
	// organisation, which would read as granted while matching nobody.
	ErrSearchGroupUnknown = errors.New("no group of that name in the organisation")
)

// searchGroupNotLDAP is ErrSearchGroupNotLDAP naming the outpost's kind.
type searchGroupNotLDAP struct{ kind string }

func (e searchGroupNotLDAP) Error() string {
	return fmt.Sprintf("a search group applies to an LDAP outpost only; a %s outpost does not search the directory", e.kind)
}

func (e searchGroupNotLDAP) Is(target error) bool { return target == ErrSearchGroupNotLDAP }

// outpostDB is what an outpost write needs: a lookup and a write, in one
// transaction or on one connection.
type outpostDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// CheckSearchGroup refuses a search group an outpost of this kind cannot use.
// Empty is always allowed: each person behind the outpost sees only their
// own entry.
func CheckSearchGroup(ctx context.Context, q outpostDB, orgID, kind, group string) error {
	if group == "" {
		return nil
	}
	if kind != "ldap" {
		return searchGroupNotLDAP{kind}
	}
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.groups
		WHERE org_id = $1::uuid AND name = $2)`, orgID, group).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrSearchGroupUnknown
	}
	return nil
}

// CreateOutpost registers an outpost and returns its token, the one time it
// exists in the clear; it is stored hashed.
func CreateOutpost(ctx context.Context, q outpostDB, orgID, name, kind, searchGroup string) (id, token string, err error) {
	if !slices.Contains(OutpostKinds, kind) {
		return "", "", ErrOutpostKind
	}
	if err := CheckSearchGroup(ctx, q, orgID, kind, searchGroup); err != nil {
		return "", "", err
	}
	token, hash, err := NewInvitationToken() // the same 32-byte shape
	if err != nil {
		return "", "", err
	}
	if err := q.QueryRow(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash, search_group)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5, '')) RETURNING id::text`,
		orgID, name, kind, hash, searchGroup).Scan(&id); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return "", "", ErrOutpostExists
		}
		return "", "", fmt.Errorf("registering outpost %q: %w", name, err)
	}
	return id, token, nil
}

// SetOutpostSearchGroup sets or clears whose members may search the whole
// directory through an LDAP outpost. The core reads it per call; the outpost
// reads it at start.
func SetOutpostSearchGroup(ctx context.Context, q outpostDB, orgID, name, group string) error {
	var kind string
	if err := q.QueryRow(ctx, `SELECT kind FROM core.outposts
		WHERE org_id = $1::uuid AND name = $2`, orgID, name).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOutpostUnknown
		}
		return err
	}
	if err := CheckSearchGroup(ctx, q, orgID, kind, group); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE core.outposts SET search_group = NULLIF($3, '')
		WHERE org_id = $1::uuid AND name = $2`, orgID, name, group)
	return err
}

// SetOutpostEnabled takes an outpost out of service, or puts it back (2.29).
// Disabled, its token is refused from its next request to the core; its
// settings are kept.
func SetOutpostEnabled(ctx context.Context, q outpostDB, orgID, name string, enabled bool) error {
	tag, err := q.Exec(ctx, `UPDATE core.outposts SET enabled = $3
		WHERE org_id = $1::uuid AND name = $2`, orgID, name, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrOutpostUnknown
	}
	return nil
}

// Outpost is one registration, without its token, which is kept only hashed.
type Outpost struct {
	ID, Name, Kind string
	Enabled        bool
	SearchGroup    string
	LastSeenAt     *time.Time
	LastSeenIP     string
}

// Outposts lists an organisation's outposts by name.
func Outposts(ctx context.Context, q Querier, orgID string) ([]Outpost, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, kind, enabled, COALESCE(search_group, ''), last_seen_at,
		       COALESCE(last_seen_ip, '')
		  FROM core.outposts WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Outpost
	for rows.Next() {
		var o Outpost
		if err := rows.Scan(&o.ID, &o.Name, &o.Kind, &o.Enabled, &o.SearchGroup, &o.LastSeenAt,
			&o.LastSeenIP); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
