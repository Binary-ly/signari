package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/radius"
)

// RADIUSAuthenticator verifies a network login against the same credential path
// as everything else.
//
// It is deliberately a thin wrapper over the LDAP shim's authenticator rather
// than its own query. Every way into this product must go through one credential
// path, with the same Argon2 parameters, the same throttling and the same audit
// trail; a protocol front end with its own quiet password check routes around
// every control the rest of the system has. The two interfaces differ only in
// what they return -- LDAP needs the identity to answer a search, RADIUS needs
// nothing but the verdict.
type RADIUSAuthenticator struct {
	inner *LDAPAuthenticator
}

func NewRADIUSAuthenticator(db *pgxpool.Pool, hasher *passwords.Hasher, orgID string,
	log *slog.Logger) *RADIUSAuthenticator {
	// Labelled `radius` in the audit trail. The credential path is shared with
	// LDAP on purpose; which port it arrived on is not a detail an
	// investigation can afford to lose.
	return &RADIUSAuthenticator{
		inner: NewLDAPAuthenticator(db, hasher, orgID, log).withVia("radius"),
	}
}

// Authenticate reports whether the credential is valid, and nothing else.
//
// The identity is discarded on purpose. RADIUS replies carry no user attributes
// here, so returning them would be handing a network device information it never
// asked for and cannot use -- and an Access-Accept is not a place to start
// leaking a directory.
func (a *RADIUSAuthenticator) Authenticate(ctx context.Context, username, password string) error {
	_, err := a.inner.Authenticate(ctx, username, password)
	return err
}

// Authorize returns the network access this person's groups grant.
//
// # Why the identity is looked up again rather than carried from Authenticate
//
// `Authenticate` returns only an error, and deliberately: the comment above it
// says the identity is discarded because "an Access-Accept is not a place to
// start leaking a directory". That reasoning still holds, and this method does
// not weaken it — what it returns is a VLAN and a filter name, both chosen by an
// operator, and never anything about the person.
//
// Keeping the two calls separate costs one indexed lookup and keeps the property
// visible in the type system: an implementation that wanted to leak a directory
// would have to change this method's return type, which is a conspicuous edit
// rather than a quiet one.
//
// # Highest priority wins, ties broken by group id
//
// A person in several authorised groups must land on the same VLAN every time
// they connect. Which rule is chosen matters less than that it is deterministic:
// without one, somebody in two groups gets an intermittent network nobody can
// reproduce.
func (a *RADIUSAuthenticator) Authorize(ctx context.Context, username string) (radius.Authorization, error) {
	var auth radius.Authorization
	var vlan *int
	var filter *string

	err := a.inner.db.QueryRow(ctx, `
		SELECT ra.vlan_id, ra.filter_id
		FROM core.radius_group_authorization ra
		JOIN core.group_members gm ON gm.group_id = ra.group_id
		JOIN core.users u          ON u.id = gm.user_id
		WHERE u.status = 'active'
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))
		ORDER BY ra.priority DESC, ra.group_id
		LIMIT 1`, username).Scan(&vlan, &filter)
	if errors.Is(err, pgx.ErrNoRows) {
		// No authorised group. Not an error: most deployments configure none,
		// and the Access-Accept then carries nothing, exactly as before.
		return auth, nil
	}
	if err != nil {
		return auth, fmt.Errorf("reading RADIUS authorisation for %q: %w", username, err)
	}
	if vlan != nil {
		auth.VLANID = *vlan
	}
	if filter != nil {
		auth.FilterID = *filter
	}
	return auth, nil
}
