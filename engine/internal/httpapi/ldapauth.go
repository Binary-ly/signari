package httpapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
)

// LDAPAuthenticator connects the LDAP shim to the real credential path.
//
// It deliberately does NOT verify passwords itself. Every bind goes through the
// same store lookup and the same Argon2 verifier as the sign-in form, so an
// LDAP bind is throttled, audited and subject to the same lockout as any other
// authentication. An LDAP front end with its own quiet credential path is a way
// around every control the rest of the product has.
type LDAPAuthenticator struct {
	db     *pgxpool.Pool
	hasher *passwords.Hasher
	orgID  string
}

func NewLDAPAuthenticator(db *pgxpool.Pool, hasher *passwords.Hasher, orgID string) *LDAPAuthenticator {
	return &LDAPAuthenticator{db: db, hasher: hasher, orgID: orgID}
}

var errLDAPInvalid = errors.New("invalid credentials")

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*ldapd.Identity, error) {
	// Belt and braces. The protocol layer refuses an empty password before
	// reaching here (RFC 4513 unauthenticated bind), and this is the second
	// place that would have to fail for one to get through.
	if password == "" {
		return nil, errLDAPInvalid
	}

	// The same query the sign-in form uses, including its status check: a
	// deactivated account must not be able to bind, and duplicating the rule
	// here is how the two paths drift apart.
	var userID, orgID, hash string
	err := a.db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text, pc.hash
		FROM core.users u
		JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status = 'active' AND pc.is_current
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))`,
		username).Scan(&userID, &orgID, &hash)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("looking up the credential: %w", err)
	}
	if !found || (a.orgID != "" && orgID != a.orgID) {
		// The dummy verify keeps the timing of "no such user" indistinguishable
		// from "wrong password". Skipping it here would make the LDAP port a
		// user-enumeration oracle by stopwatch even though the error text is
		// identical.
		_, _ = a.hasher.Verify(ctx, dummyHash, password)
		return nil, errLDAPInvalid
	}
	if _, err := a.hasher.Verify(ctx, hash, password); err != nil {
		return nil, errLDAPInvalid
	}

	id, err := a.Lookup(ctx, username)
	if err != nil || id == nil {
		return nil, errLDAPInvalid
	}
	_ = userID
	return id, nil
}

func (a *LDAPAuthenticator) Lookup(ctx context.Context, username string) (*ldapd.Identity, error) {
	var id ldapd.Identity
	err := a.db.QueryRow(ctx, `
		SELECT COALESCE(NULLIF(u.username,''), u.email, u.id::text),
		       COALESCE(u.email,''), u.status = 'active'
		FROM core.users u
		WHERE u.org_id = $1::uuid
		  AND (lower(u.username) = lower($2) OR lower(u.email) = lower($2))
		  AND u.status = 'active'`, a.orgID, username).
		Scan(&id.Username, &id.Email, &id.Active)
	if err != nil {
		return nil, nil
	}
	id.DisplayName = id.Username
	return &id, nil
}

func (a *LDAPAuthenticator) List(ctx context.Context, limit int) ([]*ldapd.Identity, error) {
	rows, err := a.db.Query(ctx, `
		SELECT COALESCE(NULLIF(username,''), email, id::text), COALESCE(email,'')
		FROM core.users
		WHERE org_id = $1::uuid AND status = 'active'
		ORDER BY created_at
		LIMIT $2`, a.orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*ldapd.Identity
	for rows.Next() {
		var id ldapd.Identity
		if err := rows.Scan(&id.Username, &id.Email); err != nil {
			return nil, err
		}
		id.Active = true
		id.DisplayName = id.Username
		out = append(out, &id)
	}
	return out, rows.Err()
}
