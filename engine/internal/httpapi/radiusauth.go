package httpapi

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/passwords"
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

func NewRADIUSAuthenticator(db *pgxpool.Pool, hasher *passwords.Hasher, orgID string) *RADIUSAuthenticator {
	return &RADIUSAuthenticator{inner: NewLDAPAuthenticator(db, hasher, orgID)}
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
