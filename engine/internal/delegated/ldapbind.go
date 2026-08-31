package delegated

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Verifying a password by binding to the directory being migrated from.
//
// # Why this exists
//
// A migration off an LDAP-backed product cannot re-hash passwords it never sees.
// The choices are to make everybody reset, or to verify against the old
// directory until each person has signed in once and their password can be
// stored here. The second is what people actually do, and doing it badly is the
// alternative to doing it at all.
//
// # The password goes to a third party, so two rules are enforced not configured
//
// The HTTP verifier already states this for token endpoints. The same reasoning,
// pointed at LDAP:
//
//   - ENCRYPTED TRANSPORT ONLY. `ldaps://`, or `ldap://` with StartTLS
//     completed. A plaintext simple bind puts the password on the wire in the
//     clear, and no convenience justifies it. There is no configuration option
//     to allow it, for the same reason the HTTP side has none for http://.
//   - THE DN IS BUILT FROM A TEMPLATE WITH THE USERNAME ESCAPED. A username is
//     attacker-chosen and a DN is a structured value; interpolating one into the
//     other unescaped lets somebody bind as a DN they chose.
//
// # An empty password is refused before anything is sent
//
// RFC 4513 §5.1.2: a simple bind carrying a DN and an empty password is an
// UNAUTHENTICATED bind, not an authentication, and a directory that answers
// success to it hands every caller a bypass. The LDAP shim in this codebase
// already refuses one on the way in; this refuses one on the way out, because
// the upstream directory may not.

// LDAPSource is a directory to verify against.
type LDAPSource struct {
	// URL must be ldaps://, or ldap:// with StartTLS.
	URL string
	// StartTLS upgrades an ldap:// connection. Ignored for ldaps://.
	StartTLS bool
	// BindDNTemplate contains {username}, which is replaced with the ESCAPED
	// username. For example: uid={username},ou=people,dc=example,dc=com
	BindDNTemplate string
	// CACerts, when set, is the only pool trusted for the connection.
	CACerts *tls.Config
}

const (
	// dialTimeout bounds reaching the directory at all.
	dialTimeout = 5 * time.Second
	// bindTimeout bounds the bind once connected.
	bindTimeout = 8 * time.Second
)

// ErrInsecureTransport is returned for a URL that would send the password in
// the clear.
var ErrInsecureTransport = fmt.Errorf(
	"delegated LDAP verification requires ldaps:// or StartTLS: a plaintext " +
		"simple bind puts the user's password on the wire in the clear")

// VerifyLDAP binds to the source directory as the user.
//
// A successful bind is the only evidence accepted. Anything else — a bind error,
// a referral, a connection failure — is a refusal, because the question asked is
// "did this credential work" and every other answer is "not demonstrably".
func VerifyLDAP(ctx context.Context, s LDAPSource, username, password string) error {
	if password == "" {
		// Before the dial, so an unauthenticated bind is never even attempted.
		return fmt.Errorf("an empty password is an unauthenticated bind, not an " +
			"authentication (RFC 4513 §5.1.2)")
	}
	if !strings.Contains(s.BindDNTemplate, "{username}") {
		return fmt.Errorf("the bind DN template must contain {username}")
	}

	lower := strings.ToLower(s.URL)
	switch {
	case strings.HasPrefix(lower, "ldaps://"):
	case strings.HasPrefix(lower, "ldap://") && s.StartTLS:
	default:
		return ErrInsecureTransport
	}

	// The DIAL is bounded, not just the operations afterwards.
	//
	// `conn.SetTimeout` only applies once there is a connection, so setting it
	// alone leaves the dial itself unbounded — and an unreachable directory then
	// blocks for the operating system's TCP timeout, which is about a minute on
	// this platform. That is a minute of a held sign-in per attempt, on the one
	// path a third party controls the latency of. It showed up as a 60-second
	// unit test before it could show up as an outage.
	conn, err := ldap.DialURL(s.URL,
		ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
		ldap.DialWithTLSConfig(s.CACerts))
	if err != nil {
		return fmt.Errorf("connecting to the source directory: %w", err)
	}
	defer conn.Close()

	// And the operations after it, for the same reason the HTTP verifier has a
	// timeout: a slow third party must not hold our own sign-in open.
	conn.SetTimeout(bindTimeout)

	if strings.HasPrefix(lower, "ldap://") {
		if err := conn.StartTLS(s.CACerts); err != nil {
			// Refused rather than continued. Falling back to plaintext because
			// the upgrade failed is exactly the downgrade StartTLS exists to
			// prevent, and it would send the password in the clear on the one
			// path where it was explicitly asked not to be.
			return fmt.Errorf("StartTLS failed and a plaintext bind will not be "+
				"attempted: %w", err)
		}
	}

	dn := strings.ReplaceAll(s.BindDNTemplate, "{username}",
		ldap.EscapeDN(username))
	if err := conn.Bind(dn, password); err != nil {
		// Not wrapped with the DN or the directory's message. A bind failure
		// distinguishes "no such user" from "wrong password" at some
		// directories, and passing that through would make this a user
		// enumeration oracle for a system we do not control.
		return fmt.Errorf("the source directory did not accept the credential")
	}
	return nil
}
