package delegated

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"signari.dev/engine/internal/safedial"
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
//
// The refusal says which kind it is, as the token-endpoint verifier's does
// (2.01): ErrRejected when the directory answered no, ErrUnavailable when it
// could not be asked. Every error was bare, so the sign-in path took an
// unreachable directory for a wrong password, charged it to the person, and
// told them their password was incorrect during somebody else's outage.
func VerifyLDAP(ctx context.Context, s LDAPSource, username, password string) error {
	_, _, err := bindLDAP(ctx, s, username, password)
	return err
}

// The steps of a bind, as a test names the one that failed (7.18).
const (
	StepConfiguration = "configuration"
	StepDial          = "dial"
	StepTLS           = "tls"
	StepBind          = "bind"
	StepAnswer        = "answer"
)

// bindLDAP is VerifyLDAP, answering the step it stopped at and, when the
// directory refused the bind, its result code: the test shows the operator
// both, and sign-in neither.
func bindLDAP(ctx context.Context, s LDAPSource, username, password string) (step, result string, err error) {
	if password == "" {
		// Before the dial, so an unauthenticated bind is never even attempted.
		return StepConfiguration, "", fmt.Errorf("%w: an empty password is an unauthenticated bind, not an "+
			"authentication (RFC 4513 §5.1.2)", ErrRejected)
	}
	if !strings.Contains(s.BindDNTemplate, "{username}") {
		return StepConfiguration, "", fmt.Errorf("%w: the bind DN template must contain {username}",
			ErrUnavailable)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return StepConfiguration, "", fmt.Errorf("%w: the directory URL does not parse", ErrUnavailable)
	}
	ldaps := strings.EqualFold(u.Scheme, "ldaps")
	switch {
	case ldaps:
	case strings.EqualFold(u.Scheme, "ldap") && s.StartTLS:
	default:
		return StepConfiguration, "", fmt.Errorf("%w: %w", ErrUnavailable, ErrInsecureTransport)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), map[bool]string{true: "636", false: "389"}[ldaps])
	}

	// The DIAL is bounded, not just the operations afterwards.
	//
	// `conn.SetTimeout` only applies once there is a connection, so setting it
	// alone leaves the dial itself unbounded — and an unreachable directory then
	// blocks for the operating system's TCP timeout, which is about a minute on
	// this platform. That is a minute of a held sign-in per attempt, on the one
	// path a third party controls the latency of. It showed up as a 60-second
	// unit test before it could show up as an outage.
	//
	// Through safedial's Control, as the token-endpoint verifier's client is:
	// the URL is a stored setting and the connection carries a password, so a
	// directory in the private network is reached only when the operator named
	// it in SIGNARI_OUTBOUND_ALLOW_PRIVATE. It dialled anywhere.
	raw, err := (&net.Dialer{Timeout: dialTimeout, Control: safedial.Control}).DialContext(ctx, "tcp", host)
	if err != nil {
		return StepDial, "", fmt.Errorf("%w: connecting to the source directory: %w", ErrUnavailable, err)
	}

	var conn *ldap.Conn
	if ldaps {
		// The handshake as a step of its own, so a wrong CA is named as one
		// rather than as a connection that failed. With no server name, the
		// host's, as go-ldap's own dial took it.
		conf := &tls.Config{}
		if s.CACerts != nil {
			conf = s.CACerts.Clone()
		}
		if conf.ServerName == "" {
			conf.ServerName = u.Hostname()
		}
		tc := tls.Client(raw, conf)
		hctx, cancel := context.WithTimeout(ctx, bindTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = raw.Close()
			return StepTLS, "", fmt.Errorf("%w: the TLS handshake with the source directory failed: %w",
				ErrUnavailable, err)
		}
		conn = ldap.NewConn(tc, true)
	} else {
		conn = ldap.NewConn(raw, false)
	}
	conn.Start()
	defer conn.Close()

	// And the operations after it, for the same reason the HTTP verifier has a
	// timeout: a slow third party must not hold our own sign-in open.
	conn.SetTimeout(bindTimeout)

	if !ldaps {
		if err := conn.StartTLS(s.CACerts); err != nil {
			// Refused rather than continued. Falling back to plaintext because
			// the upgrade failed is exactly the downgrade StartTLS exists to
			// prevent, and it would send the password in the clear on the one
			// path where it was explicitly asked not to be.
			return StepTLS, "", fmt.Errorf("%w: StartTLS failed and a plaintext bind will not be "+
				"attempted: %w", ErrUnavailable, err)
		}
	}

	dn := strings.ReplaceAll(s.BindDNTemplate, "{username}",
		ldap.EscapeDN(username))
	if err := conn.Bind(dn, password); err != nil {
		var le *ldap.Error
		if errors.As(err, &le) {
			result = ldap.LDAPResultCodeMap[le.ResultCode]
		}
		// A directory that is busy, shutting down or unreachable mid-bind did
		// not answer the question, and that is not the person's fault.
		if ldap.IsErrorAnyOf(err, ldap.ErrorNetwork, ldap.LDAPResultBusy,
			ldap.LDAPResultUnavailable, ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultOther) {
			return StepBind, result, fmt.Errorf("%w: the source directory did not answer the bind", ErrUnavailable)
		}
		// Not wrapped with the DN or the directory's message. A bind failure
		// distinguishes "no such user" from "wrong password" at some
		// directories, and passing that through would make this a user
		// enumeration oracle for a system we do not control.
		return StepBind, result, fmt.Errorf("%w: the source directory did not accept the credential", ErrRejected)
	}
	return "", "", nil
}
