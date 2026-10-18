package outpost

import (
	"crypto/tls"
	"fmt"
	"net"
)

// ListenLDAP opens the LDAP outpost's listener: LDAPS when a certificate is
// given, and plaintext only when the operator asks for it by name.
//
// New refuses a plaintext -core, because the outpost would otherwise carry
// every password it verifies across the network in the clear. The listener
// was the other half of that journey and accepted every bind in plaintext:
// the password crossed the wire unprotected before it ever reached the
// encrypted half. It now fails closed, as the admin API does, because a
// warning in a log is how a plaintext listener survives in production.
//
// StartTLS is not the alternative: internal/ldapd refuses it rather than
// answer success without upgrading, so LDAPS on its own port is the way in.
func ListenLDAP(addr, certFile, keyFile string, insecure bool) (net.Listener, error) {
	switch {
	case certFile == "" && keyFile == "" && !insecure:
		return nil, fmt.Errorf("the LDAP outpost needs -tls-cert and -tls-key: every " +
			"simple bind carries a password, and without TLS it crosses the network " +
			"in the clear. Plaintext is available as -ldap-insecure, for a listener " +
			"bound to loopback behind something that terminates TLS")
	case (certFile == "") != (keyFile == ""):
		return nil, fmt.Errorf("give both -tls-cert and -tls-key, or neither")
	case certFile != "" && insecure:
		return nil, fmt.Errorf("-ldap-insecure and -tls-cert contradict each other; " +
			"give one")
	}

	if insecure {
		return net.Listen("tcp", addr)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("LDAPS certificate: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	}), nil
}
