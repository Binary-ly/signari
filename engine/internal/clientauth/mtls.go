package clientauth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// Mutual-TLS client authentication, RFC 8705.
//
// # The two halves
//
// Authentication: the client proves who it is with a certificate rather than a
// secret. Binding: the issued access token carries a thumbprint of that
// certificate, so a stolen token is useless without the private key.
//
// Doing the first without the second is the common half-implementation, and it
// leaves the token exactly as stealable as a password-authenticated one -- which
// is most of what mTLS was supposed to fix.

// TLSAuthMethod names the two RFC 8705 methods.
const (
	MethodTLSClientAuth           = "tls_client_auth"
	MethodSelfSignedTLSClientAuth = "self_signed_tls_client_auth"
)

// TLSExpectation is what a client's registration says its certificate must be.
//
// Exactly one field is set. The database enforces that; this type carries the
// same rule so a caller cannot construct an ambiguous one in memory.
type TLSExpectation struct {
	SubjectDN string
	SANDNS    string
	SANURI    string
	// SANIP and SANEmail complete RFC 8705 §2.1's five subject forms. A client
	// whose certificate identifies it by address or mailbox could not be
	// registered at all before these existed.
	SANIP      string
	SANEmail   string
	Thumbprint []byte
}

// Method reports which RFC 8705 method this expectation describes.
func (e TLSExpectation) Method() string {
	if len(e.Thumbprint) > 0 {
		return MethodSelfSignedTLSClientAuth
	}
	if e.SubjectDN != "" || e.SANDNS != "" || e.SANURI != "" ||
		e.SANIP != "" || e.SANEmail != "" {
		return MethodTLSClientAuth
	}
	return ""
}

// Configured reports whether the client uses mTLS at all.
func (e TLSExpectation) Configured() bool { return e.Method() != "" }

// VerifyClientCertificate checks a presented certificate against a registration.
//
// Does BOTH jobs: whether the certificate is trustworthy, and which client it
// identifies. They are separate questions and the answer to the first depends on
// which method the client registered -- a self-signed certificate has no chain
// to trust and needs none, while a PKI one is worthless without a verified
// chain. Conflating them is how an implementation ends up accepting any
// well-formed certificate that happens to carry the right subject string.
//
// roots may be nil, which is not permissive: it means tls_client_auth is refused
// outright.
func VerifyClientCertificate(state *tls.ConnectionState, e TLSExpectation, roots *x509.CertPool) error {
	if !e.Configured() {
		return fmt.Errorf("this client is not registered for mutual-TLS authentication")
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate was presented")
	}
	cert := state.PeerCertificates[0]

	switch e.Method() {
	case MethodSelfSignedTLSClientAuth:
		// The certificate IS the credential: a self-signed certificate has no
		// issuer worth trusting, so nothing but an exact match will do.
		got := sha256.Sum256(cert.Raw)
		if !constantTimeEqualBytes(got[:], e.Thumbprint) {
			return fmt.Errorf("the presented certificate is not the one registered " +
				"for this client")
		}
		return nil

	case MethodTLSClientAuth:
		// The chain is verified HERE rather than relied on from the TLS layer.
		//
		// The obvious approach -- tls.VerifyClientCertIfGiven with a CA pool --
		// cannot support both methods at once: with a pool configured, a
		// self-signed client is killed during the handshake before any of this
		// runs; with no pool, ANY offered certificate fails the handshake, which
		// breaks the self-signed method that exists precisely because there is no
		// CA. The listener therefore requests certificates without verifying
		// them, and the verification that matters happens where it can be
		// conditional on which method the client registered.
		//
		// This check is load-bearing: without it the peer certificate is merely
		// something the client sent, and matching a subject string against it
		// would authenticate anybody who can write that string into a certificate
		// they signed themselves.
		if roots == nil {
			return fmt.Errorf("tls_client_auth requires a trusted certificate " +
				"authority, and none is configured; set SIGNARI_TLS_CLIENT_CA " +
				"(or use self_signed_tls_client_auth for certificates without a CA)")
		}
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots: roots,
			// Client authentication, not server. Without this a certificate
			// issued for serving TLS would satisfy a client check.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			// Intermediates the client sent, if any.
			Intermediates: intermediatesFrom(state),
		}); err != nil {
			return fmt.Errorf("the client certificate does not chain to a trusted "+
				"authority: %w", err)
		}

		switch {
		case e.SubjectDN != "":
			// RFC 4514 string form, compared exactly. Deliberately not a
			// normalised or field-by-field comparison: DN equivalence has real
			// subtleties (attribute order, case, encoding) and every one of them
			// is a way for two different names to compare equal.
			if cert.Subject.String() != e.SubjectDN {
				return fmt.Errorf("certificate subject %q does not match the "+
					"registered %q", cert.Subject.String(), e.SubjectDN)
			}
			return nil

		case e.SANDNS != "":
			for _, n := range cert.DNSNames {
				// Case-insensitive because DNS is, and exact otherwise: no
				// wildcards, because a wildcard in a client identity means a
				// whole namespace can authenticate as this client.
				if strings.EqualFold(n, e.SANDNS) {
					return nil
				}
			}
			return fmt.Errorf("certificate has no dNSName matching %q", e.SANDNS)

		case e.SANURI != "":
			for _, u := range cert.URIs {
				if u.String() == e.SANURI {
					return nil
				}
			}
			return fmt.Errorf("certificate has no uniformResourceIdentifier matching %q",
				e.SANURI)

		case e.SANIP != "":
			// Compared as a parsed ADDRESS, never as text.
			//
			// "192.168.1.1" and "192.168.001.001" are the same address and
			// different strings; "::1" and "0:0:0:0:0:0:0:1" likewise. A textual
			// comparison would refuse a certificate that carries exactly the
			// registered address written another way -- and, worse, invites
			// somebody to "fix" it with a normalisation that accepts more than it
			// should. net.IP.Equal answers the question that was actually asked.
			want := net.ParseIP(e.SANIP)
			if want == nil {
				return fmt.Errorf("the registered iPAddress %q is not an IP address",
					e.SANIP)
			}
			for _, ip := range cert.IPAddresses {
				if ip.Equal(want) {
					return nil
				}
			}
			return fmt.Errorf("certificate has no iPAddress matching %q", e.SANIP)

		case e.SANEmail != "":
			// Case-insensitive, matching how the DNS half is treated and how
			// mailbox comparison works in practice. No normalisation beyond that:
			// stripping dots or plus-addressing would make two different mailboxes
			// compare equal, and this value is an identity.
			for _, m := range cert.EmailAddresses {
				if strings.EqualFold(m, e.SANEmail) {
					return nil
				}
			}
			return fmt.Errorf("certificate has no rfc822Name matching %q", e.SANEmail)
		}
	}
	return fmt.Errorf("no usable mutual-TLS expectation is registered")
}

// CertificateThumbprint is the `x5t#S256` value for a bound token.
//
// SHA-256 over the DER, base64url without padding, exactly as RFC 8705 §3.1
// specifies. The same certificate must produce the same value at issuance and at
// every later use, so the encoding is not a detail.
func CertificateThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ThumbprintFromState is the thumbprint of the certificate on this connection.
func ThumbprintFromState(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return CertificateThumbprint(state.PeerCertificates[0])
}

// constantTimeEqualBytes avoids leaking where two thumbprints diverge.
func constantTimeEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// intermediatesFrom collects everything after the leaf.
func intermediatesFrom(state *tls.ConnectionState) *x509.CertPool {
	if len(state.PeerCertificates) < 2 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	return pool
}

// sha256Of is the DER digest, shared by the thumbprint paths.
func sha256Of(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}
