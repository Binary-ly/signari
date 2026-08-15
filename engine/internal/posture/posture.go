// Package posture decides whether a request came from a managed device.
//
// # No agent
//
// This project has said it will not build endpoint agents: that is a different
// product, it needs privileged software on every machine, and running one is a
// larger commitment than most deployments realise. So posture here is derived
// from evidence the request already carries.
//
// Two sources, in order of how much they are worth:
//
//	device certificate   the browser or client presents an mTLS certificate
//	                     issued by the organisation's own device authority.
//	                     Strong: the private key is on the device, usually in
//	                     hardware, and it cannot be copied into a request by
//	                     somebody who merely knows a header name.
//
//	trusted proxy header an MDM-aware proxy in front of this engine asserts the
//	                     device state. Only as strong as the proxy: the header
//	                     is accepted ONLY from configured addresses, because
//	                     otherwise anybody who can reach the port asserts their
//	                     own compliance.
//
// # Why the header source is dangerous and still offered
//
// A posture header is a claim by whoever sent it. Accepting one from any source
// converts "device trust" into "send this header" -- which is worse than having
// no device trust at all, because a policy that reads as enforced is not
// questioned.
//
// It is offered because a great many real deployments already have an MDM-aware
// proxy and no device PKI, and refusing them the feature pushes them toward
// nothing. The address allow-list is what makes it defensible, and it is
// mandatory: with no trusted proxies configured, headers are ignored entirely.
package posture

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// State is what was established about the device.
type State struct {
	Managed   bool
	Compliant bool
	// Source names what the verdict rests on, for the audit trail. "none" is a
	// real answer and must be distinguishable from "unmanaged" -- one means we
	// looked and it is not managed, the other that we had no way to tell.
	Source string
}

// Config is how a deployment establishes posture.
type Config struct {
	// DeviceCAs verifies device certificates. nil means that source is off.
	DeviceCAs *x509.CertPool
	// TrustedProxies may assert posture by header. Empty means headers are
	// ignored, whatever they say.
	TrustedProxies []*net.IPNet
	// ManagedHeader and CompliantHeader are the header names to read.
	ManagedHeader   string
	CompliantHeader string
}

// Evaluate establishes device posture for a request.
//
// Certificate evidence wins over header evidence when both are present: one is
// cryptographic and the other is an assertion by a machine in the path.
func (c *Config) Evaluate(r *http.Request) State {
	if c == nil {
		return State{Source: "none"}
	}

	if st := c.fromCertificate(r.TLS); st.Source != "none" {
		return st
	}
	return c.fromHeaders(r)
}

// fromCertificate reads a device certificate.
func (c *Config) fromCertificate(state *tls.ConnectionState) State {
	if c.DeviceCAs == nil || state == nil || len(state.PeerCertificates) == 0 {
		return State{Source: "none"}
	}
	cert := state.PeerCertificates[0]

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         c.DeviceCAs,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Intermediates: intermediates(state),
	}); err != nil {
		// A certificate that does not chain to the device authority proves
		// nothing. NOT an error: the request may still be a perfectly ordinary
		// unmanaged one, and refusing it here would make every personal device a
		// failure rather than an unmanaged device.
		return State{Source: "none"}
	}

	// Issued by the device authority means managed. Compliance is a further
	// claim that a certificate alone does not make -- an MDM that revokes
	// certificates for non-compliant devices makes the two equivalent, and one
	// that does not, does not. So the honest reading is managed-only.
	return State{Managed: true, Source: "device-certificate"}
}

// fromHeaders reads an assertion from a trusted proxy.
func (c *Config) fromHeaders(r *http.Request) State {
	if len(c.TrustedProxies) == 0 || c.ManagedHeader == "" {
		return State{Source: "none"}
	}
	if !c.trusted(r.RemoteAddr) {
		// The header may well be present. It is ignored, and deliberately not
		// reported as an error: an untrusted peer sending a posture header is
		// exactly what an attacker does, and answering differently would confirm
		// the header name is meaningful.
		return State{Source: "none"}
	}

	managed := truthy(r.Header.Get(c.ManagedHeader))
	compliant := managed && c.CompliantHeader != "" &&
		truthy(r.Header.Get(c.CompliantHeader))

	if !managed {
		return State{Source: "trusted-proxy"}
	}
	return State{Managed: true, Compliant: compliant, Source: "trusted-proxy"}
}

func (c *Config) trusted(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range c.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// truthy reads the small set of affirmatives proxies actually emit.
//
// Deliberately narrow. Treating any non-empty value as true would make
// `X-Device-Managed: false` mean managed, which is the kind of bug that survives
// review because the header is present and the policy passes.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "managed", "compliant":
		return true
	}
	return false
}

// ParseNetworks reads a comma-separated CIDR list.
func ParseNetworks(spec string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR: %w", part, err)
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("%q trusts every address on the internet to assert "+
				"its own device posture, which is the same as having none", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// intermediates collects everything the client sent after the leaf.
func intermediates(state *tls.ConnectionState) *x509.CertPool {
	if len(state.PeerCertificates) < 2 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	return pool
}
