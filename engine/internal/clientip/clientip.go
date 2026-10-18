// Package clientip decides which address a request came from.
//
// Every per-address budget in the engine (failed passwords, client-secret
// guesses, captcha, access-policy network rules) keys on this answer. Behind a
// reverse proxy the socket address is the proxy's, so without this every
// client shared one bucket: twenty bad passwords from anybody locked out
// everybody, and two hundred bad client secrets locked out every confidential
// client.
//
// A forwarding header is trusted only when the socket peer is a proxy the
// operator named. Even then, only the hops those proxies appended are trusted:
// the client is the rightmost address in the chain that is not a trusted
// proxy. Anything to its left was written by the client and may say anything.
package clientip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Source names where the client address is read from.
type Source string

const (
	// Socket is the connection's peer. The default, and the only answer when
	// nothing is behind a proxy.
	Socket Source = "socket"
	// XForwardedFor reads the X-Forwarded-For chain.
	XForwardedFor Source = "x-forwarded-for"
	// Forwarded reads the for= parameters of the Forwarded header.
	Forwarded Source = "forwarded"
)

// Resolver answers the client address for a request.
type Resolver struct {
	source  Source
	trusted []netip.Prefix
}

// Parse builds a Resolver from SIGNARI_CLIENT_IP_SOURCE and
// SIGNARI_TRUSTED_PROXIES.
//
// It refuses rather than guesses. A proxy list that covers every address would
// trust every client's header, so a prefix of length zero is refused. A header
// source with no trusted proxy would trust nobody's header and change nothing,
// and a proxy list with no header to read would be ignored. Both are refused
// because an operator who wrote either believes something is protected that
// is not.
func Parse(source, trusted string) (*Resolver, error) {
	r := &Resolver{source: Source(strings.ToLower(strings.TrimSpace(source)))}
	if r.source == "" {
		r.source = Socket
	}
	switch r.source {
	case Socket, XForwardedFor, Forwarded:
	default:
		return nil, fmt.Errorf("SIGNARI_CLIENT_IP_SOURCE %q is not one of socket, "+
			"x-forwarded-for, forwarded", source)
	}

	for _, raw := range strings.Split(trusted, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var p netip.Prefix
		var err error
		if strings.Contains(raw, "/") {
			p, err = netip.ParsePrefix(raw)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(raw); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("SIGNARI_TRUSTED_PROXIES: %q is not an address or a "+
				"CIDR prefix", raw)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("SIGNARI_TRUSTED_PROXIES: %q covers every address, so "+
				"every client's forwarding header would be believed; name the proxies", raw)
		}
		r.trusted = append(r.trusted, p.Masked())
	}

	switch {
	case r.source != Socket && len(r.trusted) == 0:
		return nil, fmt.Errorf("SIGNARI_CLIENT_IP_SOURCE=%s needs SIGNARI_TRUSTED_PROXIES: "+
			"a forwarding header is believed only from a proxy you named", r.source)
	case r.source == Socket && len(r.trusted) > 0:
		return nil, errors.New("SIGNARI_TRUSTED_PROXIES is set but SIGNARI_CLIENT_IP_SOURCE " +
			"is socket, so no header would be read; set the source to x-forwarded-for " +
			"or forwarded")
	}
	return r, nil
}

// Source reports where this resolver reads from.
func (r *Resolver) Source() Source {
	if r == nil {
		return Socket
	}
	return r.source
}

// ClientIP returns the client address for req, without a port. A nil Resolver
// reads the socket.
func (r *Resolver) ClientIP(req *http.Request) string {
	peer, ok := addrOf(req.RemoteAddr)
	if !ok {
		return hostOnly(req.RemoteAddr)
	}
	if r == nil || r.source == Socket || !r.isTrusted(peer) {
		return peer.String()
	}

	var chain []string
	if r.source == XForwardedFor {
		for _, v := range req.Header.Values("X-Forwarded-For") {
			for _, hop := range strings.Split(v, ",") {
				chain = append(chain, strings.TrimSpace(hop))
			}
		}
	} else {
		for _, v := range req.Header.Values("Forwarded") {
			chain = append(chain, forwardedFor(v)...)
		}
	}

	// Right to left. Each trusted proxy appended the address it received from;
	// the first address that is not one of ours is the client. A hop that is
	// not an address at all (a hidden identifier, or garbage) ends the walk:
	// nothing to its left can be believed, and the peer is answered rather
	// than a value a client chose.
	last := peer
	for i := len(chain) - 1; i >= 0; i-- {
		a, ok := addrOf(chain[i])
		if !ok {
			return peer.String()
		}
		if !r.isTrusted(a) {
			return a.String()
		}
		last = a
	}
	// Every hop was one of ours: the request began inside the trusted network.
	return last.String()
}

func (r *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forwardedFor returns the for= values of one Forwarded header, in order.
func forwardedFor(header string) []string {
	var out []string
	for _, element := range splitQuoted(header, ',') {
		for _, pair := range splitQuoted(element, ';') {
			k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(k), "for") {
				continue
			}
			out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
		}
	}
	return out
}

// splitQuoted splits on sep outside double quotes, so a quoted
// "[2001:db8::1]:4711" stays one value.
func splitQuoted(s string, sep rune) []string {
	var out []string
	quoted, start := false, 0
	for i, c := range s {
		switch {
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// addrOf parses an address that may carry a port or IPv6 brackets.
func addrOf(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func hostOnly(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return strings.TrimSpace(remote)
}
