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
	return ParseFor(source, trusted, false)
}

// ParseFor is Parse for a deployment where some listener reads a PROXY
// protocol header from the trusted proxies (internal/proxyproto). Then the
// socket address already is the client's, and a proxy list with no forwarding
// header to read is the configuration of a TCP balancer rather than a mistake.
func ParseFor(source, trusted string, proxyProtocol bool) (*Resolver, error) {
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
	case r.source == Socket && len(r.trusted) > 0 && !proxyProtocol:
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
// reads the socket. It is "" when a trusted proxy's Forwarded header cannot be
// parsed because a client left a quoted string open in it.
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
			hops, ok := forwardedFor(v)
			if !ok {
				// A quote left open may hold the hop our proxy appended, so
				// nothing on the line can be placed. Unknown, NOT the peer: the
				// client chose to be unplaceable, and the peer is the proxy's
				// own, usually internal, address -- answering it would hand
				// anyone who sends this header whatever a from_networks rule
				// grants the proxy's range. Every per-address decision treats
				// "" as unknown: budgets share one bucket, network rules fail.
				return ""
			}
			chain = append(chain, hops...)
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

// Trusts reports whether a is one of the proxies the operator named.
func (r *Resolver) Trusts(a netip.Addr) bool {
	if r == nil {
		return false
	}
	return r.isTrusted(a.Unmap())
}

func (r *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forwardedFor returns the for= values of one Forwarded header, in order. ok
// is false when a quoted string in it never closes.
func forwardedFor(header string) (out []string, ok bool) {
	elements, ok := splitQuoted(header, ',')
	if !ok {
		return nil, false
	}
	for _, element := range elements {
		pairs, _ := splitQuoted(element, ';')
		for _, pair := range pairs {
			k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(k), "for") {
				continue
			}
			out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
		}
	}
	return out, true
}

// splitQuoted splits on sep outside quoted strings, so a quoted
// "[2001:db8::1]:4711" stays one value.
//
// A value is a token or a quoted-string (RFC 7239 §4), and inside a
// quoted-string a backslash escapes the next character (RFC 9110 §5.6.4,
// quoted-pair). ok is false when a quoted string is still open at the end.
// That is the case to refuse: a client sending `for=1.2.3.4;by="` left the
// quote open, the comma and hop its proxy appended to the same line landed
// inside it, and the client's own for= was the only one left to believe.
func splitQuoted(s string, sep rune) (parts []string, ok bool) {
	quoted, escaped, start := false, false, 0
	for i, c := range s {
		switch {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:]), !quoted
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

// Budget is the key a per-address budget counts ip under: an IPv6 address's
// /64, and an IPv4 address as it is. "" stays "", which callers already treat
// as unknown.
//
// A /64 is one subnet, and a host on it may use any of its 2^64 addresses --
// privacy addresses rotate on their own, and choosing a fresh one is a
// configuration line. Keyed by the full /128, every new address arrived with a
// fresh budget, so twenty failed passwords per address was no limit at all for
// anyone reaching the server over IPv6. The /64 is where a network ends and a
// host begins, so it is the narrowest key a client cannot step out of by itself.
//
// Only for budgets. A network rule judges the address as it is, and logs
// record it whole.
func Budget(ip string) string {
	a, ok := addrOf(ip)
	switch {
	case !ok:
		return ip
	case a.Is4():
		// Unmapped, so ::ffff:192.0.2.7 and 192.0.2.7 are one budget.
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

func hostOnly(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return strings.TrimSpace(remote)
}
