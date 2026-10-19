package safedial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Refusing to make requests into our own network.
//
// # The attack
//
// A webhook URL is a place the identity provider will send an HTTP request, on
// request, to an address somebody else chose. That is a proxy sitting inside the
// trust boundary, and the classic use of one is to reach what the attacker
// cannot: 169.254.169.254 for cloud instance credentials, 127.0.0.1 for the
// admin API, 10.0.0.0/8 for everything else in the VPC.
//
// # Why this checks at DIAL time and not at save time
//
// Validating the hostname when the subscription is saved checks a NAME. The
// request is made to an ADDRESS, and the two are connected by DNS, which the
// person who owns the name controls. A host that resolves publicly when checked
// and to 169.254.169.254 when dialled defeats any amount of URL parsing --
// that is DNS rebinding, and it is not exotic.
//
// So the check lives in the dialler, where the address is the one actually being
// connected to. Every redirect hop is dialled too, so a 302 into the private
// range is refused by the same code.

// ErrBlocked is returned when an address is not one we will connect to.
type ErrBlocked struct {
	Host string
	IP   string
}

func (e *ErrBlocked) Error() string {
	msg := fmt.Sprintf("refusing to connect to %s (%s): it is a private, loopback "+
		"or link-local address, and an outbound request from the identity "+
		"provider to one is how an internal service gets reached from outside",
		e.Host, e.IP)
	if a, err := netip.ParseAddr(e.IP); err == nil && !isMetadata(a) {
		msg += "; a destination that is meant to be internal is named in " +
			"SIGNARI_OUTBOUND_ALLOW_PRIVATE"
	}
	return msg
}

// Blocked reports whether an address is one we refuse.
//
// Everything that is not ordinary public unicast. Go's predicates are asked
// first, because asking what KIND of address it is covers whole classes. They
// leave several special-purpose ranges looking like public unicast, though,
// and do not look inside IPv6 forms that carry an IPv4 address. Those are the
// `refused` table and embeddedIPv4 below.
func Blocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// The cloud metadata address is link-local, so the check above already
	// covers it -- named here because it is the one that matters most and a
	// future edit to the conditions above must not silently drop it.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) is the same address wearing a
	// different shape, and Go's predicates do NOT see through the mapping for
	// IsPrivate. Unmap and ask again.
	if v4 := ip.To4(); v4 != nil && len(ip) == net.IPv6len {
		return Blocked(v4)
	}
	// Unique-local IPv6 (fc00::/7). IsPrivate covers it, but only for addresses
	// Go recognises as such; the explicit test costs nothing.
	if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return true
	}

	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	for _, p := range refused {
		if p.Contains(a) {
			return true
		}
	}
	// An IPv6 address that carries an IPv4 one is that IPv4 address to anything
	// translating it, so the IPv4 address is asked about. Without this,
	// 64:ff9b::a9fe:a9fe (the metadata service, through a NAT64 gateway) and
	// 2002:7f00:1:: (loopback, through a 6to4 relay) were permitted.
	if v4, ok := embeddedIPv4(a); ok {
		return Blocked(net.IP(v4.AsSlice()))
	}
	return false
}

// refused are the ranges the predicates above do not see, which Go's
// IsPrivate, IsLoopback and the rest leave as ordinary unicast.
var refused = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network": reaches the host itself on many stacks
	netip.MustParsePrefix("100.64.0.0/10"),  // shared address space (carrier NAT), where some clouds put metadata
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking, routed inside networks that use it
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, and the broadcast address
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 for local use: a translator inside the network
	netip.MustParsePrefix("2001::/32"),      // Teredo, whose IPv4 address is obfuscated rather than embedded
	netip.MustParsePrefix("100::/64"),       // discard-only
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
	v4compat  = netip.MustParsePrefix("::/96")
)

// embeddedIPv4 returns the IPv4 address an IPv6 address carries: the last four
// bytes for NAT64's well-known prefix and the deprecated IPv4-compatible form,
// bytes two to five for 6to4.
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a), v4compat.Contains(a) && a != netip.IPv6Unspecified() && a != netip.IPv6Loopback():
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// allowed are the private destinations the operator named in
// SIGNARI_OUTBOUND_ALLOW_PRIVATE: an old identity provider being migrated off
// inside the network, an internal SCIM target. Empty is the default and means
// none.
var allowed atomic.Pointer[[]netip.Prefix]

var metadataAddr = netip.MustParseAddr("169.254.169.254")

// metadataPrefixes are the metadata address and every IPv6 form that carries
// it, which Blocked already judges by the IPv4 inside: NAT64's well-known
// prefix, the IPv4-compatible form, and 6to4, whose whole /48 embeds it. An
// allow-list entry overlapping any of them would reopen the metadata service
// through a translator.
var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("64:ff9b::a9fe:a9fe/128"),
	netip.MustParsePrefix("::a9fe:a9fe/128"),
	netip.MustParsePrefix("2002:a9fe:a9fe::/48"),
}

// isMetadata reports whether a is the metadata address, however spelled.
func isMetadata(a netip.Addr) bool {
	a = a.Unmap()
	if a == metadataAddr {
		return true
	}
	v4, ok := embeddedIPv4(a)
	return ok && v4 == metadataAddr
}

func overlapsMetadata(p netip.Prefix) bool {
	for _, m := range metadataPrefixes {
		if p.Overlaps(m) {
			return true
		}
	}
	return false
}

// AllowPrivate sets SIGNARI_OUTBOUND_ALLOW_PRIVATE, comma-separated addresses
// or prefixes that outbound requests may reach although they are private.
//
// Refused: a prefix of length zero, which is every address, and one that
// covers the cloud metadata address, which no destination needs and which is
// the first thing a forged request asks for.
func AllowPrivate(list string) error {
	var out []netip.Prefix
	for _, raw := range strings.Split(list, ",") {
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
		// Addresses are compared unmapped, so an IPv4-mapped prefix is written
		// back as the IPv4 one it means: ::ffff:0:0/96 is 0.0.0.0/0.
		if err == nil && p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		switch {
		case err != nil:
			return fmt.Errorf("SIGNARI_OUTBOUND_ALLOW_PRIVATE: %q is not an address or a prefix", raw)
		case p.Bits() == 0:
			return fmt.Errorf("SIGNARI_OUTBOUND_ALLOW_PRIVATE: %q covers every address; name "+
				"the internal destinations instead", raw)
		case overlapsMetadata(p):
			return fmt.Errorf("SIGNARI_OUTBOUND_ALLOW_PRIVATE: %q covers the cloud metadata "+
				"address 169.254.169.254, which no destination needs", raw)
		}
		out = append(out, p.Masked())
	}
	allowed.Store(&out)
	return nil
}

// permitted reports whether the dialler may connect to ip: it is not blocked,
// or it is a private address the operator allowed, or one this client allows.
// The metadata address is never permitted.
func permitted(ip net.IP, extra []netip.Prefix) bool {
	if !Blocked(ip) {
		return true
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if isMetadata(a) {
		return false
	}
	list := extra
	if p := allowed.Load(); p != nil {
		list = append(append([]netip.Prefix(nil), *p...), extra...)
	}
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Control is a net.Dialer Control function that refuses blocked addresses.
//
// Control runs AFTER the name has been resolved and BEFORE the socket connects,
// which is the only point where the address is known and nothing has been sent.
// Checking earlier checks a name; checking later has already connected.
func Control(network, address string, c syscall.RawConn) error {
	return controlWith(nil)(network, address, c)
}

func controlWith(extra []netip.Prefix) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// Control is called with a resolved address. A name here means
			// something upstream changed, and refusing is the safe reading.
			return &ErrBlocked{Host: address, IP: "unresolved"}
		}
		if !permitted(ip, extra) {
			return &ErrBlocked{Host: address, IP: ip.String()}
		}
		return nil
	}
}

// Transport returns an http.Transport that will not reach private addresses.
func Transport() *http.Transport { return transportWith(nil) }

// TransportAllowingPrivate opens every private and special-purpose range
// except the cloud metadata address, which permitted refuses before any
// allowance is read. It is for an operator who delivers inside a network they
// trust (SIGNARI_ALLOW_PRIVATE_DELIVERY). That switch once swapped in a plain
// transport, and the metadata address went with everything else: a logout or
// CIBA notification URL, which a client chooses, could then read the
// instance's credentials.
func TransportAllowingPrivate() *http.Transport {
	return transportWith([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
}

func transportWith(extra []netip.Prefix) *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: controlWith(extra)}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		// A subscriber that opens a connection and never speaks holds a
		// goroutine; an outbox drain that stalls stops delivering everything.
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   2,
	}
}

// Client returns an HTTP client for calling addresses somebody else chose.
//
// Redirects are followed but capped, and every hop is dialled through the same
// Control -- a 302 into the private range is refused exactly like a direct
// attempt. Not refusing redirects outright, because subscribers do move and a
// permanent redirect is a normal thing for a URL to do.
func Client(timeout time.Duration) *http.Client { return ClientAllowing(timeout) }

// ClientAllowing is Client that may also reach the given prefixes, for one
// destination an operator wrote down explicitly, such as an SMS gateway on
// loopback. Wider allowances belong in SIGNARI_OUTBOUND_ALLOW_PRIVATE, where
// they are visible.
func ClientAllowing(timeout time.Duration, extra ...netip.Prefix) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transportWith(extra),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			// Downgrade to plaintext is refused even though the address check
			// would allow it: the event is signed, but the body is still the
			// shape of somebody's organisation.
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("refusing a redirect from https to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

// ClientTrusting is Client with its own certificate roots, for a destination
// behind an internal certificate authority. Which certificates are trusted and
// which addresses may be reached are separate decisions: trusting a private CA
// does not open the private network, which SIGNARI_OUTBOUND_ALLOW_PRIVATE does.
func ClientTrusting(timeout time.Duration, roots *x509.CertPool) *http.Client {
	c := Client(timeout)
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS12,
	}
	return c
}

// CheckURL is a cheap pre-flight for the moment a subscription is SAVED.
//
// Not a security control -- DNS can change between saving and sending, which is
// exactly why the real check is in the dialler. This exists so an operator who
// pastes http://localhost:9000 is told immediately rather than discovering it
// from a delivery that never arrives.
func CheckURL(raw string) error {
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return fmt.Errorf("the URL must be https: an event carries the shape of " +
			"your organisation, and sending it in clear undoes the reason for signing it")
	}
	host := raw[len("https://"):]
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// The same judgement as the dialler, allow-list included, so a destination
	// the operator permitted is not refused at save time and then reached.
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && !permitted(ip, nil) {
		return (&ErrBlocked{Host: host, IP: ip.String()})
	}
	// Names are resolved rather than pattern-matched: "localhost" is not the only
	// name that points at 127.0.0.1, and a blocklist of names catches only the
	// ones somebody thought of.
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		// Unresolvable now is not necessarily unresolvable later, and refusing
		// here would stop an operator configuring a subscriber before it exists.
		return nil
	}
	for _, ip := range ips {
		if !permitted(ip, nil) {
			return &ErrBlocked{Host: host, IP: ip.String()}
		}
	}
	return nil
}
