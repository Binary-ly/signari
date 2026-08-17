package safedial

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
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
	return fmt.Sprintf("refusing to connect to %s (%s): it is a private, loopback "+
		"or link-local address, and an outbound request from the identity "+
		"provider to one is how an internal service gets reached from outside",
		e.Host, e.IP)
}

// Blocked reports whether an address is one we refuse.
//
// Everything that is not ordinary public unicast. Listing the ranges by name
// would miss one; asking what KIND of address it is does not.
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
	return false
}

// Control is a net.Dialer Control function that refuses blocked addresses.
//
// Control runs AFTER the name has been resolved and BEFORE the socket connects,
// which is the only point where the address is known and nothing has been sent.
// Checking earlier checks a name; checking later has already connected.
func Control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control is called with a resolved address. A name here means something
		// upstream changed, and refusing is the safe reading.
		return &ErrBlocked{Host: address, IP: "unresolved"}
	}
	if Blocked(ip) {
		return &ErrBlocked{Host: address, IP: ip.String()}
	}
	return nil
}

// Transport returns an http.Transport that will not reach private addresses.
func Transport() *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: Control}
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
func Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(),
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
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && Blocked(ip) {
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
		if Blocked(ip) {
			return &ErrBlocked{Host: host, IP: ip.String()}
		}
	}
	return nil
}
