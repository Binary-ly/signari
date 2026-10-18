package safedial

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The addresses an outbound request from an identity provider must never reach.
//
// Each of these is a real SSRF target, not a hypothetical one.
func TestBlockedCoversTheAddressesThatMatter(t *testing.T) {
	for _, c := range []struct {
		ip      string
		blocked bool
		why     string
	}{
		{"169.254.169.254", true, "cloud instance metadata -- credentials, for the asking"},
		{"127.0.0.1", true, "loopback: the admin API listens here"},
		{"::1", true, "loopback, IPv6"},
		{"10.1.2.3", true, "RFC 1918"},
		{"172.16.5.5", true, "RFC 1918, the range people forget"},
		{"192.168.1.1", true, "RFC 1918"},
		{"0.0.0.0", true, "unspecified: routes to localhost on Linux"},
		{"169.254.1.1", true, "link-local"},
		{"fd00::1", true, "unique-local IPv6"},
		{"fe80::1", true, "link-local IPv6"},
		{"224.0.0.1", true, "multicast"},
		{"::ffff:127.0.0.1", true, "loopback wearing an IPv6 shape"},
		{"::ffff:10.0.0.1", true, "RFC 1918 wearing an IPv6 shape"},

		// The ranges Go's predicates leave as public unicast.
		{"0.1.2.3", true, "'this network'"},
		{"100.64.0.1", true, "shared address space, where some clouds put metadata"},
		{"100.100.100.200", true, "shared address space"},
		{"192.0.0.8", true, "IETF protocol assignments"},
		{"198.18.0.1", true, "benchmarking"},
		{"198.19.255.255", true, "benchmarking, upper end"},
		{"240.0.0.1", true, "reserved"},
		{"255.255.255.255", true, "broadcast"},
		{"100::1", true, "discard-only"},
		// IPv6 forms that carry an IPv4 address are asked about that address.
		{"64:ff9b::a9fe:a9fe", true, "the metadata service through a NAT64 gateway"},
		{"64:ff9b::7f00:1", true, "loopback through NAT64"},
		{"64:ff9b:1::1", true, "NAT64 for local use"},
		{"2002:7f00:1::", true, "loopback through a 6to4 relay"},
		{"2002:a00:1::", true, "10.0.0.1 through 6to4"},
		{"2001::1", true, "Teredo"},
		{"::7f00:1", true, "loopback in the deprecated IPv4-compatible form"},

		{"93.184.216.34", false, "ordinary public unicast"},
		{"8.8.8.8", false, "ordinary public unicast"},
		{"2606:2800:220:1::1", false, "ordinary public unicast, IPv6"},
		{"64:ff9b::808:808", false, "8.8.8.8 through NAT64 is still 8.8.8.8"},
		{"2002:808:808::", false, "8.8.8.8 through 6to4"},
		{"198.20.0.1", false, "just past the benchmarking range"},
		{"100.128.0.1", false, "just past the shared address space"},
		{"192.0.2.1", false, "documentation; unroutable, and the provider tests rely on it being permitted"},
	} {
		got := Blocked(net.ParseIP(c.ip))
		if got != c.blocked {
			t.Errorf("Blocked(%s) = %v, want %v -- %s", c.ip, got, c.blocked, c.why)
		}
	}
}

// The check that matters: it happens at DIAL time, so a name that resolves to a
// private address is refused however innocent the name looks.
func TestTheDiallerRefusesLoopbackHoweverItIsSpelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request reached a loopback server; the guard did not fire")
	}))
	defer srv.Close()

	c := Client(0)
	// srv.URL is http://127.0.0.1:PORT -- exactly what an attacker would supply
	// to reach a service that only listens locally.
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the request succeeded; this is an SSRF")
	}
	if !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("err = %v, want the guard's refusal", err)
	}
}

func TestCheckURLRefusesTheObviousMistakes(t *testing.T) {
	for _, c := range []struct{ url, want string }{
		{"http://example.com/hook", "must be https"},
		{"https://127.0.0.1/hook", "refusing to connect"},
		{"https://[::1]/hook", "refusing to connect"},
		{"https://169.254.169.254/latest/meta-data/", "refusing to connect"},
	} {
		err := CheckURL(c.url)
		if err == nil {
			t.Errorf("CheckURL(%q) accepted it", c.url)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("CheckURL(%q) = %q, want it to mention %q", c.url, err, c.want)
		}
	}

	// A name that does not resolve is NOT refused: a subscriber can be
	// configured before it exists, and the dialler is the real guard anyway.
	if err := CheckURL("https://not-a-real-host-4f9a2b.example/hook"); err != nil {
		t.Errorf("an unresolvable host was refused at save time: %v", err)
	}
}
