package safedial

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// An allow-list that admits everything, or the metadata address, is the
// guard switched off under another name, so it is refused at startup.
func TestTheAllowListRefusesWhatWouldSwitchTheGuardOff(t *testing.T) {
	t.Cleanup(func() { _ = AllowPrivate("") })
	for _, c := range []struct{ list, want string }{
		{"0.0.0.0/0", "covers every address"},
		{"::/0", "covers every address"},
		{"10.0.0.0/8, 0.0.0.0/0", "covers every address"},
		{"::ffff:0:0/96", "covers every address"},
		{"::ffff:169.254.169.254", "metadata"},
		// The IPv6 forms that carry it, which Blocked judges by the IPv4 inside.
		{"64:ff9b::/96", "metadata"},
		{"2002::/16", "metadata"},
		{"2002:a9fe:a9fe:1::/64", "metadata"},
		{"::a9fe:a9fe", "metadata"},
		{"169.254.0.0/16", "metadata"},
		{"169.254.169.254", "metadata"},
		{"128.0.0.0/1", "metadata"},
		{"not-an-address", "not an address"},
		{"10.0.0.0/33", "not an address"},
	} {
		if err := AllowPrivate(c.list); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("AllowPrivate(%q) = %v, want it refused mentioning %q", c.list, err, c.want)
		}
	}
	if err := AllowPrivate(" 10.20.0.0/16 , 192.168.7.9 ,, fd00:1::/32 "); err != nil {
		t.Fatalf("an ordinary internal list was refused: %v", err)
	}
}

// Every metadata endpoint, not only 169.254.169.254, in every form that carries
// it, plus the translators whose destination cannot be read. The first version
// refused only the one address, so each of the first four lists below reopened
// a cloud's credentials service.
func TestNoAllowanceReachesAnyMetadataEndpoint(t *testing.T) {
	t.Cleanup(func() { _ = AllowPrivate("") })
	for _, list := range []string{
		"fd00::/8", "fd00:ec2::/32", "fd00:ec2::254", // the IPv6 instance metadata service
		"100.64.0.0/10", "100.100.100.200", // another cloud's, in the shared address space
		"169.254.170.0/24", "169.254.170.2", // container credentials
		"64:ff9b::6464:64c8", "2002:a9fe:aa00::/40", "::a9fe:aa02", // the same, translated
		"64:ff9b:1::/48", "64:ff9b:1:fffe::/96", // local-use NAT64: any mechanism, unreadable
		"2001::/32", "2001:0:4136:e378::/64", // Teredo: the client address is inverted
	} {
		if err := AllowPrivate(list); err == nil || !strings.Contains(err.Error(), "metadata") {
			t.Errorf("AllowPrivate(%q) = %v, want it refused as covering a metadata endpoint", list, err)
		}
	}
	// Ranges beside them stay allowable.
	if err := AllowPrivate("fd00:1::/32, 100.64.0.0/16, 169.254.171.0/24, 10.20.0.0/16"); err != nil {
		t.Fatalf("an ordinary internal list beside the endpoints was refused: %v", err)
	}

	// At dial, under the widest allowance there is: what
	// SIGNARI_ALLOW_PRIVATE_DELIVERY passes.
	everything := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for _, ip := range []string{
		"169.254.169.254", "fd00:ec2::254", "169.254.170.2", "100.100.100.200",
		"::ffff:100.100.100.200", "64:ff9b::a9fe:aa02", "2002:6464:64c8::1",
		"64:ff9b:1::a9fe:a9fe", "64:ff9b:1:fffe::a9fe:a9fe",
		"2001:0:4136:e378:8000:63bf:5601:5601", // Teredo whose inverted client is 169.254.169.254
	} {
		if permitted(net.ParseIP(ip), everything) {
			t.Errorf("an allowance of everything reached %s", ip)
		}
	}
	for _, ip := range []string{"10.20.0.1", "fd00:1::5", "100.64.0.1", "169.254.171.1", "64:ff9b::a14:1"} {
		if !permitted(net.ParseIP(ip), everything) {
			t.Errorf("an allowance of everything refused %s, which is no metadata endpoint", ip)
		}
	}
}

// The allow-list widens what may be reached by exactly what it names.
func TestTheAllowListPermitsWhatItNamesAndNothingElse(t *testing.T) {
	t.Cleanup(func() { _ = AllowPrivate("") })
	if err := AllowPrivate("10.20.0.0/16,::ffff:192.168.7.9"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"10.20.3.4", true},
		{"192.168.7.9", true},
		{"::ffff:10.20.3.4", true}, // the same address in its mapped form
		{"10.21.0.1", false},
		{"192.168.7.10", false},
		{"127.0.0.1", false},
		{"169.254.169.254", false},
		{"8.8.8.8", true}, // public addresses never needed the list
	} {
		if got := permitted(net.ParseIP(c.ip), nil); got != c.want {
			t.Errorf("permitted(%s) = %v, want %v", c.ip, got, c.want)
		}
	}

	// A per-client allowance cannot reach the metadata address either, in any
	// of its spellings.
	for _, c := range []struct{ ip, allowance string }{
		{"169.254.169.254", "169.254.0.0/16"},
		{"64:ff9b::a9fe:a9fe", "64:ff9b::/96"},
		{"2002:a9fe:a9fe::1", "2002::/16"},
	} {
		if permitted(net.ParseIP(c.ip), []netip.Prefix{netip.MustParsePrefix(c.allowance)}) {
			t.Errorf("an allowance of %s reached the metadata address as %s", c.allowance, c.ip)
		}
	}
	// While the same translators to an ordinary internal address stay allowable.
	if !permitted(net.ParseIP("64:ff9b::a14:1"), []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}) {
		t.Error("an allowed NAT64 path to 10.20.0.1 was refused")
	}
}

// End to end through the dialler: loopback is refused by default, reachable
// once allowed for one client, and still refused for every other client.
func TestAClientAllowanceIsThatClientsAlone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "reached")
	}))
	defer srv.Close()
	loop := netip.MustParsePrefix("127.0.0.1/32")

	resp, err := ClientAllowing(0, loop).Get(srv.URL)
	if err != nil {
		t.Fatalf("the allowed client was refused: %v", err)
	}
	_ = resp.Body.Close()

	if resp, err := Client(0).Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an allowance given to one client reached loopback from another")
	}
}

// Trusting an internal certificate authority and reaching the internal network
// are two decisions. The first alone is still refused at the dialler; with the
// address allowed as well, the request completes over the private roots.
func TestTrustingAPrivateCADoesNotOpenThePrivateNetwork(t *testing.T) {
	t.Cleanup(func() { _ = AllowPrivate("") })
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "reached")
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	if resp, err := ClientTrusting(0, roots).Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a trusted certificate opened loopback")
	} else if !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("err = %v, want the dialler's refusal", err)
	}

	if err := AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	resp, err := ClientTrusting(0, roots).Get(srv.URL)
	if err != nil {
		t.Fatalf("allowed and trusted, still refused: %v", err)
	}
	_ = resp.Body.Close()
}

func TestCheckURLAgreesWithTheAllowList(t *testing.T) {
	t.Cleanup(func() { _ = AllowPrivate("") })
	if err := CheckURL("https://10.20.0.5/hook"); err == nil {
		t.Fatal("a private address was accepted before anything allowed it")
	} else if !strings.Contains(err.Error(), "SIGNARI_OUTBOUND_ALLOW_PRIVATE") {
		t.Errorf("the refusal does not say how to allow it: %v", err)
	}
	// The metadata address is not offered the way out, because there is none.
	if err := CheckURL("https://169.254.169.254/"); err == nil ||
		strings.Contains(err.Error(), "SIGNARI_OUTBOUND_ALLOW_PRIVATE") {
		t.Errorf("metadata refusal = %v, want it refused with no allow-list hint", err)
	}
	if err := AllowPrivate("10.20.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := CheckURL("https://10.20.0.5/hook"); err != nil {
		t.Fatalf("an allowed address was refused at save time but would be dialled: %v", err)
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
