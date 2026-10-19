package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// A budget counts an IPv6 client by its /64, the subnet whose addresses it can
// step between, and an IPv4 client by its address.
func TestABudgetCountsAnIPv6ClientByItsSubnet(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:1:2:3:4:5:6":  "2001:db8:1:2::/64",
		"2001:db8:1:2::ffff":    "2001:db8:1:2::/64",
		"[2001:db8:1:2::7]":     "2001:db8:1:2::/64",
		"2001:db8:1:3::1":       "2001:db8:1:3::/64",
		"::ffff:192.0.2.7":      "192.0.2.7",
		"192.0.2.7":             "192.0.2.7",
		"":                      "",
		"not an address":        "not an address",
		"fe80::1234:5678:9:abc": "fe80::/64",
	} {
		if got := Budget(in); got != want {
			t.Errorf("Budget(%q) = %q, want %q", in, got, want)
		}
	}
}

func request(remote string, headers ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func TestTheClientIsTheRightmostAddressThatIsNotATrustedProxy(t *testing.T) {
	xff, err := Parse("x-forwarded-for", "10.0.0.0/8, 192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	fwd, err := Parse("forwarded", "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		r    *Resolver
		req  *http.Request
		want string
	}{
		{"an untrusted peer's header is ignored", xff,
			request("203.0.113.9:5000", "X-Forwarded-For", "198.51.100.1"), "203.0.113.9"},
		{"one trusted proxy", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "198.51.100.1"), "198.51.100.1"},
		{"a client-written prefix is not believed", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "1.2.3.4, 198.51.100.1"), "198.51.100.1"},
		{"two trusted hops", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "6.6.6.6, 198.51.100.1, 192.0.2.10"), "198.51.100.1"},
		{"the chain across several header lines", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "6.6.6.6", "X-Forwarded-For", "198.51.100.1"), "198.51.100.1"},
		{"a port on a hop", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "198.51.100.1:4711"), "198.51.100.1"},
		{"IPv6 in brackets with a port", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "[2001:db8::7]:4711"), "2001:db8::7"},
		{"every hop is ours", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "10.1.1.1, 10.2.2.2"), "10.1.1.1"},
		{"no header from a trusted proxy", xff, request("10.0.0.2:5000"), "10.0.0.2"},
		{"garbage where the client should be answers the peer", xff,
			request("10.0.0.2:5000", "X-Forwarded-For", "198.51.100.1, not-an-address"), "10.0.0.2"},
		{"an IPv4-mapped peer is matched as IPv4", xff,
			request("[::ffff:10.0.0.2]:5000", "X-Forwarded-For", "198.51.100.1"), "198.51.100.1"},
		{"Forwarded, quoted IPv6 with a port", fwd,
			request("10.0.0.2:5000", "Forwarded", `for="[2001:db8:cafe::17]:4711";proto=https`), "2001:db8:cafe::17"},
		{"Forwarded, several elements", fwd,
			request("10.0.0.2:5000", "Forwarded", "for=6.6.6.6, for=198.51.100.1;by=10.0.0.2"), "198.51.100.1"},
		{"Forwarded, a hidden identifier ends the walk", fwd,
			request("10.0.0.2:5000", "Forwarded", "for=198.51.100.1, for=_hidden"), "10.0.0.2"},
		// The client leaves a quote open; its proxy appends the real hop to
		// the same line, inside the quote. Neither the client's choice nor the
		// proxy's own address: unknown.
		{"Forwarded, an unterminated quote swallowing the proxy's hop is unknown", fwd,
			request("10.0.0.2:5000", "Forwarded", `for=1.2.3.4;by=", for=198.51.100.1`), ""},
		{"Forwarded, an escaped quote does not close the string", fwd,
			request("10.0.0.2:5000", "Forwarded", `for=1.2.3.4;by="\", for=198.51.100.1`), ""},
		{"Forwarded, an escaped quote inside a closed string is one value", fwd,
			request("10.0.0.2:5000", "Forwarded", `for=6.6.6.6;by="a\"b", for=198.51.100.1`), "198.51.100.1"},
		{"Forwarded, an unterminated quote on any line is unknown", fwd,
			request("10.0.0.2:5000", "Forwarded", `for=1.2.3.4;by="`, "Forwarded", "for=198.51.100.1"), ""},
		{"the socket source ignores headers", nil,
			request("10.0.0.2:5000", "X-Forwarded-For", "198.51.100.1"), "10.0.0.2"},
	} {
		if got := c.r.ClientIP(c.req); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAConfigurationThatProtectsNothingIsRefused(t *testing.T) {
	for _, c := range []struct{ source, trusted, want string }{
		{"x-forwarded-for", "0.0.0.0/0", "covers every address"},
		{"forwarded", "10.0.0.0/8, ::/0", "covers every address"},
		{"x-forwarded-for", "", "needs SIGNARI_TRUSTED_PROXIES"},
		{"socket", "10.0.0.0/8", "no header would be read"},
		{"x-real-ip", "10.0.0.0/8", "is not one of"},
		{"x-forwarded-for", "10.0.0.0/33", "not an address or a CIDR prefix"},
	} {
		_, err := Parse(c.source, c.trusted)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q, %q) = %v, want an error containing %q", c.source, c.trusted, err, c.want)
		}
	}
	if r, err := Parse("", ""); err != nil || r.Source() != Socket {
		t.Errorf("the default is not the socket: %v %v", r, err)
	}
}

// Behind a TCP balancer that sends a PROXY header, the socket already is the
// client and the trusted list names the balancer: the one combination Parse
// refuses as protecting nothing is then the configuration that works.
func TestTrustedProxiesWithTheSocketSourceAreAcceptedForAPROXYBalancer(t *testing.T) {
	r, err := ParseFor("socket", "10.0.0.5, 2001:db8::/64", true)
	if err != nil {
		t.Fatalf("a PROXY balancer's configuration was refused: %v", err)
	}
	for addr, want := range map[string]bool{
		"10.0.0.5": true, "::ffff:10.0.0.5": true, "2001:db8::9": true,
		"10.0.0.6": false, "2001:db9::9": false,
	} {
		if got := r.Trusts(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Trusts(%s) = %v, want %v", addr, got, want)
		}
	}
	if _, err := ParseFor("socket", "10.0.0.5", false); err == nil {
		t.Error("without a PROXY listener the same configuration was accepted")
	}
	if _, err := ParseFor("socket", "0.0.0.0/0", true); err == nil {
		t.Error("a balancer list covering every address was accepted")
	}
	var nilResolver *Resolver
	if nilResolver.Trusts(netip.MustParseAddr("10.0.0.5")) {
		t.Error("no resolver trusted an address")
	}
}
