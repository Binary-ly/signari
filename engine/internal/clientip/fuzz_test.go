package clientip

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

// X-Forwarded-For and Forwarded are headers any client can set. Behind a trusted proxy
// the resolver reads them; whatever they hold, it answers an address or "", unknown, so
// the rate limits and network rules keyed on it never see a value a client wrote.
func FuzzClientIP(f *testing.F) {
	f.Add("203.0.113.7, 10.0.0.1", `for=203.0.113.7;proto=https, for="[2001:db8::1]:443"`)
	f.Add("unknown, , ,", `for=_hidden;by=x`)
	f.Add("", "")
	f.Add("2001:db8::1%eth0", `for="`)
	xff, err := ParseFor(string(XForwardedFor), "10.0.0.0/8", false)
	if err != nil {
		f.Fatal(err)
	}
	fwd, err := ParseFor(string(Forwarded), "10.0.0.0/8", false)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, xffHeader, forwarded string) {
		for _, r := range []*Resolver{xff, fwd} {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "10.0.0.1:443"
			req.Header.Set("X-Forwarded-For", xffHeader)
			req.Header.Set("Forwarded", forwarded)
			ip := r.ClientIP(req)
			if _, err := netip.ParseAddr(ip); err != nil && ip != "" {
				t.Fatalf("resolved %q, which is not an address", ip)
			}
		}
	})
}
