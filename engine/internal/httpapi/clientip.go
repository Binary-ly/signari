package httpapi

import (
	"net"
	"net/http"
	"net/netip"

	"signari.dev/engine/internal/clientip"
)

// withClientIP resolves the client address once, at the edge, and puts it in
// r.RemoteAddr.
//
// Every per-address decision in this package reads r.RemoteAddr or clientIP(r):
// the sign-in, client-secret and second-factor budgets, the captcha counter,
// access-policy network rules and the log lines. Rewriting it here is what
// makes them agree. Resolving it in each caller would be ten places to forget
// the proxy, and the captcha already had.
func (s *Server) withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.clientIPs.Source() == clientip.Socket {
			s.warnIfBehindAnUnnamedProxy(r)
			next.ServeHTTP(w, r)
			return
		}
		r2 := r.WithContext(r.Context()) // a shallow copy is all RemoteAddr needs
		r2.RemoteAddr = net.JoinHostPort(s.clientIPs.ClientIP(r), "0")
		next.ServeHTTP(w, r2)
	})
}

// budgetIP is ip as a per-address budget counts it: an IPv6 address's /64
// (clientip.Budget). Every `:ip:` budget key is built through it, so that the
// count and the check of one budget agree and no budget can be reset by
// stepping to the next address in the same subnet.
// TestEveryAddressBudgetIsKeyedByItsSubnet fails on a key built without it.
func budgetIP(ip string) string { return clientip.Budget(ip) }

// warnIfBehindAnUnnamedProxy says so, once, when forwarding headers arrive from
// a private or loopback peer while no proxy is trusted. That is the shape of a
// deployment behind an ingress that nobody configured, in which every client
// shares the proxy's budgets and twenty wrong passwords from anyone lock out
// everyone.
func (s *Server) warnIfBehindAnUnnamedProxy(r *http.Request) {
	if r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("Forwarded") == "" {
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !(a.IsPrivate() || a.IsLoopback()) {
		return
	}
	s.unconfiguredProxyWarning.Do(func() {
		s.log.Warn("requests carry forwarding headers from a private address but "+
			"SIGNARI_TRUSTED_PROXIES is unset, so every client behind that proxy shares "+
			"one address for rate limits, captcha and network policy",
			"peer", host)
	})
}
