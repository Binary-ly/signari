package safedial

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

// A client is built per call by nearly every caller here (a federated sign-in's exchange, a
// hook's call, a delivery), so the connection one call makes must be the next call's, and
// one left idle must be closed in time. Each client had a transport of its own: fifty calls
// were fifty connections, every one left open, and a provider that never closes them ran
// the ports out under load (E.21).
func TestClientsBuiltPerCallShareTheirConnections(t *testing.T) {
	var opened atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	loop := netip.MustParsePrefix("127.0.0.1/32")

	const calls = 50
	for range calls {
		resp, err := ClientAllowing(0, loop).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if n := opened.Load(); n > 1 {
		t.Errorf("%d calls, each through a client built for it, opened %d connections; they share one", calls, n)
	}

	tr, ok := Underneath(ClientAllowing(0, loop).Transport)
	if !ok || tr.IdleConnTimeout <= 0 {
		t.Errorf("an idle connection is never closed by this side (IdleConnTimeout %v)", tr.IdleConnTimeout)
	}
	if other, _ := Underneath(Client(0).Transport); other == tr {
		t.Error("a client with no allowance shares the transport of one allowed loopback")
	}
}
