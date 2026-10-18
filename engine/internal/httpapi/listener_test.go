package httpapi

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The public listener had no read or write timeout, so a body sent a byte at a
// time held a goroutine for as long as the sender liked.

func listenOn(t *testing.T, srv *http.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestThePublicListenerBoundsEveryRequest(t *testing.T) {
	srv := NewPublicServer("", http.NotFoundHandler())
	if srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("the public listener leaves a timeout unset: read %v, write %v, header %v, idle %v",
			srv.ReadTimeout, srv.WriteTimeout, srv.ReadHeaderTimeout, srv.IdleTimeout)
	}
}

func TestASlowBodyIsCutOff(t *testing.T) {
	result := make(chan error, 1)
	srv := NewPublicServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		result <- err
	}))
	srv.ReadTimeout = time.Second // the production value is 30s; the mechanism is the same
	addr := listenOn(t, srv)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				if _, err := conn.Write([]byte("a")); err != nil {
					return
				}
			}
		}
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("a body trickled a byte at a time was read to the end")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("five seconds into a trickled body the handler is still reading it; " +
			"nothing bounds how long a slow client may hold a goroutine")
	}
}

// The remote-access tunnel is a hijacked connection, and survives the request
// timeouts only because net/http clears them on hijack (listener.go). If that
// ever stops being true, every remote desktop is cut off at PublicReadTimeout.
func TestAHijackedTunnelOutlivesTheRequestTimeouts(t *testing.T) {
	srv := NewPublicServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		time.Sleep(1500 * time.Millisecond) // past both timeouts below
		_, _ = brw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nalive\n")
		_ = brw.Flush()
	}))
	srv.ReadTimeout, srv.WriteTimeout = time.Second, time.Second
	addr := listenOn(t, srv)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the tunnel was cut off at the request timeout: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "alive") {
		t.Fatalf("got %q from the tunnel", body)
	}
}
