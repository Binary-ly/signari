package rac

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A fake guacd.
//
// It speaks the real handshake and records what it was sent, so the ordering
// rule -- values positional, matched by NAME to what guacd asked for -- can be
// checked rather than assumed. Not a substitute for the real daemon, and the
// docs say so.
type fakeGuacd struct {
	ln net.Listener
	// args is the parameter list this guacd asks for, in its order.
	args []string
	// refuse makes it answer `error` instead of `ready`.
	refuse string

	gotSelect  string
	gotConnect []string
	gotSize    []string
}

func startFakeGuacd(t *testing.T, args []string) *fakeGuacd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGuacd{ln: ln, args: args}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r, w := NewReader(conn), NewWriter(conn)

		sel, err := r.ReadInstruction()
		if err != nil {
			return
		}
		if len(sel.Args) > 0 {
			g.gotSelect = sel.Args[0]
		}
		_ = w.Write(Instruction{Opcode: "args", Args: g.args})

		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			switch in.Opcode {
			case "size":
				g.gotSize = in.Args
			case "connect":
				g.gotConnect = in.Args
				if g.refuse != "" {
					_ = w.Write(Instruction{Opcode: "error", Args: []string{g.refuse, "519"}})
					return
				}
				_ = w.Write(Instruction{Opcode: "ready", Args: []string{"$fake-connection"}})
				return
			}
		}
	}()
	return g
}

func (g *fakeGuacd) addr() string { return g.ln.Addr().String() }

func TestHandshakeCompletes(t *testing.T) {
	g := startFakeGuacd(t, []string{"hostname", "port", "username", "password"})

	s, err := Dial(g.addr(), Connection{
		Protocol: "rdp",
		Parameters: map[string]string{
			"hostname": "desktop.corp.test",
			"port":     "3389",
			"username": "alice",
			"password": "hunter2",
		},
		Width: 1440, Height: 900, DPI: 120,
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	if s.ID != "$fake-connection" {
		t.Fatalf("connection id %q", s.ID)
	}
	if g.gotSelect != "rdp" {
		t.Fatalf("selected %q", g.gotSelect)
	}
	if len(g.gotSize) != 3 || g.gotSize[0] != "1440" || g.gotSize[2] != "120" {
		t.Fatalf("size was %v", g.gotSize)
	}
}

// TestParametersFollowGuacdsOrder is the trap this design exists to avoid.
//
// `connect` supplies values POSITIONALLY, in the order guacd listed them in
// `args` -- and that list differs between protocols and between versions. An
// implementation that hardcodes the order sends the password where the hostname
// belongs the day somebody upgrades guacd.
func TestParametersFollowGuacdsOrder(t *testing.T) {
	params := map[string]string{
		"hostname": "desktop.corp.test",
		"port":     "3389",
		"username": "alice",
		"password": "hunter2",
	}

	// The same parameters, two different orders from guacd.
	for _, order := range [][]string{
		{"hostname", "port", "username", "password"},
		{"password", "username", "port", "hostname"},
	} {
		g := startFakeGuacd(t, order)
		s, err := Dial(g.addr(), Connection{Protocol: "rdp", Parameters: params},
			5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()

		if len(g.gotConnect) != len(order) {
			t.Fatalf("sent %d values for %d parameters", len(g.gotConnect), len(order))
		}
		for i, name := range order {
			if g.gotConnect[i] != params[name] {
				t.Fatalf("guacd asked for %v and position %d carried %q, which is "+
					"the value for a different parameter. Values must be matched by "+
					"NAME to what guacd asked for.", order, i, g.gotConnect[i])
			}
		}
	}
}

// TestAParameterGuacdDoesNotWantIsRefused.
//
// Sending it silently does nothing, and the operator is left wondering why
// their setting had no effect -- which is the same class as configuration that
// is documented and never read.
func TestAParameterGuacdDoesNotWantIsRefused(t *testing.T) {
	g := startFakeGuacd(t, []string{"hostname", "port"})

	_, err := Dial(g.addr(), Connection{
		Protocol: "vnc",
		Parameters: map[string]string{
			"hostname":       "desktop.corp.test",
			"port":           "5900",
			"enable-sftp":    "true",
			"recording-path": "/var/lib/signari",
		},
	}, 5*time.Second)
	if err == nil {
		t.Fatal("parameters guacd never asked for were accepted; they would have " +
			"been ignored")
	}
	if !strings.Contains(err.Error(), "enable-sftp") ||
		!strings.Contains(err.Error(), "recording-path") {
		t.Fatalf("the error does not name what was wrong: %v", err)
	}
}

// TestMissingParameterIsSentEmpty: guacd asking for something a connection does
// not define is normal -- most parameters are optional.
func TestMissingParameterIsSentEmpty(t *testing.T) {
	g := startFakeGuacd(t, []string{"hostname", "port", "domain"})

	s, err := Dial(g.addr(), Connection{
		Protocol:   "rdp",
		Parameters: map[string]string{"hostname": "d.test", "port": "3389"},
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	if len(g.gotConnect) != 3 || g.gotConnect[2] != "" {
		t.Fatalf("connect sent %v; the unset parameter must be an empty value in "+
			"its position, not omitted", g.gotConnect)
	}
}

func TestGuacdRefusalIsReported(t *testing.T) {
	g := startFakeGuacd(t, []string{"hostname"})
	g.refuse = "Connection failed"

	_, err := Dial(g.addr(), Connection{
		Protocol:   "rdp",
		Parameters: map[string]string{"hostname": "d.test"},
	}, 5*time.Second)
	if err == nil {
		t.Fatal("a refusal from guacd was reported as success")
	}
	if !strings.Contains(err.Error(), "Connection failed") {
		t.Fatalf("the reason from guacd was lost: %v", err)
	}
}

// TestHandshakeIsBounded: a guacd that accepts a connection and then says
// nothing must not hold a browser session open indefinitely.
func TestHandshakeIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Accept and say nothing at all.
		time.Sleep(10 * time.Second)
		_ = conn.Close()
	}()

	start := time.Now()
	_, err = Dial(ln.Addr().String(), Connection{
		Protocol: "rdp", Parameters: map[string]string{},
	}, 500*time.Millisecond)
	if err == nil {
		t.Fatal("a silent guacd was treated as a successful handshake")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the handshake took %s; it must be bounded", time.Since(start))
	}
}

// TestInstructionsAfterReadyAreNotStranded is a regression test for a bug that
// produced a session which connected successfully and then displayed nothing.
//
// The handshake reads through a bufio.Reader, which fills itself from the socket
// in blocks. A real guacd sends `ready` and then, immediately, the first
// instructions of the session -- so they arrive in the SAME read and sit in that
// buffer. A proxy that then copies from the bare net.Conn never sees them: they
// have already been taken off the socket and are stranded in a buffer nobody
// reads again.
//
// The write below is deliberately a single Write call. Splitting it into two
// would let the socket deliver them separately and the test would pass against
// the broken code.
func TestInstructionsAfterReadyAreNotStranded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := NewReader(conn)

		if _, err := r.ReadInstruction(); err != nil { // select
			return
		}
		_ = NewWriter(conn).Write(Instruction{Opcode: "args", Args: []string{"hostname"}})

		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			if in.Opcode != "connect" {
				continue
			}
			// One write: `ready` and the session's first instruction together.
			ready := Instruction{Opcode: "ready", Args: []string{"$c"}}.String()
			first := Instruction{Opcode: "name", Args: []string{"Desk"}}.String()
			if _, err := conn.Write([]byte(ready + first)); err != nil {
				return
			}
			// Hold the connection open so a Read that finds nothing buffered
			// blocks rather than returning EOF, which is what the bug looked
			// like in production.
			time.Sleep(2 * time.Second)
			return
		}
	}()

	s, err := Dial(ln.Addr().String(), Connection{
		Protocol:   "rdp",
		Parameters: map[string]string{"hostname": "desk.corp.test"},
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	raw := s.Raw()
	type result struct {
		data string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		buf := make([]byte, 256)
		n, err := raw.Read(buf)
		got <- result{string(buf[:n]), err}
	}()

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("reading after the handshake: %v", r.err)
		}
		if !strings.Contains(r.data, "4.name") {
			t.Fatalf("the proxy read %q, which does not contain the instruction "+
				"guacd sent with `ready`", r.data)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("the proxy blocked: the instruction guacd sent alongside `ready` " +
			"was consumed by the handshake's buffer and never forwarded")
	}
}
