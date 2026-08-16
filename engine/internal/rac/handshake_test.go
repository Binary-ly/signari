package rac

import (
	"io"
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

	type result struct {
		data string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		frame, err := s.ReadFrame()
		got <- result{string(frame), err}
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

// parseFrameStandalone parses a frame the way the browser's tunnel does: on its
// own, holding nothing over from the frame before.
//
// That independence is the whole reason ReadFrame exists, so the test has to
// model it rather than reusing a reader that would paper over a split.
func parseFrameStandalone(t *testing.T, frame []byte) []Instruction {
	t.Helper()
	r := NewReader(strings.NewReader(string(frame)))
	var out []Instruction
	for {
		in, err := r.ReadInstruction()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("a frame did not parse on its own: %v\nframe ended: %q",
				err, tail(frame))
		}
		out = append(out, in)
	}
}

func tail(b []byte) string {
	if len(b) > 40 {
		return string(b[len(b)-40:])
	}
	return string(b)
}

// TestFramesAreWholeInstructions is the bug the browser client revealed.
//
// The browser's tunnel parses each WebSocket message independently and keeps no
// state between them, so a message that ends part-way through an instruction
// loses the remainder. A proxy forwarding whatever a Read happened to return
// therefore corrupts the stream as soon as an instruction spans a TCP boundary
// -- which on RDP is every screen update, because image data is the bulk of it.
//
// The payload below is far larger than the read buffer, so it CANNOT arrive in
// one read. It also contains ';' and ',' inside an element value, which is why
// scanning for a terminator instead of parsing does not work either.
func TestFramesAreWholeInstructions(t *testing.T) {
	big := strings.Repeat("iVBORw0KGgo;and,a comma", 12000) // ~264 KB, well over the buffer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	const bursts = 3
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r, w := NewReader(conn), NewWriter(conn)
		if _, err := r.ReadInstruction(); err != nil {
			return
		}
		_ = w.Write(Instruction{Opcode: "args", Args: []string{"hostname"}})
		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			if in.Opcode != "connect" {
				continue
			}
			_ = w.Write(Instruction{Opcode: "ready", Args: []string{"$c"}})
			for i := 0; i < bursts; i++ {
				_ = w.Write(Instruction{Opcode: "blob", Args: []string{"1", big}})
				_ = w.Write(Instruction{Opcode: "sync", Args: []string{"1000"}})
			}
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

	var blobs, syncs int
	deadline := time.Now().Add(5 * time.Second)
	// Waits on the sync, which follows each blob -- stopping on the last blob
	// would end the loop before its sync had been read.
	for syncs < bursts && time.Now().Before(deadline) {
		frame, err := s.ReadFrame()
		if err != nil {
			t.Fatalf("reading a frame: %v", err)
		}
		for _, in := range parseFrameStandalone(t, frame) {
			switch in.Opcode {
			case "blob":
				if len(in.Args) != 2 || in.Args[1] != big {
					t.Fatalf("blob %d arrived with %d bytes of payload, want %d",
						blobs, len(in.Args[1]), len(big))
				}
				blobs++
			case "sync":
				syncs++
			}
		}
	}
	if blobs != bursts || syncs != bursts {
		t.Fatalf("got %d blobs and %d syncs, want %d of each", blobs, syncs, bursts)
	}
}
