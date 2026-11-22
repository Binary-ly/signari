package rac

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// The browser's tunnel closes a channel it has heard nothing on for fifteen seconds,
// and its ping is how a quiet channel stays open: the endpoint sends back an identical
// one (guacamole-common.js:15414). The proxy passed it on to guacd, so a channel lived
// only while guacd kept drawing, and the viewer's sign-in form, where guacd is waiting
// and has nothing to draw, was disconnected in the middle of somebody typing (8.28).

// scriptedPeer is a browser driven by the test.
type scriptedPeer struct{ in, out chan []byte }

func (p scriptedPeer) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case m := <-p.in:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p scriptedPeer) WriteMessage(_ context.Context, data []byte) error {
	p.out <- bytes.Clone(data)
	return nil
}

func TestThePingIsAnsweredHereAndNeverReachesGuacd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	received := make(chan Instruction, 16)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r, w := NewReader(conn), NewWriter(conn)
		_, _ = r.ReadInstruction() // select
		_ = w.Write(Instruction{Opcode: "args", Args: []string{"VERSION_1_5_0", "hostname"}})
		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			if in.Opcode == "connect" {
				break
			}
		}
		_ = w.Write(Instruction{Opcode: "ready", Args: []string{"$quiet"}})
		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			received <- in
		}
	}()
	guac, err := Dial(ln.Addr().String(), Connection{Protocol: "rdp", Parameters: map[string]string{"hostname": "h"}},
		2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guac.Close() })

	peer := scriptedPeer{in: make(chan []byte, 8), out: make(chan []byte, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Proxy(ctx, peer, guac, nil)
	answer := func() []byte {
		t.Helper()
		select {
		case m := <-peer.out:
			return m
		case <-time.After(2 * time.Second):
			t.Fatal("nothing came back to the browser")
			return nil
		}
	}
	if first := answer(); !strings.HasPrefix(string(first), "0.,") {
		t.Fatalf("the tunnel's identifier was not first: %q", first)
	}

	ping := []byte("0.,4.ping,13.1793449422841;")
	peer.in <- ping
	if got := answer(); !bytes.Equal(got, ping) {
		t.Errorf("the ping was answered with %q", got)
	}

	// Nothing else with an empty opcode is guacd's either, and nothing else is
	// answered; what follows them still gets through, in order.
	for _, m := range []string{"0.,4.mute;", "0.,4.ping;", "0.;", "3.nop;", "4.sync,13.1793449422842;"} {
		peer.in <- []byte(m)
	}
	var got []string
	for len(got) < 2 {
		select {
		case in := <-received:
			got = append(got, in.Opcode)
		case <-time.After(2 * time.Second):
			t.Fatalf("guacd received only %v", got)
		}
	}
	if got[0] != "nop" || got[1] != "sync" {
		t.Errorf("guacd received %v, want nop then sync", got)
	}
	select {
	case m := <-peer.out:
		t.Errorf("an internal instruction that is no ping was answered with %q", m)
	case <-time.After(50 * time.Millisecond):
	}
}

// An empty opcode is an opcode. Read by whether it was empty, the next element took
// its place, and the tunnel's identifier read back as an instruction named after it.
func TestAnEmptyOpcodeStaysEmpty(t *testing.T) {
	in, err := NewReader(strings.NewReader("0.,4.ping,2.17;")).ReadInstruction()
	if err != nil {
		t.Fatal(err)
	}
	if in.Opcode != "" || len(in.Args) != 2 || in.Args[0] != "ping" {
		t.Errorf("read as %+v", in)
	}
}
