package rac

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An open remote-access channel asked nothing after it opened: signing out,
// a revoked session and a deactivated account ended every other way in and
// left the desktop open.

// idleGuacd completes the handshake and then holds the connection open, as a
// real session to an idle desktop does.
func idleGuacd(t *testing.T) string {
	t.Helper()
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
		r, w := NewReader(conn), NewWriter(conn)
		if _, err := r.ReadInstruction(); err != nil { // select
			return
		}
		_ = w.Write(Instruction{Opcode: "args", Args: []string{"VERSION_1_5_0", "hostname"}})
		for {
			in, err := r.ReadInstruction()
			if err != nil {
				return
			}
			if in.Opcode == "connect" {
				_ = w.Write(Instruction{Opcode: "ready", Args: []string{"$idle"}})
				break
			}
		}
		// Hold the session open; read until the proxy closes it.
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

// quietPeer is a browser that sends nothing and receives whatever it is sent.
type quietPeer struct{}

func (quietPeer) ReadMessage(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (quietPeer) WriteMessage(context.Context, []byte) error { return nil }

func dialIdle(t *testing.T) *Session {
	t.Helper()
	s, err := Dial(idleGuacd(t), Connection{Protocol: "rdp", Parameters: map[string]string{"hostname": "h"}},
		2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAChannelEndsWhenTheRecheckSaysNo(t *testing.T) {
	prev := RecheckInterval
	RecheckInterval = 20 * time.Millisecond
	t.Cleanup(func() { RecheckInterval = prev })

	guac := dialIdle(t)
	var asked atomic.Int32
	recheck := func(context.Context) (bool, string) {
		if asked.Add(1) < 3 {
			return true, ""
		}
		return false, "the sign-in session ended"
	}

	got := make(chan string, 1)
	go func() { got <- Proxy(context.Background(), quietPeer{}, guac, recheck) }()
	select {
	case reason := <-got:
		if reason != "the sign-in session ended" {
			t.Errorf("the channel ended for %q, want the recheck's reason", reason)
		}
		if n := asked.Load(); n != 3 {
			t.Errorf("asked %d times before ending, want 3", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the recheck said no and the channel stayed open")
	}
}

// Without a recheck the channel is held as before -- the harness and anything
// else that has no session to ask about are unchanged.
func TestWithoutARecheckTheChannelIsHeld(t *testing.T) {
	prev := RecheckInterval
	RecheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { RecheckInterval = prev })

	guac := dialIdle(t)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	ended := make(chan struct{})
	go func() {
		defer wg.Done()
		Proxy(ctx, quietPeer{}, guac, nil)
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("a channel with no recheck ended by itself")
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	_ = guac.Close()
	wg.Wait()
}
