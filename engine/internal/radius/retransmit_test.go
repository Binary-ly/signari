package radius

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

const rightPassword = "correct-horse-battery"

var (
	deviceAddr   = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	samePortless = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5001}
	strangerAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
)

type datagram struct {
	raw  []byte
	addr net.Addr
}

// scriptedConn is the socket, driven by the test: send returns when the read
// loop has taken a packet and settle when it has finished with it, so what the
// loop decided is known rather than a matter of timing.
type scriptedConn struct {
	*fakePacketConn
	in     chan datagram
	closed chan struct{}
	once   sync.Once
}

func (c *scriptedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case d := <-c.in:
		return copy(b, d.raw), d.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *scriptedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *scriptedConn) send(raw []byte, from net.Addr) { c.in <- datagram{raw, from} }

func (c *scriptedConn) settle() { c.send([]byte("nothing"), strangerAddr) }

func listen(t *testing.T, s *Server) *scriptedConn {
	t.Helper()
	c := &scriptedConn{fakePacketConn: newFakePacketConn(), in: make(chan datagram), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, c) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return c
}

// heldAuth keeps every password at the hasher until it is let go, except
// somebody called quick.
type heldAuth struct {
	mu     sync.Mutex
	calls  int
	letGo  chan struct{}
	inside chan struct{}
}

func newHeldAuth() *heldAuth {
	return &heldAuth{letGo: make(chan struct{}), inside: make(chan struct{}, 64)}
}

func (a *heldAuth) Authenticate(ctx context.Context, u, p string) error {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	a.inside <- struct{}{}
	if u != "quick" {
		select {
		case <-a.letGo:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if p == rightPassword {
		return nil
	}
	return fmt.Errorf("wrong password for %s", u)
}

func (a *heldAuth) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func heldServer(t *testing.T, a Authenticator, workers int) *Server {
	t.Helper()
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	s, err := New(Config{Clients: []Client{{Net: n, Secret: testSecret, Name: "test"}}, Workers: workers}, a,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func take(t *testing.T, c *scriptedConn) []byte {
	t.Helper()
	raw, err := c.take(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nothingMore(t *testing.T, c *scriptedConn) {
	t.Helper()
	if raw, err := c.take(50 * time.Millisecond); err == nil {
		t.Errorf("another reply, of %d bytes", len(raw))
	}
}

// A device that hears nothing sends the same packet, and means "I did not hear
// you". Hashed again, a wrong password counted twice towards a lockout.
func TestARetransmissionIsNotASecondQuestion(t *testing.T) {
	for name, password := range map[string]string{"an Accept": rightPassword, "a Reject": "not-the-password"} {
		t.Run(name, func(t *testing.T) {
			a := newHeldAuth()
			c := listen(t, heldServer(t, a, 2))
			req := buildRequest(t, testSecret, "alice", password, true)

			// While it is being answered, a device need only wait.
			c.send(req, deviceAddr)
			<-a.inside
			c.send(req, deviceAddr)
			c.send(req, deviceAddr)
			c.settle()
			close(a.letGo)
			first := take(t, c)
			nothingMore(t, c)

			// Once answered, the answer again, which it was signed for.
			c.send(req, deviceAddr)
			if again := take(t, c); !bytes.Equal(first, again) {
				t.Error("a retransmission was answered differently")
			}
			if n := a.count(); n != 1 {
				t.Errorf("the password was verified %d times", n)
			}

			// The same bytes from elsewhere are not this device's retransmission.
			c.send(req, samePortless)
			take(t, c)
			if n := a.count(); n != 2 {
				t.Errorf("another source was verified %d times in all, want 2", n)
			}
		})
	}
}

// A one-time code is spent by its first answer, so the second was refused and a
// person who had given the right code was told it was wrong.
func TestARetransmittedCodeIsAnsweredAsItWas(t *testing.T) {
	a := &codeAuth{}
	c := listen(t, newCodeServer(t, a))
	c.send(buildRequest(t, testSecret, "alice", rightPassword, true), deviceAddr)
	challenge, err := Decode(take(t, c))
	if err != nil {
		t.Fatal(err)
	}
	state, ok := challenge.Attr(AttrState)
	if !ok {
		t.Fatalf("answered %+v", challenge)
	}
	req := withSecondAttribute(t, buildRequest(t, testSecret, "alice", "123456", true), AttrState, state)
	c.send(req, deviceAddr)
	first := take(t, c)
	c.send(req, deviceAddr)
	if again := take(t, c); !bytes.Equal(first, again) {
		t.Error("a retransmission was answered differently")
	}
	if first[0] != CodeAccessAccept {
		t.Errorf("answered code %d", first[0])
	}
	if len(a.asked) != 1 {
		t.Errorf("the code was checked %d times", len(a.asked))
	}
}

// The listener used to answer one packet at a time, so everybody waited behind
// the slowest.
func TestASlowPasswordHoldsUpNobody(t *testing.T) {
	a := newHeldAuth()
	c := listen(t, heldServer(t, a, 2))
	c.send(buildRequest(t, testSecret, "slow", rightPassword, true), deviceAddr)
	<-a.inside
	c.send(buildRequest(t, testSecret, "quick", rightPassword, true), deviceAddr)
	if got := take(t, c); got[0] != CodeAccessAccept {
		t.Errorf("answered code %d", got[0])
	}
	close(a.letGo)
	take(t, c)
}

// Past the queue a packet is lost, as a datagram can be, and not remembered as
// though it were being answered: its retransmission would be swallowed.
func TestTheQueueIsAsLongAsItSays(t *testing.T) {
	a := newHeldAuth()
	s := heldServer(t, a, 1)
	s.queueLength = 1
	c := listen(t, s)
	dropped := buildRequest(t, testSecret, "alice", rightPassword, true)

	c.send(buildRequest(t, testSecret, "alice", rightPassword, true), deviceAddr)
	<-a.inside
	c.send(buildRequest(t, testSecret, "alice", rightPassword, true), deviceAddr)
	c.send(dropped, deviceAddr)
	c.settle()
	close(a.letGo)
	take(t, c)
	take(t, c)
	nothingMore(t, c)
	if n := a.count(); n != 2 {
		t.Errorf("%d were answered of a worker and a queue of one", n)
	}

	c.send(dropped, deviceAddr)
	take(t, c)
	if n := a.count(); n != 3 {
		t.Errorf("the retransmission of a dropped packet went unanswered: %d verified", n)
	}
}

// Only a device can fill the queue: anything else is turned away on the read
// loop, for the cost of an HMAC.
func TestAPacketNobodySignedTakesNoPlaceInTheQueue(t *testing.T) {
	a := newHeldAuth()
	s := heldServer(t, a, 1)
	s.queueLength = 1
	c := listen(t, s)

	c.send(buildRequest(t, testSecret, "alice", rightPassword, true), deviceAddr)
	<-a.inside
	for range 3 {
		c.send(buildRequest(t, "a-guessed-secret-of-sufficient-length", "alice", rightPassword, true), deviceAddr)
		c.send(buildRequest(t, testSecret, "alice", rightPassword, true), strangerAddr)
	}
	c.send(buildRequest(t, testSecret, "alice", rightPassword, true), deviceAddr)
	c.settle()
	close(a.letGo)
	take(t, c)
	take(t, c)
	if n := a.count(); n != 2 {
		t.Errorf("%d were verified, want the two a device signed", n)
	}
}

// A request's five seconds start when it arrives, so a queue cannot hold one
// until it is answered to nobody.
func TestAPacketThatWaitedTooLongIsNotAnswered(t *testing.T) {
	a := &fakeAuth{}
	s, _ := newServer(t)
	s.auth = a
	r, ok := s.admit(deviceAddr, buildRequest(t, testSecret, "alice", rightPassword, true))
	if !ok {
		t.Fatal("not believed")
	}
	r.arrived = time.Now().Add(-AuthTimeout - time.Millisecond)
	conn := newFakePacketConn()
	s.answer(context.Background(), conn, r)
	if a.calls != 0 {
		t.Errorf("verified %d times for nobody", a.calls)
	}
	if raw, err := conn.take(10 * time.Millisecond); err == nil {
		t.Errorf("answered %d bytes", len(raw))
	}

	r.arrived = time.Now().Add(-AuthTimeout + time.Second)
	s.answer(context.Background(), conn, r)
	if a.calls != 1 || a.left > time.Second {
		t.Errorf("%d calls, with %v left: the queue did not spend the deadline", a.calls, a.left)
	}
}

func TestARequestIsRememberedForTheWindow(t *testing.T) {
	seen := newSeenRequests()
	d := digestOf(deviceAddr, []byte("a request"))
	if d == digestOf(samePortless, []byte("a request")) || d == digestOf(deviceAddr, []byte("another")) {
		t.Fatal("two questions have one digest")
	}
	t0 := time.Now()
	if _, asked := seen.arrive(d, t0); asked {
		t.Error("asked before it was")
	}
	if reply, asked := seen.arrive(d, t0.Add(time.Second)); !asked || reply != nil {
		t.Errorf("in flight, it answered %q, %v", reply, asked)
	}
	seen.answered(d, []byte("the answer"))
	if reply, asked := seen.arrive(d, t0.Add(retransmitWindow-time.Second)); !asked || string(reply) != "the answer" {
		t.Errorf("answered, it answered %q, %v", reply, asked)
	}
	if _, asked := seen.arrive(d, t0.Add(retransmitWindow)); asked {
		t.Error("remembered past the window")
	}
	for i := range maxSeenRequests + 10 {
		seen.arrive(digestOf(deviceAddr, binary.BigEndian.AppendUint32(nil, uint32(i))), t0)
	}
	if n := len(seen.byKey); n > maxSeenRequests {
		t.Errorf("%d remembered, past the limit of %d", n, maxSeenRequests)
	}
	if _, asked := seen.arrive(d, t0.Add(retransmitWindow)); asked {
		t.Error("the oldest was not the one forgotten")
	}
}

// Every packet of a conversation sent twice. The Accept closes the session, so
// the last one's retransmission used to be refused: an access point that missed
// an Accept was told Reject.
func TestARetransmissionDoesNotDerailAConversation(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})
	c := listen(t, srv)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	sup := &supplicant{t: t, secret: []byte("a-secret-of-sufficient-length"),
		cert: pki.issue(t, "alice@corp.test", true, 2000), pool: pki.pool, identity: "anonymous"}
	sup.send = func(req []byte) ([]byte, error) {
		c.send(req, addr)
		reply, err := c.take(5 * time.Second)
		if err != nil {
			return nil, err
		}
		c.send(req, addr)
		again, err := c.take(5 * time.Second)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(reply, again) {
			t.Errorf("a retransmission in round %d was answered differently", sup.rounds)
		}
		return reply, nil
	}
	code, _, err := sup.run()
	if err != nil || code != CodeAccessAccept {
		t.Fatalf("answered %d, %v", code, err)
	}
}

// Two different packets for one conversation at once are not a retransmission
// and not a conversation. Neither waits, or a device could hold every worker on
// one session, and the second does not touch the handshake.
func TestAConversationTakesOnePacketAtATime(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})
	sess, _, err := srv.startEAPTLS(2)
	if err != nil {
		t.Fatal(err)
	}
	srv.sessions.put(sess)
	sess.busy.Lock()
	defer sess.busy.Unlock()

	eap := (&EAPPacket{Code: EAPResponse, Identifier: 2, Type: EAPTypeTLS, Data: (&EAPTLSFrame{}).Encode()}).Encode()
	req, err := buildTestRequest([]byte("a-secret-of-sufficient-length"),
		append(EAPAttributes(eap), Attribute{Type: AttrState, Value: []byte(sess.state)}))
	if err != nil {
		t.Fatal(err)
	}
	conn := newFakePacketConn()
	done := make(chan struct{})
	go func() {
		srv.handle(context.Background(), conn, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a worker waited on a conversation another was in")
	}
	if raw, err := conn.take(10 * time.Millisecond); err == nil {
		t.Errorf("answered %d bytes", len(raw))
	}
}

// A packet nobody answered is not one to wait for. Remembered as being answered,
// the device's every retransmission would be swallowed for the whole window.
func TestAPacketLeftUnansweredCanBeAskedAgain(t *testing.T) {
	pki := newTestPKI(t)
	srv := eapTestServer(t, pki, &certAuth{})
	sess, _, err := srv.startEAPTLS(2)
	if err != nil {
		t.Fatal(err)
	}
	srv.sessions.put(sess)
	sess.busy.Lock()

	// No flags at all, which is refused at once when it gets through.
	eap := (&EAPPacket{Code: EAPResponse, Identifier: 2, Type: EAPTypeTLS}).Encode()
	req, err := buildTestRequest([]byte("a-secret-of-sufficient-length"),
		append(EAPAttributes(eap), Attribute{Type: AttrState, Value: []byte(sess.state)}))
	if err != nil {
		t.Fatal(err)
	}
	c := listen(t, srv)
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}
	c.send(req, addr)
	c.settle()
	nothingMore(t, c)
	sess.busy.Unlock()

	// Forgetting is the worker's last act, so as a device does, it asks again.
	for range 100 {
		c.send(req, addr)
		if _, err := c.take(20 * time.Millisecond); err == nil {
			return
		}
	}
	t.Error("a request nobody answered was never answered")
}

// A name that is not known, an expired one and a full table are each the whole
// handshake, and never a failed one.
func TestAResumptionIsForgotten(t *testing.T) {
	r := newEAPResumptions()
	if s, err := r.unwrap([]byte("nobody"), tls.ConnectionState{}); s != nil || err != nil {
		t.Errorf("a name never given answered %v, %v", s, err)
	}
	r.byName["old"] = eapResumption{state: []byte("x"), expires: time.Now().Add(-time.Second)}
	if s, err := r.unwrap([]byte("old"), tls.ConnectionState{}); s != nil || err != nil {
		t.Errorf("an expired name answered %v, %v", s, err)
	}
	if len(r.byName) != 0 {
		t.Error("an expired name was kept")
	}
	state := (&tls.SessionState{})
	for range eapMaxResumptions + 3 {
		if _, err := r.wrap(tls.ConnectionState{}, state); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r.byName); n != eapMaxResumptions {
		t.Errorf("%d kept, of a limit of %d", n, eapMaxResumptions)
	}
}

// A sealed ticket carried the chain, and one made under a Config of its own
// could not be read at all. Skipping the chain must not skip the question:
// somebody refused since is refused on resumption.
func TestASupplicantResumesAndIsAskedAboutAgain(t *testing.T) {
	for name, version := range map[string]uint16{"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13} {
		t.Run(name, func(t *testing.T) {
			pki := newTestPKI(t)
			auth := &certAuth{}
			srv := eapTestServer(t, pki, auth)
			cert := pki.issue(t, "alice@corp.test", true, 3000)
			cache := tls.NewLRUClientSessionCache(4)
			run := func() (*supplicant, byte) {
				t.Helper()
				sup := &supplicant{t: t, server: srv, conn: newFakePacketConn(),
					secret: []byte("a-secret-of-sufficient-length"), cert: cert, pool: pki.pool, identity: "anonymous",
					cache: cache, maxVersion: version}
				code, _, err := sup.run()
				if err != nil {
					t.Fatal(err)
				}
				return sup, code
			}

			full, code := run()
			if code != CodeAccessAccept || full.resumed {
				t.Fatalf("the first answered %d, resumed %v", code, full.resumed)
			}
			short, code := run()
			if code != CodeAccessAccept {
				t.Fatalf("the resumption answered %d", code)
			}
			if !short.resumed {
				t.Fatal("the second conversation did the whole handshake again")
			}
			if short.rounds >= full.rounds {
				t.Errorf("resuming took %d rounds, the whole handshake %d", short.rounds, full.rounds)
			}
			t.Logf("%d rounds, then %d resuming", full.rounds, short.rounds)

			auth.refuse = true
			refused, code := run()
			if !refused.resumed {
				t.Fatal("not resumed, so this says nothing about a resumption")
			}
			if code != CodeAccessReject {
				t.Errorf("a person refused since resumed and was answered %d", code)
			}
		})
	}
}
