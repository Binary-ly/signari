package radius

import (
	"crypto/sha256"
	"net"
	"slices"
	"sync"
	"time"
)

// A device that hears nothing sends the same packet again, and what it means is
// "I did not hear you", not a second question. Answering it as one spent a
// second hash, counted a wrong password as two failures towards a lockout, spent
// a one-time code on the first answer and refused the second, and, for the last
// packet of an EAP conversation, whose session the Accept had closed, turned an
// Accept the access point missed into a Reject.
//
// So a request is remembered for as long as a device goes on retrying it, and
// its answer with it. This is not a decision kept for a later question, which
// ADR-007 rules out: only the same bytes from the same source find it, which is
// the question already answered, and a packet is believed before it is looked up,
// so a device disabled since is answered nothing.

const (
	// retransmitWindow is how long a request is remembered: five retries, five
	// seconds apart, and some to spare.
	retransmitWindow = 30 * time.Second
	// maxSeenRequests bounds the memory, and past it the oldest are forgotten
	// early, which costs a repeat of the work and nothing else. It holds the
	// window at 250 requests a second.
	maxSeenRequests = 8192
)

// requestDigest names one datagram from one source: the Identifier and Request
// Authenticator a retransmission keeps, and everything else, so that an answer
// is only ever repeated to the question it was the answer to. A digest rather
// than the packet, which would keep passwords here.
type requestDigest [sha256.Size]byte

func digestOf(addr net.Addr, raw []byte) requestDigest {
	h := sha256.New()
	h.Write([]byte(addr.String()))
	h.Write([]byte{0})
	h.Write(raw)
	return requestDigest(h.Sum(nil))
}

type seenRequest struct {
	at    time.Time
	reply []byte // nil until it has been answered
}

// seenRequests remembers in arrival order: slots is a ring, so the oldest is
// overwritten and there is nothing to sweep.
type seenRequests struct {
	mu    sync.Mutex
	byKey map[requestDigest]*seenRequest
	slots []requestDigest
	next  int
}

func newSeenRequests() *seenRequests {
	return &seenRequests{byKey: map[requestDigest]*seenRequest{}, slots: make([]requestDigest, maxSeenRequests)}
}

// arrive records a request. asked says it has been seen in the window, and
// reply is its answer if it has one yet.
func (s *seenRequests) arrive(d requestDigest, now time.Time) (reply []byte, asked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byKey[d]; ok && now.Sub(e.at) < retransmitWindow {
		return e.reply, true
	}
	delete(s.byKey, s.slots[s.next])
	s.slots[s.next] = d
	s.next = (s.next + 1) % len(s.slots)
	s.byKey[d] = &seenRequest{at: now}
	return nil, false
}

func (s *seenRequests) answered(d requestDigest, reply []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byKey[d]; ok {
		e.reply = reply
	}
}

func (s *seenRequests) forget(d requestDigest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byKey, d)
}

// queuedRequest waits for a worker.
type queuedRequest struct {
	request
	digest requestDigest
}

// rememberedReply is the socket as a worker sees it: what is written is kept for
// the retransmission of what it answers, on every path that can answer, without
// any of them knowing.
type rememberedReply struct {
	net.PacketConn
	seen     *seenRequests
	digest   requestDigest
	answered bool
}

func (r *rememberedReply) WriteTo(b []byte, addr net.Addr) (int, error) {
	r.answered = true
	r.seen.answered(r.digest, slices.Clone(b))
	return r.PacketConn.WriteTo(b, addr)
}
