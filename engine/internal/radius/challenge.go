package radius

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net"
	"sync"
	"time"
)

// A code for RADIUS PAP (7.05). A client that can show a prompt is answered a
// right password with Access-Challenge, and the person's code comes back in the
// next request where the password was, with the State this sent. One that
// cannot prompt sends `password;123456`, which the authenticator reads.

// ErrSecondFactor is a right password from somebody who must also give a code.
var ErrSecondFactor = errors.New("radius: a second factor is needed")

// CodeVerifier is an Authenticator that can check a code. Without one a password
// that needs a code is refused, as nothing could finish it.
type CodeVerifier interface {
	VerifyCode(ctx context.Context, username, code string) error
}

const (
	// codeLife is how long a person has to read their authenticator.
	codeLife = 2 * time.Minute
	// maxPendingCodes bounds what right passwords can make this hold. Each one
	// took a correct password and a hash, so it is a ceiling and not a defence.
	maxPendingCodes = 4096
	// codePrompt is what the device shows.
	codePrompt = "Enter your authentication code"
)

// pendingCode is a password proved, waiting for its code: one use, by the device
// and for the person it was proved to. A state is all that stands between a
// device and skipping the password, so it is unguessable and held here rather
// than sealed and handed out, and a second node does not recognise it: a client
// balanced between nodes starts again, and `password;code` works anywhere.
type pendingCode struct {
	username string
	client   string
	expires  time.Time
}

type pendingCodes struct {
	mu      sync.Mutex
	waiting map[string]pendingCode
}

func (c *pendingCodes) add(state string, p pendingCode, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.waiting == nil {
		c.waiting = map[string]pendingCode{}
	}
	for k, v := range c.waiting {
		if now.After(v.expires) {
			delete(c.waiting, k)
		}
	}
	if len(c.waiting) >= maxPendingCodes {
		return false
	}
	c.waiting[state] = p
	return true
}

// take spends a state: found or not, it cannot be asked about twice.
func (c *pendingCodes) take(state string, now time.Time) (pendingCode, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.waiting[state]
	delete(c.waiting, state)
	return p, ok && !now.After(p.expires)
}

// askForCode answers a right password with Access-Challenge, or refuses when
// nothing could carry on from one.
func (s *Server) askForCode(conn net.PacketConn, addr net.Addr, p *Packet, secret []byte,
	client Client, username string) {

	if _, ok := s.auth.(CodeVerifier); !ok {
		s.reject(conn, addr, p, secret, "a code is needed and cannot be checked")
		return
	}
	state := make([]byte, 16)
	if _, err := rand.Read(state); err != nil {
		s.reject(conn, addr, p, secret, "no random state")
		return
	}
	if !s.codes.add(string(state), pendingCode{username: username, client: client.Name,
		expires: time.Now().Add(codeLife)}, time.Now()) {
		s.log.Warn("too many RADIUS sign-ins waiting for a code", "client", client.Name)
		s.reject(conn, addr, p, secret, "too many waiting")
		return
	}
	out, err := Response(p, CodeAccessChallenge, secret, []Attribute{
		{Type: AttrState, Value: state},
		{Type: AttrReplyMessage, Value: []byte(codePrompt)},
	})
	if err != nil {
		s.log.Error("building a RADIUS challenge", "err", err)
		return
	}
	_, _ = conn.WriteTo(out, addr)
}

// answerChallenge takes the code a person answered with. The device and the name
// have to be the ones the password was proved to: a state alone proves nothing
// about who is holding it.
func (s *Server) answerChallenge(ctx context.Context, conn net.PacketConn, addr net.Addr, p *Packet,
	secret []byte, client Client, state, username, code string) {

	pending, ok := s.codes.take(state, time.Now())
	verifier, can := s.auth.(CodeVerifier)
	if !ok || !can || pending.client != client.Name ||
		subtle.ConstantTimeCompare([]byte(pending.username), []byte(username)) != 1 {
		s.log.Info("RADIUS challenge answer refused", "client", client.Name)
		s.reject(conn, addr, p, secret, "no such challenge")
		return
	}
	actx, cancel := context.WithTimeout(ctx, AuthTimeout)
	err := verifier.VerifyCode(actx, username, code)
	cancel()
	if err != nil {
		s.log.Info("RADIUS code refused", "client", client.Name)
		s.reject(conn, addr, p, secret, "authentication failed")
		return
	}
	s.accept(ctx, conn, addr, p, secret, client, username)
}
