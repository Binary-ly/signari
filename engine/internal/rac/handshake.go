package rac

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// The guacd handshake, and the decision it hides.
//
// The exchange itself is four instructions:
//
//	→ select    which protocol (rdp, vnc, ssh)
//	← args      guacd lists the parameter names it wants, IN ORDER
//	→ size, audio, video, image, connect
//	← ready     with a connection id
//
// The `connect` instruction supplies values POSITIONALLY, matching the order
// guacd sent in `args`. That ordering is the whole trap: guacd's parameter list
// differs between protocols and between versions, so an implementation that
// hardcodes the order sends the password where the hostname belongs the day
// somebody upgrades. Values are therefore looked up by NAME from what guacd
// asked for, and a parameter guacd does not want is not sent at all.
//
// # Where the security lives
//
// guacd has no concept of a user. It connects to whatever host it is told to,
// with whatever credentials it is given. Everything that makes this safe --
// which person, which host, whether policy allows it, what is recorded --
// happens before Connect is called, and none of it can be delegated to guacd.

// Connection is one thing a user may reach.
type Connection struct {
	// Protocol is rdp, vnc or ssh.
	Protocol string
	// Parameters are guacd's connection parameters, by name: hostname, port,
	// username, password, and so on.
	//
	// A map rather than a struct because the set differs per protocol and per
	// version of guacd, and a struct would have to be revised for each -- while
	// silently dropping anything it did not know about.
	Parameters map[string]string

	// Width, Height and DPI describe the client's display.
	Width  int
	Height int
	DPI    int
}

// Session is a live connection to guacd.
type Session struct {
	conn net.Conn
	r    *Reader
	w    *Writer

	// ID is guacd's identifier for the connection, from its `ready`.
	ID string

	// pending holds a read error deferred while a whole batch was delivered.
	pending error
}

// Dial opens a connection to guacd and performs the handshake.
//
// The address is guacd's TCP listener -- typically 127.0.0.1:4822, and it
// should not be reachable from anywhere else: guacd will connect wherever it is
// asked, so anything that can talk to it can reach every host it can.
func Dial(addr string, c Connection, timeout time.Duration) (*Session, error) {
	if c.Protocol == "" {
		return nil, fmt.Errorf("no protocol given")
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to guacd at %s: %w", addr, err)
	}
	s := &Session{conn: conn, r: NewReader(conn), w: NewWriter(conn)}

	if err := s.handshake(c, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) handshake(c Connection, timeout time.Duration) error {
	// The handshake is bounded. Everything after it is interactive and has no
	// deadline, but a guacd that never answers `args` must not hold a browser
	// connection open indefinitely.
	if err := s.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()

	if err := s.w.Write(Instruction{Opcode: "select", Args: []string{c.Protocol}}); err != nil {
		return fmt.Errorf("sending select: %w", err)
	}

	args, err := s.r.ReadInstruction()
	if err != nil {
		return fmt.Errorf("reading the parameter list: %w", err)
	}
	if args.Opcode != "args" {
		return fmt.Errorf("expected `args` from guacd, got %q -- protocol %q may "+
			"not be supported by this guacd", args.Opcode, c.Protocol)
	}

	width, height, dpi := c.Width, c.Height, c.DPI
	if width <= 0 {
		width = 1024
	}
	if height <= 0 {
		height = 768
	}
	if dpi <= 0 {
		dpi = 96
	}

	if err := s.w.Write(Instruction{Opcode: "size", Args: []string{
		itoa(width), itoa(height), itoa(dpi)}}); err != nil {
		return err
	}
	// Empty capability lists: this proxy forwards whatever guacd sends and does
	// not transcode, so claiming support for a codec would be claiming something
	// about the browser that this side cannot know.
	for _, op := range []string{"audio", "video", "image"} {
		if err := s.w.Write(Instruction{Opcode: op}); err != nil {
			return err
		}
	}

	// Positional, in the order guacd asked. Values by NAME, so a parameter list
	// that changes between versions cannot shift a password into the hostname.
	values := make([]string, 0, len(args.Args))
	var unknown []string
	for _, name := range args.Args {
		if v, ok := c.Parameters[name]; ok {
			values = append(values, v)
			continue
		}
		values = append(values, "")
	}
	// A parameter supplied that guacd never asked for is a configuration error
	// worth reporting: it is silently ignored otherwise, and the operator is
	// left wondering why their setting had no effect.
	asked := make(map[string]bool, len(args.Args))
	for _, name := range args.Args {
		asked[name] = true
	}
	for name := range c.Parameters {
		if !asked[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("guacd does not accept these parameters for %s: %s. "+
			"They would have been ignored, which is worse than being refused",
			c.Protocol, strings.Join(unknown, ", "))
	}

	if err := s.w.Write(Instruction{Opcode: "connect", Args: values}); err != nil {
		return fmt.Errorf("sending connect: %w", err)
	}

	ready, err := s.r.ReadInstruction()
	if err != nil {
		return fmt.Errorf("waiting for guacd to be ready: %w", err)
	}
	if ready.Opcode == "error" {
		return fmt.Errorf("guacd refused the connection: %s", strings.Join(ready.Args, " "))
	}
	if ready.Opcode != "ready" || len(ready.Args) == 0 {
		return fmt.Errorf("expected `ready` from guacd, got %q", ready.Opcode)
	}
	s.ID = ready.Args[0]
	return nil
}

// Read returns the next instruction from guacd.
func (s *Session) Read() (Instruction, error) { return s.r.ReadInstruction() }

// Write sends an instruction to guacd.
func (s *Session) Write(i Instruction) error { return s.w.Write(i) }

// Close ends the session.
//
// A `disconnect` is sent first so guacd tears down the remote session rather
// than waiting for a timeout -- which on RDP can leave a logged-in desktop
// running for minutes after the browser has gone.
func (s *Session) Close() error {
	_ = s.w.Write(Instruction{Opcode: "disconnect"})
	return s.conn.Close()
}

// frameSoftLimit is when ReadFrame stops adding more instructions to a batch.
//
// Soft, because a single instruction is never split to respect it: one image
// can exceed this on its own and must still cross in one piece.
const frameSoftLimit = 64 << 10

// ReadFrame returns one or more COMPLETE instructions from guacd.
//
// # Why this is not io.Copy
//
// The browser's tunnel parses each WebSocket message on its own and keeps no
// state between them: it walks the message start to end and, if a message ends
// part-way through an instruction, the remainder is not held over to be joined
// with the next one. It is discarded, and the tunnel reports a broken stream.
//
// So a proxy that forwards whatever a Read happened to return -- an arbitrary
// TCP boundary -- works right up until an instruction is larger than the buffer
// or a packet lands mid-instruction. On RDP that is every screen update, since
// image data is the bulk of the traffic. The failure looks like a corrupt
// display rather than a framing fault, which is what makes it expensive.
//
// Instructions are batched while they are already in hand, so a busy stream
// costs one frame per burst rather than one per instruction, but the batch is
// only ever cut at a boundary.
//
// Reading through the handshake's buffer is also load-bearing: guacd sends
// `ready` and the session's first instructions in the same packet, so those
// instructions are already off the socket and in that buffer by the time the
// proxy starts. Reading the bare connection instead skips them, and the symptom
// -- a session that connects successfully and displays nothing -- looks like a
// rendering fault at the far end.
func (s *Session) ReadFrame() ([]byte, error) {
	if s.pending != nil {
		return nil, s.pending
	}
	frame, err := s.r.ReadRaw()
	if err != nil {
		return nil, err
	}
	// Whatever else has already arrived, without waiting for more.
	for len(frame) < frameSoftLimit && s.r.Buffered() > 0 {
		next, err := s.r.ReadRaw()
		if err != nil {
			// The batch so far is whole and worth delivering; the error will
			// come back on the next call, when there is nothing to lose.
			s.pending = err
			break
		}
		frame = append(frame, next...)
	}
	return frame, nil
}

// WriteRaw sends bytes from the browser to guacd unchanged.
//
// The browser's tunnel emits one complete instruction per message, so there is
// nothing to reframe in this direction.
func (s *Session) WriteRaw(p []byte) (int, error) { return s.conn.Write(p) }

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
