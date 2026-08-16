package rac

import (
	"context"
	"errors"
	"io"
)

// Copying between a browser and guacd.
//
// This lives beside the protocol rather than in the HTTP layer because what it
// does is a protocol obligation, not a transport detail: the browser's tunnel
// parses each message on its own, so the boundary between messages is part of
// the protocol contract. Putting it here also means the exact code that runs in
// production is the code a harness can drive without an HTTP server, a database
// or a signed-in user.

// Peer is the browser side of the proxy.
//
// An interface rather than a *websocket.Conn so this package does not depend on
// a WebSocket library to express something that is not about WebSockets.
type Peer interface {
	// ReadMessage returns one complete client message.
	//
	// The error should report a normal close distinguishably; see NormalClose.
	ReadMessage(ctx context.Context) ([]byte, error)
	// WriteMessage sends one message, which must contain whole instructions.
	WriteMessage(ctx context.Context, data []byte) error
}

// NormalClose is the error a Peer returns when the user closed the session
// deliberately, so it can be reported as that rather than as a failure.
var NormalClose = errors.New("closed by the user")

// Proxy copies between a browser and guacd until either stops, and returns why.
//
// The reason is returned rather than logged because it is recorded against the
// session: "the session closed" with no reason tells an operator nothing about
// whether the user left or the host died.
func Proxy(ctx context.Context, peer Peer, guac *Session) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan string, 2)

	// The tunnel identifier, before anything else.
	//
	// The browser's tunnel treats the first instruction as the signal that it is
	// open, and adopts the identifier when that instruction carries the internal
	// (empty) opcode. This is what the reference Java tunnel sends, and sending
	// it means the client's own connection id matches the one recorded against
	// the session -- so an entry in the audit trail can be tied to what the user
	// was actually looking at.
	if err := peer.WriteMessage(ctx, []byte(Instruction{Args: []string{guac.ID}}.String())); err != nil {
		return reasonFor(err, "client went away before the session started")
	}

	// Browser → guacd. The browser's tunnel emits one complete instruction per
	// message, so there is nothing to reframe in this direction.
	go func() {
		for {
			data, err := peer.ReadMessage(ctx)
			if err != nil {
				done <- reasonFor(err, "client disconnected")
				return
			}
			if _, err := guac.WriteRaw(data); err != nil {
				done <- "guacd stopped reading"
				return
			}
		}
	}()

	// guacd → browser, one message per batch of WHOLE instructions.
	go func() {
		for {
			frame, err := guac.ReadFrame()
			if len(frame) > 0 {
				if werr := peer.WriteMessage(ctx, frame); werr != nil {
					done <- reasonFor(werr, "client stopped reading")
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					done <- "remote session ended"
					return
				}
				done <- "guacd disconnected"
				return
			}
		}
	}()

	// The first side to finish ends the session; the other goroutine unblocks
	// when its connection closes, which the caller's Close guarantees.
	return <-done
}

func reasonFor(err error, fallback string) string {
	if errors.Is(err, NormalClose) {
		return "closed by the user"
	}
	return fallback
}
