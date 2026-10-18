package httpapi

import (
	"net/http"
	"time"
)

// Timeouts for the public listener.
//
// It had a header timeout and an idle timeout and nothing else. A client that
// sent its headers promptly and then its body a byte a minute held a goroutine
// and a connection for as long as it liked, and a few thousand of them held
// the server. Every request here is small: forms, JSON and redirects, each
// bounded by a MaxBytesReader. Thirty seconds to read one and a minute to
// answer one is generous for every route.
//
// The one connection that is meant to stay open, the remote-access tunnel, is
// a hijacked WebSocket, and net/http clears both deadlines when a connection is
// hijacked (hijackLocked, src/net/http/server.go:325 in go1.26.9). The
// interface comment on http.Hijacker still says the deadlines "may" remain, so
// TestAHijackedTunnelOutlivesTheRequestTimeouts holds the behaviour this relies
// on rather than the comment.
const (
	PublicReadHeaderTimeout = 10 * time.Second
	PublicReadTimeout       = 30 * time.Second
	PublicWriteTimeout      = 60 * time.Second
	PublicIdleTimeout       = 120 * time.Second
)

// NewPublicServer is the public listener with those timeouts.
func NewPublicServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: h,
		// A slow-header attack costs an attacker nothing and holds a connection
		// open indefinitely without this.
		ReadHeaderTimeout: PublicReadHeaderTimeout,
		ReadTimeout:       PublicReadTimeout,
		WriteTimeout:      PublicWriteTimeout,
		IdleTimeout:       PublicIdleTimeout,
	}
}
