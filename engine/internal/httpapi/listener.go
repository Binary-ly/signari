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
// the server. Every request here is small: forms, JSON and redirects. JSON is
// bounded where it is decoded, a pushed authorization request by maxPARBody and
// the token family by formCapped; other form bodies, sign-in pages and SAML posts
// among them, by net/http's own ceiling on a urlencoded form (10 MB,
// src/net/http/request.go:1280 in go1.26.6). This said every request was bounded
// by a MaxBytesReader, and the PAR cap was declared and read by nothing. Thirty
// seconds to read one and a minute to answer one is generous for every route.
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

// maxTokenFormBody bounds a form at the token family, which holds a few short
// parameters and at most a client assertion. maxPARBody's size, since that carries
// everything an authorization does.
const maxTokenFormBody = maxPARBody

// formCapped bounds a handler's form, before it reads one. These are the endpoints a
// stranger can post to before anything has checked who they are, and net/http would
// read ten megabytes of form for each.
func formCapped(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxTokenFormBody)
		next(w, r)
	}
}

// AllowH2C lets the listener speak HTTP/2 with no TLS, for a proxy in front of it
// that has already ended TLS and would rather keep one connection than many. With
// prior knowledge only: net/http does not honour the `Upgrade: h2c` a browser could
// be made to send through a proxy that passes it on, which is the known way of
// smuggling a request past one.
func AllowH2C(srv *http.Server) {
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetHTTP1(true)
	srv.Protocols.SetHTTP2(true)
	srv.Protocols.SetUnencryptedHTTP2(true)
}

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
