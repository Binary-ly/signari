// Package httpapi serves the engine's public protocol endpoints.
package httpapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/sulimanbenhalim/idp/engine/internal/keys"
	"github.com/sulimanbenhalim/idp/engine/internal/oidc"
)

// Server holds the public endpoints. Everything it serves is derived from a live
// key set, so metadata cannot drift from what the server can actually do.
type Server struct {
	cfg  oidc.Config
	log  *slog.Logger
	jwks *bucket
}

func New(cfg oidc.Config, log *slog.Logger) (*Server, error) {
	// Fail at construction if the metadata is not renderable, rather than serving
	// 500s from a discovery endpoint that relying parties poll.
	if _, err := oidc.Build(cfg); err != nil {
		return nil, err
	}
	return &Server{
		cfg:  cfg,
		log:  log,
		jwks: newBucket(20, 40), // 20 req/s sustained, burst 40
	}, nil
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+oidc.PathDiscovery, s.handleDiscovery)
	mux.HandleFunc("GET "+oidc.PathJWKS, s.handleJWKS)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	md, err := oidc.Build(s.cfg)
	if err != nil {
		s.log.Error("building discovery metadata", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "metadata unavailable")
		return
	}
	// Discovery is public, stable, and polled. Let it be cached, but not so long
	// that adding a signing algorithm takes a day to become visible.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, md)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// A relying party that refreshes its JWKS whenever it sees an unknown `kid`
	// is a free DoS amplifier: send tokens with random kids and it hammers this
	// endpoint. Cheap to fix, rarely discussed, so it is fixed here.
	if !s.jwks.allow() {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many key set requests")
		return
	}

	body, err := s.cfg.Keys.MarshalJWKS()
	if err != nil {
		s.log.Error("marshalling jwks", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "key set unavailable")
		return
	}
	// Well-behaved clients converge within max-age. Never assume they honour it:
	// the rotation dwell in internal/keys is sized for clients that do not.
	w.Header().Set("Cache-Control",
		fmt.Sprintf("public, max-age=%d", int(keys.JWKSMaxAge.Seconds())))
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"algs":   s.cfg.Keys.Algorithms(),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError uses the OAuth 2.0 error shape everywhere, including on endpoints
// that are not strictly OAuth, so clients and operators see one format.
func writeError(w http.ResponseWriter, code int, err, desc string) {
	writeJSON(w, code, map[string]string{
		"error":             err,
		"error_description": desc,
	})
}

// bucket is a token bucket. Global rather than per-IP on purpose: the JWKS
// endpoint is unauthenticated and typically sits behind a proxy, so per-IP
// limiting mostly measures the proxy.
type bucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func newBucket(ratePerSec, capacity float64) *bucket {
	return &bucket{tokens: capacity, capacity: capacity, rate: ratePerSec, last: time.Now()}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
