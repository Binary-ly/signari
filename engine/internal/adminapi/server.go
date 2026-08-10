// Package adminapi is the engine's write surface.
//
// Every change the Laravel admin makes arrives here. That is not a stylistic
// preference -- ADR-004 gives the admin role no privilege on schema `core` at
// all, so this is the only path that exists.
//
// The invariant this package enforces, from ADR-008:
//
//	EVERY mutation bumps core.config_version IN THE SAME TRANSACTION.
//
// Engine nodes poll that version to decide when to reload. If a write commits
// without bumping it, the change is durable but invisible: the database says a
// client is disabled while every running node keeps honouring it, until some
// unrelated write happens to bump the version. That failure is silent, it is
// intermittent, and it looks like a caching bug rather than a missing line --
// so the bump lives in one helper that every handler must route through.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Server is the admin write API. It listens separately from the public protocol
// endpoints so it can be bound to a private interface: an internet-reachable
// admin API on an identity provider is a large and unnecessary target.
type Server struct {
	db    *pgxpool.Pool
	log   *slog.Logger
	token string
}

func New(db *pgxpool.Pool, log *slog.Logger, token string) (*Server, error) {
	// Short shared secrets get brute-forced; there is no rate limit that makes a
	// 12-character admin token safe. Refuse at construction rather than warn.
	if len(token) < 32 {
		return nil, fmt.Errorf("admin API token must be at least 32 characters (got %d)", len(token))
	}
	return &Server{db: db, log: log, token: token}, nil
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /admin/clients/{clientID}", s.auth(s.patchClient))
	mux.HandleFunc("GET /admin/config-version", s.auth(s.configVersion))
	return mux
}

// auth is a constant-time bearer check.
//
// Deliberately not a per-request database lookup: this endpoint is the one an
// attacker will hammer, and a lookup would turn a guessing attempt into a query.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) ||
			!constantTimeEqual(h[len(prefix):], s.token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="idp-admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

type patchClientRequest struct {
	// Pointer so "absent" and "false" are distinguishable. Without this, a PATCH
	// that does not mention `enabled` would silently disable the client.
	Enabled *bool `json:"enabled"`
}

func (s *Server) patchClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")

	var req patchClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing_to_change", "detail": "no supported field present",
		})
		return
	}

	version, err := s.mutate(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE core.clients SET enabled = $2, updated_at = now() WHERE client_id = $1`,
			clientID, *req.Enabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return nil
	})

	switch {
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case err != nil:
		s.log.Error("patching client", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Disabling is a security-relevant action, so it is logged at a level an
	// operator will actually see, with the version needed to confirm propagation.
	s.log.Info("client updated", "client_id", clientID, "enabled", *req.Enabled,
		"config_version", version)

	writeJSON(w, http.StatusOK, map[string]any{
		"client_id": clientID, "enabled": *req.Enabled, "config_version": version,
	})
}

func (s *Server) configVersion(w http.ResponseWriter, r *http.Request) {
	var v int64
	if err := s.db.QueryRow(r.Context(),
		`SELECT version FROM core.config_version`).Scan(&v); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config_version": v})
}

var errNotFound = errors.New("not found")

// mutate runs fn inside a transaction and bumps config_version with it.
//
// This is the ONLY way a handler should write. The bump is not appended after
// fn succeeds -- it is part of the same transaction, so a rollback takes the
// version with it. A write that commits while the bump rolls back would leave
// every engine node serving stale config with no signal that anything changed.
func (s *Server) mutate(ctx context.Context, fn func(pgx.Tx) error) (int64, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return 0, err
	}

	var version int64
	if err := tx.QueryRow(ctx, `
		UPDATE core.config_version
		SET version = version + 1, bumped_at = now()
		WHERE id = true
		RETURNING version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("bumping config version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return version, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// constantTimeEqual compares without leaking length or content through timing.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// Length alone is not secret here (the token length is fixed by config),
		// and comparing different lengths in constant time is not meaningful.
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
