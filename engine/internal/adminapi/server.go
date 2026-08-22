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

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/ratelimit"
)

// Server is the admin write API. It listens separately from the public protocol
// endpoints so it can be bound to a private interface: an internet-reachable
// admin API on an identity provider is a large and unnecessary target.
type Server struct {
	db    *pgxpool.Pool
	log   *slog.Logger
	token string
	// hasher is the ENGINE's Argon2 configuration. Passwords set by an
	// administrator must be written with the same parameters the login path
	// expects; a hash produced elsewhere is a credential that may simply not
	// work, and the failure looks like the user mistyping.
	hasher *passwords.Hasher
	// pwPolicy is the SAME policy the sign-in paths enforce. An administrator
	// setting a password must not be able to set one a user could not.
	pwPolicy passwords.Policy

	// arrivals bounds work done for callers who have not authenticated yet.
	//
	// Every request costs a SHA-256 and an indexed database probe before it can
	// be refused, so an anonymous caller with no credential at all can generate
	// unbounded database load on the administrative interface. That is the
	// threat this answers, and it is a denial of service rather than a
	// credential attack: `auth` already explains why guessing a 256-bit random
	// token is not the risk, and a limiter does not change that either way.
	arrivals *ratelimit.Bucket

	// perToken keeps one caller from starving the others.
	//
	// A single shared bucket means the noisiest integration decides what
	// everybody else gets -- a bulk provisioning script would throttle the
	// console an operator is trying to use during the same incident. Keyed on
	// the authenticated token, which is safe to evict from because the key had
	// to exist and be unrevoked before the limiter is ever consulted.
	perToken *ratelimit.Keyed
}

func New(db *pgxpool.Pool, log *slog.Logger, token string) (*Server, error) {
	// Empty is allowed now: a deployment can run entirely on database tokens and
	// set no environment token at all, which is the better configuration. What is
	// refused is a SHORT one -- there is no rate limit that makes a 12-character
	// admin credential safe, and accepting it with a warning is not a control.
	if token != "" && len(token) < 32 {
		return nil, fmt.Errorf("admin API token must be at least 32 characters (got %d)", len(token))
	}
	return &Server{db: db, log: log, token: token,
		hasher:   passwords.NewHasher(passwords.MemoryBudgetMiB),
		pwPolicy: passwords.PolicyFromEnv(),
		// Generous on purpose. Administration is low-volume and bursty -- an
		// operator paging through clients, a provisioning run creating a batch --
		// so these bound the damage without being something a real deployment
		// ever notices. A limit tight enough to interfere is a limit somebody
		// raises to infinity during an incident.
		arrivals: ratelimit.New(adminArrivalsPerSecond, adminArrivalsBurst),
		perToken: ratelimit.NewKeyed(adminPerTokenPerSecond, adminPerTokenBurst,
			adminTrackedTokens),
	}, nil
}

// Rate limits for the administrative interface.
const (
	adminArrivalsPerSecond = 100
	adminArrivalsBurst     = 200
	adminPerTokenPerSecond = 50
	adminPerTokenBurst     = 100
	// adminTrackedTokens bounds the per-token map. Far above the number of
	// credentials any deployment issues, because the map is only a memory bound
	// and evicting an entry hands its key a fresh allowance.
	adminTrackedTokens = 1024
)

// Routes returns the fully wrapped handler.
//
// It returns http.Handler rather than *http.ServeMux so that the global limiter
// is part of what a caller receives. Exposing the bare mux and a separate
// wrapper would leave two ways to serve this API, one of them unlimited -- and
// the unlimited one is shorter to type.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /admin/clients/{clientID}", s.auth(ScopeClientsWrite, s.patchClient))
	mux.HandleFunc("POST /admin/users", s.auth(ScopeUsersWrite, s.createUser))
	mux.HandleFunc("POST /admin/clients", s.auth(ScopeClientsWrite, s.createClient))
	mux.HandleFunc("POST /admin/clients/{clientID}/rotate-secret",
		s.auth(ScopeClientsWrite, s.rotateClientSecret))
	mux.HandleFunc("PATCH /admin/users/{userID}", s.auth(ScopeUsersWrite, s.patchUser))
	mux.HandleFunc("GET /admin/config-version", s.auth(ScopeConfigRead, s.configVersion))
	mux.HandleFunc("POST /admin/subjects/{subjectID}/erase",
		s.auth(ScopeSubjectsErase, s.eraseSubject))
	return s.limitArrivals(mux)
}

// limitArrivals is the outermost wrapper: it runs before authentication, because
// authentication is the work being protected.
func (s *Server) limitArrivals(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.arrivals != nil && !s.arrivals.Allow() {
			tooManyRequests(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tooManyRequests answers a throttled caller.
//
// Retry-After is set for the same reason the JWKS endpoint sets it: a client
// told only "no" retries immediately and makes the problem worse.
func tooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusTooManyRequests, map[string]string{
		"error":  "rate_limited",
		"detail": "too many administrative requests",
	})
}

// auth authenticates the caller and requires a scope.
//
// # Why this now reads the database
//
// It used to be a constant-time comparison against one environment variable and
// nothing else, on the reasoning that a lookup turns a guessing attempt into a
// query. That reasoning was sound about load and wrong about risk: it also meant
// no revocation, no expiry, no attribution and no organisation boundary, and a
// leaked token stayed valid until somebody restarted every node.
//
// The lookup is a single indexed probe on a SHA-256 of the presented value.
// Guessing is not the threat against a 256-bit random token; leaking is, and
// leaking is what the old design had no answer to. The environment token still
// works and still needs no database, so the break-glass path is unchanged.
func (s *Server) auth(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
			unauthorized(w)
			return
		}

		p, err := s.resolveToken(r.Context(), h[len(prefix):])
		if err != nil {
			if !errors.Is(err, errTokenRejected) {
				s.log.Error("resolving an admin token", "err", err)
				writeJSON(w, http.StatusServiceUnavailable,
					map[string]string{"error": "unavailable"})
				return
			}
			unauthorized(w)
			return
		}

		// Per-token, and placed HERE rather than earlier for a specific reason.
		//
		// The key has to be an authenticated identity. Keying a limiter on
		// anything the caller supplies -- the raw bearer value, a header, an
		// address behind a proxy -- lets them mint fresh keys at will, and since
		// a new key starts with a full bucket, the limit becomes something the
		// attacker resets rather than something they are subject to. By this
		// point the token has been found, is unrevoked and is unexpired, so its
		// name is a bounded value we chose.
		//
		// Its purpose is fairness, not defence: the global limiter above already
		// bounds total work. This stops one integration's bulk run from consuming
		// the whole allowance while an operator is trying to use the console.
		if s.perToken != nil && !s.perToken.Allow(p.Name) {
			s.log.Info("admin request throttled", "token", p.Name,
				"method", r.Method, "path", r.URL.Path)
			tooManyRequests(w)
			return
		}

		// Authenticated but not permitted is 403, and says which scope was
		// missing. This is an operator-facing API: "forbidden" with no detail
		// turns a one-line fix into an afternoon.
		if !p.Can(scope) {
			s.log.Info("admin request refused: missing scope", "token", p.Name,
				"required", scope, "held", p.Scopes)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "insufficient_scope",
				"detail": "this token does not hold " + scope,
			})
			return
		}

		if p.BreakGlass {
			// Logged every single time. A credential that bypasses revocation and
			// expiry should never be quietly interchangeable with the others.
			s.log.Warn("admin request used the break-glass environment token",
				"method", r.Method, "path", r.URL.Path)
		}
		s.touch(p.TokenID)
		next(w, r.WithContext(withPrincipal(r.Context(), p)))
	}
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="signari-admin"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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
		// This handler previously changed a client without ever reading which
		// organisation it belonged to, so there was nothing for the boundary to
		// check against. The lookup exists for that reason.
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.clients WHERE client_id = $1`,
			clientID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}

		tag, err := tx.Exec(ctx,
			`UPDATE core.clients SET enabled = $2, updated_at = now() WHERE client_id = $1`,
			clientID, *req.Enabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}

		// Disabling a client is the emergency lever -- the way an operator cuts a
		// compromised integration off from every user at once. It had no audit
		// record at all, so afterwards there was no way to say who pulled it, or
		// when, or whether it was pulled rather than the client breaking on its
		// own.
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.client_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID,
			Detail: map[string]any{"enabled": *req.Enabled},
		})
	})

	switch {
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
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

// writeCrossOrg answers a boundary violation with 403 and says so.
//
// Not 404. The record exists; this credential simply may not touch it, and
// pretending otherwise sends an operator hunting for a resource that is right
// where they left it.
func writeCrossOrg(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": "outside_token_organisation", "detail": err.Error(),
	})
}

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
