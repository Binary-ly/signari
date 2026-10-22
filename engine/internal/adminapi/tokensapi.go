package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/audit"
)

// Admin tokens over the API (6.04). Until October 2026 a token could be made,
// listed and revoked only by the CLI, with a database DSN, and never expired
// unless told to: an integration's credential lived until somebody with the
// database remembered it.
//
// # A token cannot mint a wider one
//
// Every token minted, rotated or revoked here is held to the caller in each
// dimension a token has: its scopes are ones the caller holds, its
// organisation is the caller's, its named clients and groups are among the
// caller's, and it expires no later than the caller does. Rotation is held to
// it as well, because rotating a token hands the caller a working secret for
// it -- a narrow token that could rotate a wide one would have become the wide
// one. Revocation too, or a token for one client could revoke the
// organisation's main credential. A token may always rotate or revoke itself.

const (
	// tokenDefaultLifetime is what a token minted here lives for unless asked.
	tokenDefaultLifetime = 90 * 24 * time.Hour
	// tokenMaxLifetime bounds it: a credential that is never rotated is the
	// one that leaks in a repository nobody remembers.
	tokenMaxLifetime = 365 * 24 * time.Hour
	// rotationDefaultGrace is how long the old secret keeps working after a
	// rotation, so the replacement can be deployed without an outage.
	rotationDefaultGrace = 24 * time.Hour
	rotationMaxGrace     = 7 * 24 * time.Hour
)

// tokenTerms is what a token may do, as the width check compares it.
type tokenTerms struct {
	OrgID     string
	Scopes    []string
	ClientIDs []string
	GroupIDs  []string
	ExpiresAt *time.Time
}

// wider names the first way terms would exceed the caller, or nil.
func (p *Principal) wider(t tokenTerms) error {
	for _, sc := range t.Scopes {
		if !p.Can(sc) {
			return fmt.Errorf("this token does not hold %s, so it cannot grant it", sc)
		}
	}
	if p.OrgID != "" && !strings.EqualFold(t.OrgID, p.OrgID) {
		return fmt.Errorf("this token may only act on organisation %s", p.OrgID)
	}
	if p.ClientIDs != nil {
		if t.ClientIDs == nil {
			return fmt.Errorf("this token is narrowed to named clients, so a token it makes must be too")
		}
		for _, c := range t.ClientIDs {
			if !slices.Contains(p.ClientIDs, c) {
				return fmt.Errorf("client %s is not one this token may reach", c)
			}
		}
	}
	if p.GroupIDs != nil {
		if t.GroupIDs == nil {
			return fmt.Errorf("this token is narrowed to named groups, so a token it makes must be too")
		}
		for _, g := range t.GroupIDs {
			if !slices.ContainsFunc(p.GroupIDs, func(h string) bool { return strings.EqualFold(g, h) }) {
				return fmt.Errorf("group %s is not one this token may reach", g)
			}
		}
	}
	if p.ExpiresAt != nil && (t.ExpiresAt == nil || t.ExpiresAt.After(*p.ExpiresAt)) {
		return fmt.Errorf("a token may not outlive the one that makes it, which expires at %s",
			p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// tokenView is a token as it is listed: never its hash.
type tokenView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	OrgID      *string  `json:"org_id"`
	Scopes     []string `json:"scopes"`
	ClientIDs  []string `json:"client_ids"`
	GroupIDs   []string `json:"group_ids"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  *string  `json:"expires_at"`
	RevokedAt  *string  `json:"revoked_at"`
	LastUsedAt *string  `json:"last_used_at"`
}

const tokenViewColumns = `id::text, name, org_id::text, scopes, client_ids, group_ids::text[],
	to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
	to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

func scanTokenView(row pgx.Row) (tokenView, error) {
	var v tokenView
	err := row.Scan(&v.ID, &v.Name, &v.OrgID, &v.Scopes, &v.ClientIDs, &v.GroupIDs,
		&v.CreatedAt, &v.ExpiresAt, &v.RevokedAt, &v.LastUsedAt)
	return v, err
}

// listTokens is every token for a deployment-wide caller, its organisation's
// for a scoped one.
func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)
	rows, err := s.db.Query(ctx, `SELECT `+tokenViewColumns+` FROM core.admin_tokens
		WHERE $1 = '' OR org_id::text = $1 ORDER BY created_at, id`, p.OrgID)
	if err != nil {
		s.log.Error("listing admin tokens", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()
	out := []tokenView{}
	for rows.Next() {
		v, err := scanTokenView(rows)
		if err != nil {
			s.log.Error("listing admin tokens", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing admin tokens", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, map[string]any{"tokens": out})
}

type createTokenRequest struct {
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	OrgID      string   `json:"org_id"`
	ClientIDs  []string `json:"client_ids"`
	GroupIDs   []string `json:"group_ids"`
	ExpiresInS *int64   `json:"expires_in_s"`
}

// lifetime is the asked-for lifetime, or the default, refused outside bounds.
func lifetime(seconds *int64) (time.Duration, error) {
	if seconds == nil {
		return tokenDefaultLifetime, nil
	}
	d := time.Duration(*seconds) * time.Second
	if d < time.Hour || d > tokenMaxLifetime {
		return 0, fmt.Errorf("expires_in_s is 3600 to %d; a token minted here always expires",
			int64(tokenMaxLifetime.Seconds()))
	}
	return d, nil
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)
	var req createTokenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	life, err := lifetime(req.ExpiresInS)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_lifetime", "detail": err.Error()})
		return
	}
	if req.OrgID == "" {
		req.OrgID = p.OrgID
	}
	// Stored as uuids. One that is not reached the cast and came back as
	// PostgreSQL's own message (0.23); another spelling of one is stored as
	// the one the width check compares.
	for i, g := range req.GroupIDs {
		id, err := uuid.Parse(g)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_token_request",
				"detail": fmt.Sprintf("group_ids[%d] is not a uuid", i)})
			return
		}
		req.GroupIDs[i] = id.String()
	}
	expires := time.Now().Add(life)
	terms := tokenTerms{OrgID: req.OrgID, Scopes: req.Scopes, ClientIDs: nilIfEmpty(req.ClientIDs),
		GroupIDs: nilIfEmpty(req.GroupIDs), ExpiresAt: &expires}
	if err := p.wider(terms); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wider_than_caller", "detail": err.Error()})
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	var secret, id string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if req.OrgID != "" {
			if err := requireNamedOrg(ctx, tx, req.OrgID); err != nil {
				return err
			}
		}
		var err error
		secret, id, err = NewToken(ctx, tx, req.Name, req.OrgID, req.Scopes, &expires,
			terms.ClientIDs, terms.GroupIDs)
		if err != nil {
			return asTokenRequestError(err)
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.token_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: req.OrgID, Detail: map[string]any{"token_id": id, "scopes": req.Scopes,
				"expires_at": expires.UTC().Format(time.RFC3339)}})
	})
	if !s.tokenWriteFailed(w, err, "minting an admin token") {
		setETag(w, version)
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": strings.TrimSpace(req.Name),
			"secret": secret, "scopes": req.Scopes, "org_id": req.OrgID,
			"expires_at": expires.UTC().Format(time.RFC3339), "config_version": version})
	}
}

// targetTerms reads a token's terms for the width check, refusing a token
// outside the caller's organisation as not found.
func (s *Server) targetTerms(ctx context.Context, tx pgx.Tx, p *Principal, tokenID string) (tokenTerms, string, error) {
	var t tokenTerms
	var orgID *string
	var name string
	var revoked *time.Time
	err := tx.QueryRow(ctx, `SELECT org_id::text, name, scopes, client_ids, group_ids::text[], expires_at, revoked_at
		FROM core.admin_tokens WHERE id::text = $1 FOR UPDATE`, tokenID).
		Scan(&orgID, &name, &t.Scopes, &t.ClientIDs, &t.GroupIDs, &t.ExpiresAt, &revoked)
	if err != nil {
		return t, "", err
	}
	if orgID != nil {
		t.OrgID = *orgID
	}
	if p.OrgID != "" && !strings.EqualFold(t.OrgID, p.OrgID) {
		return t, "", pgx.ErrNoRows
	}
	if revoked != nil {
		return t, "", errTokenRevoked
	}
	return t, name, nil
}

var errTokenRevoked = errors.New("the token is revoked")

// rotateTokenRequest is the optional body of a rotation.
type rotateTokenRequest struct {
	GraceS     *int64 `json:"grace_s"`
	ExpiresInS *int64 `json:"expires_in_s"`
}

// rotateToken mints a replacement with the same terms and gives the old
// secret a grace period, so the new one can be deployed first.
func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)
	tokenID := r.PathValue("tokenID")
	var req rotateTokenRequest
	if r.ContentLength != 0 {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
			return
		}
	}
	grace := rotationDefaultGrace
	if req.GraceS != nil {
		grace = time.Duration(*req.GraceS) * time.Second
		if grace < 0 || grace > rotationMaxGrace {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grace",
				"detail": fmt.Sprintf("grace_s is 0 to %d", int64(rotationMaxGrace.Seconds()))})
			return
		}
	}
	life, err := lifetime(req.ExpiresInS)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_lifetime", "detail": err.Error()})
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	var secret, newID string
	expires := time.Now().Add(life)
	oldUntil := time.Now().Add(grace)
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		t, name, err := s.targetTerms(ctx, tx, p, tokenID)
		if err != nil {
			return err
		}
		if err := p.wider(t); err != nil {
			return &widerError{err}
		}
		next := t
		next.ExpiresAt = &expires
		if err := p.wider(next); err != nil {
			return &widerError{err}
		}
		secret, newID, err = NewToken(ctx, tx, name, t.OrgID, t.Scopes, &expires, t.ClientIDs, t.GroupIDs)
		if err != nil {
			return asTokenRequestError(err)
		}
		if t.ExpiresAt == nil || oldUntil.Before(*t.ExpiresAt) {
			if _, err := tx.Exec(ctx, `UPDATE core.admin_tokens SET expires_at = $2 WHERE id::text = $1`,
				tokenID, oldUntil); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.token_rotated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: t.OrgID, Detail: map[string]any{"token_id": tokenID, "replacement_id": newID,
				"old_works_until": oldUntil.UTC().Format(time.RFC3339)}})
	})
	if !s.tokenWriteFailed(w, err, "rotating an admin token") {
		setETag(w, version)
		writeJSON(w, http.StatusOK, map[string]any{"id": newID, "secret": secret, "replaces": tokenID,
			"replaced_works_until": oldUntil.UTC().Format(time.RFC3339), "config_version": version,
			"expires_at": expires.UTC().Format(time.RFC3339)})
	}
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)
	tokenID := r.PathValue("tokenID")
	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		t, _, err := s.targetTerms(ctx, tx, p, tokenID)
		if err != nil {
			return err
		}
		if err := p.wider(t); err != nil {
			return &widerError{err}
		}
		if _, err := tx.Exec(ctx, `UPDATE core.admin_tokens SET revoked_at = now() WHERE id::text = $1`,
			tokenID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.token_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: t.OrgID, Detail: map[string]any{"token_id": tokenID}})
	})
	if !s.tokenWriteFailed(w, err, "revoking an admin token") {
		setETag(w, version)
		writeJSON(w, http.StatusOK, map[string]any{"id": tokenID, "revoked": true, "config_version": version})
	}
}

type widerError struct{ err error }

func (e *widerError) Error() string { return e.err.Error() }

type badTokenRequest struct{ err error }

func (e *badTokenRequest) Error() string { return e.err.Error() }

// asTokenRequestError is NewToken's refusal of the terms as the caller's
// mistake, and a database failure as the server's: the second was answered 400
// with PostgreSQL's message, naming a table and a constraint to the caller.
func asTokenRequestError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return err
	}
	return &badTokenRequest{err}
}

// tokenWriteFailed answers a failed token write and reports whether it did.
func (s *Server) tokenWriteFailed(w http.ResponseWriter, err error, doing string) bool {
	var wide *widerError
	var bad *badTokenRequest
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.As(err, &wide):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wider_than_caller", "detail": wide.Error()})
	case errors.As(err, &bad):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_token_request", "detail": bad.Error()})
	case errors.Is(err, pgx.ErrNoRows):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	case errors.Is(err, errTokenRevoked):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "revoked", "detail": err.Error()})
	default:
		s.log.Error(doing, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
