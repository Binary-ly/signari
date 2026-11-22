package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Grant Management's API (specs/grant-management.txt §6): a client reading back and
// revoking what it was given. Creating and changing a grant happen in an authorization
// request, because those almost always need the person.

const (
	grantScopeQuery  = "grant_management_query"
	grantScopeRevoke = "grant_management_revoke"
)

type clientGrantKey struct{}

// withClientGrant carries the grant a set of tokens is issued under to where they are.
func withClientGrant(ctx context.Context, grantID string) context.Context {
	return context.WithValue(ctx, clientGrantKey{}, grantID)
}

func clientGrantFrom(ctx context.Context) string {
	grantID, _ := ctx.Value(clientGrantKey{}).(string)
	return grantID
}

// clientGrantScopes is §6.4's `scopes`: each entry one scope string with the resources
// it holds for. This grants every scope for every resource, so there is one entry.
func clientGrantScopes(g *store.ClientGrant) []map[string]any {
	entry := map[string]any{"scope": strings.Join(g.Scopes, " ")}
	if len(g.Resources) > 0 {
		entry["resource"] = g.Resources
	}
	return []map[string]any{entry}
}

// handleClientGrantQuery is §6.4.
func (s *Server) handleClientGrantQuery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := s.acceptedToken(w, r, grantScopeQuery, "grant management")
	if !ok {
		return
	}
	g, err := store.ClientGrantOf(ctx, s.db, r.PathValue("grantID"), claims.ClientID)
	if errors.Is(err, store.ErrClientGrantUnknown) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "reading a grant", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	out := map[string]any{"scopes": clientGrantScopes(g), "created_at": g.CreatedAt.Unix(),
		"last_updated": g.UpdatedAt.Unix(), "updated_by": "client"}
	if len(g.Details) > 0 {
		out["authorization_details"] = json.RawMessage(g.Details)
	}
	w.Header().Set("Cache-Control", "no-cache, no-store")
	writeJSON(w, http.StatusOK, out)
}

// handleClientGrantRevoke is §6.5.
func (s *Server) handleClientGrantRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := s.acceptedToken(w, r, grantScopeRevoke, "grant management")
	if !ok {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	g, err := store.RevokeClientGrant(ctx, tx, r.PathValue("grantID"), claims.ClientID)
	if errors.Is(err, store.ErrClientGrantUnknown) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err == nil {
		err = audit.Write(ctx, tx, audit.Event{Type: "oauth.grant_revoked", OrgID: g.OrgID, SubjectID: g.UserID,
			ClientID: claims.ClientID, CorrelationID: correlationID(ctx)})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "revoking a grant", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
