package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Declaring the scopes an organisation uses.
//
// # What declaring buys, and what it does not
//
// It does NOT add a gate on a request. A client already cannot ask for a scope
// it is not registered for -- `Client.UnknownScopes`, enforced at /authorize,
// the device and CIBA endpoints, jwt-bearer and client_credentials. Nothing here
// weakens or duplicates that.
//
// What it buys is that a scope stops being a word somebody typed twice. Before
// this, `hr_records` existed only because the same string appeared in a client's
// registered list and in a claim mapper's `required_scope`, with nothing
// connecting them — so a typo in either was silent, and silent in the worst
// direction: the mapper waits for a scope no client can be granted, the claim is
// never released, and the configuration looks correct.
//
// Declaring also gives the consent screen something to say. "hr_records" tells a
// person nothing, and a consent screen that cannot explain what is being asked
// for collects a click rather than a decision.

type scopeRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	// Advertise defaults to TRUE when absent, which is why it is a pointer:
	// the common case is a scope an integrator should be able to discover, and
	// a plain bool would default to hiding it.
	Advertise *bool `json:"advertise"`
}

func (s *Server) declareScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")

	var req scopeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	advertise := true
	if req.Advertise != nil {
		advertise = *req.Advertise
	}

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if err := store.DeclareScope(ctx, tx, orgID, store.Scope{
			Name: req.Name, DisplayName: req.DisplayName,
			Description: req.Description, Advertise: advertise,
		}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.scope_declared", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID,
			Detail: map[string]any{
				"name": req.Name, "advertise": advertise,
			},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case err != nil && isConstraintViolation(err, "scopes_not_a_standard_scope"),
		err != nil && strings.Contains(err.Error(), "is a standard scope"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "standard_scope",
			"detail": "that scope's meaning is defined by the specification and " +
				"is not configurable; a row redefining it would be a setting " +
				"that changes nothing",
		})
		return
	case err != nil && isConstraintViolation(err, "scopes_name_check"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_name",
			"detail": "a scope name starts with a letter and continues with " +
				"letters, digits, underscore, colon, dot or hyphen",
		})
		return
	case err != nil:
		s.log.Error("declaring a scope", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"name": req.Name, "advertise": advertise, "config_version": version,
	})
}

func (s *Server) listScopes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	scopes, err := store.Scopes(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing scopes", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scopes": scopes,
		// The fixed set, so a caller reading this knows the whole vocabulary
		// rather than only the operator-defined half.
		"standard": store.StandardScopes,
	})
}

func (s *Server) deleteScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	name := r.PathValue("scope")

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		// org_id in the WHERE as well as the name, so one tenant cannot delete
		// another's declaration by guessing a name.
		tag, err := tx.Exec(ctx,
			`DELETE FROM core.scopes WHERE org_id = $1::uuid AND name = $2`, orgID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.scope_deleted", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": name},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope_not_found"})
		return
	case err != nil:
		s.log.Error("deleting a scope", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "config_version": version})
}
