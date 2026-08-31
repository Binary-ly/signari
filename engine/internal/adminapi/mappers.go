package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// Administering claim mappers.
//
// # Creating one is a disclosure decision, so it is audited as one
//
// A mapper is the only thing that puts a user attribute into a token. Creating
// one therefore decides that a particular relying party — or every relying
// party in the organisation — will receive a particular fact about every user
// who has it. That is the moment worth recording, and the audit event carries
// the attribute, the claim name, the destination and the client, because those
// four together are the disclosure.
//
// # Why the destination and the client are required rather than defaulted
//
// A default would be a disclosure nobody chose. Defaulting the client to "all"
// would silently release to relying parties already integrated; defaulting the
// destination to the ID token would put it somewhere the user at least sees a
// consent screen for, but defaulting to the access token would send it to
// resource servers they never did. Neither default is safe enough to be worth
// the keystroke it saves.

type mapperRequest struct {
	Attribute string `json:"attribute"`
	ClaimName string `json:"claim_name"`
	// Destination is required: id_token, userinfo or access_token.
	Destination string `json:"destination"`
	// ClientID empty means every client in the organisation, which is the wider
	// disclosure and is therefore stated rather than defaulted -- see
	// AllClients.
	ClientID string `json:"client_id"`
	// AllClients must be true to release to every client. Without it, an empty
	// client_id is refused rather than read as "all": the difference between
	// "one client" and "everyone" is the whole disclosure, and a field left out
	// of a JSON body must never be the one that widens it.
	AllClients    bool   `json:"all_clients"`
	RequiredScope string `json:"required_scope"`
}

// createMapper declares that an attribute is released as a claim.
func (s *Server) createMapper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")

	var req mapperRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Attribute == "" || req.ClaimName == "" || req.Destination == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "incomplete",
			"detail": "attribute, claim_name and destination are all required",
		})
		return
	}
	if req.ClientID == "" && !req.AllClients {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "audience_required",
			"detail": "name a client_id, or set all_clients to release to every " +
				"client in the organisation. Releasing to everyone is the wider " +
				"disclosure and is not what an omitted field should mean",
		})
		return
	}

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var mapperID string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}

		var attrID string
		var personal bool
		if err := tx.QueryRow(ctx, `
			SELECT id::text, personal FROM core.user_attribute_schema
			WHERE org_id = $1::uuid AND name = $2`, orgID, req.Attribute).
			Scan(&attrID, &personal); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}

		var client any
		if req.ClientID != "" {
			client = req.ClientID
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO core.claim_mappers
				(org_id, client_id, attribute_id, claim_name, destination, required_scope)
			VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6)
			ON CONFLICT (org_id, client_id, attribute_id, destination) DO UPDATE SET
				claim_name = EXCLUDED.claim_name,
				required_scope = EXCLUDED.required_scope
			RETURNING id::text`,
			orgID, client, attrID, req.ClaimName, req.Destination,
			req.RequiredScope).Scan(&mapperID); err != nil {
			return err
		}

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.claim_mapper_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: req.ClientID,
			// The four fields that together ARE the disclosure. No value: this
			// records that a fact will be released, not the fact itself.
			Detail: map[string]any{
				"attribute": req.Attribute, "claim_name": req.ClaimName,
				"destination": req.Destination, "required_scope": req.RequiredScope,
				"all_clients": req.ClientID == "",
				// Whether the released attribute is personal, because an audit
				// asking "what personal data does this deployment disclose, and
				// to whom" is answerable from these events alone.
				"personal": personal,
			},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":  "unknown_attribute",
			"detail": "no attribute named " + req.Attribute + " is declared here",
		})
		return
	case err != nil && isConstraintViolation(err, "claim_mappers_not_a_protocol_claim"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "protocol_claim",
			"detail": "that claim name is part of the token's own identity. A " +
				"mapper writing sub, iss, aud, acr or amr would let this " +
				"organisation forge what a relying party reads to decide who " +
				"authenticated and how strongly",
		})
		return
	case err != nil && isConstraintViolation(err, "claim_mappers_destination_check"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid_destination",
			"detail": "destination is one of id_token, userinfo, access_token",
		})
		return
	case err != nil && isConstraintViolation(err, "claim_mappers_client_id_fkey"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_client", "detail": "no client with that id",
		})
		return
	case err != nil:
		s.log.Error("creating a claim mapper", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": mapperID, "claim_name": req.ClaimName,
		"destination": req.Destination, "config_version": version,
	})
}

// listMappers reports what an organisation releases, and to whom.
//
// The answer to "what does this deployment disclose about its users" ought to be
// one request, not an audit of every client's integration.
func (s *Server) listMappers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	rows, err := s.db.Query(ctx, `
		SELECT m.id::text, COALESCE(m.client_id, ''), s.name, s.personal,
		       m.claim_name, m.destination, m.required_scope
		FROM core.claim_mappers m
		JOIN core.user_attribute_schema s ON s.id = m.attribute_id
		WHERE m.org_id = $1::uuid
		ORDER BY s.name, m.destination, m.client_id NULLS FIRST`, orgID)
	if err != nil {
		s.log.Error("listing claim mappers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var id, clientID, attr, claim, dest, scope string
		var personal bool
		if err := rows.Scan(&id, &clientID, &attr, &personal, &claim, &dest, &scope); err != nil {
			s.log.Error("listing claim mappers", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		entry := map[string]any{
			"id": id, "attribute": attr, "personal": personal,
			"claim_name": claim, "destination": dest,
			"required_scope": scope,
			"all_clients":    clientID == "",
		}
		if clientID != "" {
			entry["client_id"] = clientID
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing claim mappers", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mappers": out})
}

// deleteMapper stops releasing a claim.
func (s *Server) deleteMapper(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	mapperID := r.PathValue("mapperID")

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		// org_id in the WHERE clause as well as the id: without it a caller could
		// delete another tenant's mapper by id, which is the tenancy boundary
		// undone by an omitted clause.
		tag, err := tx.Exec(ctx,
			`DELETE FROM core.claim_mappers WHERE id = $1::uuid AND org_id = $2::uuid`,
			mapperID, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.claim_mapper_deleted", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"mapper_id": mapperID},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mapper_not_found"})
		return
	case err != nil:
		s.log.Error("deleting a claim mapper", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": mapperID, "config_version": version,
	})
}
