package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
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
	// Source is where the value comes from: attribute, the default, constant,
	// groups, user_field or relation. SourceValue is a constant's text, or which
	// field.
	Source      string `json:"source"`
	SourceValue string `json:"source_value"`
	// Transform is lower, prefix or extract, and TransformArg its text or RE2.
	Transform    string `json:"transform"`
	TransformArg string `json:"transform_arg"`
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
	attributeSource := req.Source == "" || req.Source == "attribute"
	if (attributeSource && req.Attribute == "") || req.ClaimName == "" || req.Destination == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "incomplete",
			"detail": "claim_name and destination are required, and attribute for an attribute source",
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
		// A mapper hands the attribute's value to applications, which is a read
		// of it by other means: only one the token may reach (V8.2.3).
		if attributeSource {
			if err := requireAttribute(ctx, req.Attribute); err != nil {
				return err
			}
		}

		// The attribute declared, the scope one a grant can carry, the client
		// the organisation's (store.SetClaimMapper): a typo otherwise made a
		// mapper that released nothing, to anybody, while looking configured.
		var personal bool
		var err error
		if mapperID, personal, err = store.SetClaimMapper(ctx, tx, orgID, store.ClaimMapper{
			Attribute: req.Attribute, ClaimName: req.ClaimName, Destination: req.Destination,
			ClientID: req.ClientID, RequiredScope: req.RequiredScope, Source: req.Source,
			SourceValue: req.SourceValue, Transform: req.Transform, TransformArg: req.TransformArg}); err != nil {
			return err
		}

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.claim_mapper_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: req.ClientID,
			// The four fields that together ARE the disclosure. No value: this
			// records that a fact will be released, not the fact itself.
			Detail: map[string]any{
				"attribute": req.Attribute, "source": req.Source, "claim_name": req.ClaimName,
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
	case errors.Is(err, store.ErrMapperAttributeUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":  "unknown_attribute",
			"detail": "no attribute named " + req.Attribute + " is declared here",
		})
		return
	case errors.Is(err, store.ErrMapperScopeUnknown):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_scope",
			"detail": req.RequiredScope + " is neither a standard scope nor one this " +
				"organisation declares, so no grant can carry it and the mapper " +
				"would release nothing. Declare it first",
		})
		return
	case errors.Is(err, store.ErrMapperSource):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_source", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrMapperProtocolClaim):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "protocol_claim",
			"detail": "that claim name is part of the token's own identity. A " +
				"mapper writing sub, iss, aud, acr or amr would let this " +
				"organisation forge what a relying party reads to decide who " +
				"authenticated and how strongly",
		})
		return
	case errors.Is(err, store.ErrMapperDestination):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid_destination",
			"detail": "destination is one of id_token, userinfo, access_token",
		})
		return
	case errors.Is(err, store.ErrMapperClientElsewhere):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_client", "detail": "no client with that id in this organisation",
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

	mappers, err := store.ClaimMappers(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing claim mappers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]map[string]any, 0, len(mappers))
	for _, m := range mappers {
		entry := map[string]any{
			"id": m.ID, "attribute": m.Attribute, "personal": m.Personal,
			"claim_name": m.ClaimName, "destination": m.Destination,
			"required_scope": m.RequiredScope,
			"all_clients":    m.ClientID == "",
			"source":         m.Source, "source_value": m.SourceValue,
			"transform": m.Transform, "transform_arg": m.TransformArg,
		}
		if m.ClientID != "" {
			entry["client_id"] = m.ClientID
		}
		out = append(out, entry)
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
		// How an attribute is released is the attribute's: a token narrowed
		// to others leaves its mappers alone (V8.2.3).
		if attributeFilter(ctx) != nil {
			var name *string
			err := tx.QueryRow(ctx, `SELECT s.name FROM core.claim_mappers m
				LEFT JOIN core.user_attribute_schema s ON s.id = m.attribute_id
				WHERE m.org_id = $1::uuid AND m.id = $2::uuid`, orgID, store.ExactUUIDOrNil(mapperID)).Scan(&name)
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			if err != nil {
				return err
			}
			if name != nil {
				if err := requireAttribute(ctx, *name); err != nil {
					return err
				}
			}
		}
		// In the organisation only (store.RemoveClaimMapper): without it a
		// caller could delete another tenant's mapper by id.
		if err := store.RemoveClaimMapper(ctx, tx, orgID, mapperID); errors.Is(err, store.ErrMapperUnknown) {
			return errNotFound
		} else if err != nil {
			return err
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
