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

// Administering the user profile schema and its values.
//
// # Declaring an attribute is a configuration change, editing one is not
//
// The two are split across scopes for that reason. Declaring `home_address` as
// an attribute of an organisation decides what the deployment may hold about
// everybody in it, and whether it survives an erasure request -- that is
// config, and it needs `clients:write`-class authority over the tenant. Setting
// one person's value is user administration.
//
// # Reads never return a value the requester should not see
//
// A personal attribute's value is sealed under the subject's key, so a read of
// an erased subject returns `readable: false` rather than a value or an error.
// That distinction is deliberate and is reported: "destroyed on request" and
// "never set" are different facts, and somebody auditing whether an erasure
// completed needs to tell them apart.

type declareAttributeRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	ValueType   string `json:"value_type"`
	// Personal defaults to TRUE when the field is absent, which is why it is a
	// pointer. A plain bool would default to false, silently storing an
	// undeclared-sensitivity attribute in the clear where erasure cannot reach
	// it -- the exact failure the schema exists to prevent, arriving through a
	// JSON field somebody left out.
	Personal     *bool `json:"personal"`
	UserReadable bool  `json:"user_readable"`
	UserWritable bool  `json:"user_writable"`
	Required     bool  `json:"required"`
}

// declareAttribute creates or updates an attribute declaration.
func (s *Server) declareAttribute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")

	var req declareAttributeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.ValueType == "" {
		req.ValueType = "string"
	}
	personal := true
	if req.Personal != nil {
		personal = *req.Personal
	}

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var attrID string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM core.organizations WHERE id = $1::uuid`, orgID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}

		id, err := store.DeclareAttribute(ctx, tx, orgID, store.Attribute{
			Name: req.Name, DisplayName: req.DisplayName, ValueType: req.ValueType,
			Personal: personal, UserReadable: req.UserReadable,
			UserWritable: req.UserWritable, Required: req.Required,
		})
		if err != nil {
			return err
		}
		attrID = id

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.attribute_declared", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID,
			// The NAME and the sensitivity, never a value: this event records a
			// configuration decision, and the decision is what an audit of "what
			// may this deployment hold about people" needs.
			Detail: map[string]any{
				"name": req.Name, "value_type": req.ValueType, "personal": personal,
				"user_readable": req.UserReadable, "user_writable": req.UserWritable,
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
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization_not_found"})
		return
	case err != nil && isConstraintViolation(err, "user_attribute_schema_name_check"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_name",
			"detail": "an attribute name is lowercase letters, digits and " +
				"underscores, starting with a letter",
		})
		return
	case err != nil && isConstraintViolation(err, "user_attribute_writable_implies_readable"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "writable_but_not_readable",
			"detail": "a field somebody can set and cannot see is one they will set twice",
		})
		return
	case err != nil && isConstraintViolation(err, "user_attribute_schema_value_type_check"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid_value_type",
			"detail": "value_type is one of string, number, boolean, date",
		})
		return
	case errors.Is(err, store.ErrAttributeTypeInUse):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "attribute_type_in_use",
			"detail": err.Error() + "; its values were checked against that type. " +
				"Declare a new attribute and move the values deliberately",
		})
		return
	case err != nil:
		s.log.Error("declaring an attribute", "org_id", orgID, "name", req.Name, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": attrID, "name": req.Name, "personal": personal,
		"config_version": version,
	})
}

// listAttributes returns an organisation's declarations.
func (s *Server) listAttributes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	attrs, err := store.Attributes(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing attributes", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// By the names the declaration takes, as every other response is: the
	// store type went out as it was, so this one route answered in Go's field
	// names (ID, ValueType, UserReadable) where the rest say snake_case (6.02).
	out := make([]attributeView, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, attributeView{ID: a.ID, Name: a.Name, DisplayName: a.DisplayName,
			ValueType: a.ValueType, Personal: a.Personal, UserReadable: a.UserReadable,
			UserWritable: a.UserWritable, Required: a.Required})
	}
	writeJSON(w, http.StatusOK, map[string]any{"attributes": out})
}

// attributeView is one declaration as the list returns it.
type attributeView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DisplayName  string `json:"display_name"`
	ValueType    string `json:"value_type"`
	Personal     bool   `json:"personal"`
	UserReadable bool   `json:"user_readable"`
	UserWritable bool   `json:"user_writable"`
	Required     bool   `json:"required"`
}

// getUserAttributes returns one user's attribute values.
func (s *Server) getUserAttributes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("reading attributes", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var orgID string
	if err := tx.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		s.log.Error("reading attributes", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	values, err := store.UserAttributes(ctx, tx, userID, orgID, s.root)
	if err != nil {
		s.log.Error("reading attributes", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	out := make([]map[string]any, 0, len(values))
	for _, v := range values {
		out = append(out, map[string]any{
			"name": v.Name, "display_name": v.DisplayName,
			"value_type": v.ValueType, "personal": v.Personal,
			"value": v.Value,
			// See the file comment: this distinguishes "destroyed on request"
			// from "never set", which an erasure audit needs.
			"readable": v.Readable,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "attributes": out})
}

type setAttributesRequest struct {
	Attributes map[string]string `json:"attributes"`
}

// setUserAttributes writes values for one user.
func (s *Server) setUserAttributes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	var req setAttributesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if len(req.Attributes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "nothing_to_change", "detail": "no attributes given",
		})
		return
	}

	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var unknown string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}

		// Names only, never values, and sorted so the record is stable.
		names := make([]string, 0, len(req.Attributes))
		for name, value := range req.Attributes {
			if err := store.SetUserAttribute(ctx, tx, userID, orgID, name, value, s.root); err != nil {
				if errors.Is(err, store.ErrNoSuchAttribute) {
					unknown = name
				}
				return err
			}
			names = append(names, name)
		}

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.attributes_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID,
			// WHICH attributes moved, never what they were set to. Recording the
			// values would put the personal data straight into the append-only
			// table the audit package's first rule keeps it out of -- and would
			// make it survive the erasure that the sealed storage exists to
			// honour.
			Detail: map[string]any{"attributes": names},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	case errors.Is(err, store.ErrInvalidAttributeValue):
		// Names the attribute and its type, never the value, which may be
		// personal and would then sit in every log that keeps responses.
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_attribute_value", "detail": err.Error(),
		})
		return
	case errors.Is(err, store.ErrNoSuchAttribute):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_attribute",
			"detail": "no attribute named " + unknown + " is declared for this " +
				"organisation. Declare it first, so its sensitivity and erasure " +
				"behaviour are decided before it holds anything",
		})
		return
	case err != nil:
		s.log.Error("setting attributes", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": userID, "config_version": version,
	})
}

// clearUserAttribute removes one of a person's values (6.07). Before it the
// Admin API could set a value and never take one away, so a leaver's
// department could only be overwritten with another.
func (s *Server) clearUserAttribute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, name := r.PathValue("userID"), r.PathValue("name")
	orgID, ok := s.consentUser(w, r)
	if !ok {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := store.RemoveUserAttribute(ctx, tx, userID, orgID, name); err != nil {
			return err
		}
		// The name only, as admin.attributes_set records it.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.attribute_cleared", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID, Detail: map[string]any{"attribute": name}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrNoSuchAttribute):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_attribute", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrAttributeNotSet):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "attribute_not_set", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrAttributeRequired):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "attribute_required", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("clearing an attribute", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "attribute": name, "cleared": true,
		"config_version": version})
}

// isConstraintViolation reports whether err names a database constraint.
func isConstraintViolation(err error, name string) bool {
	return err != nil && strings.Contains(err.Error(), name)
}
