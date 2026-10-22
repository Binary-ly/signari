package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
)

// Tenant provisioning.
//
// # Why an unscoped token, and only an unscoped token
//
// Creating an organisation is the one write with no organisation to be scoped
// to, and that makes it the one place the tenancy boundary could be crossed by
// accident rather than by attack: a tenant that can provision tenants is a
// tenant that has escaped the isolation the entire product is built on. It
// could create a sibling and then, holding a token for the new organisation,
// act on data it was never supposed to reach.
//
// The check needed no new machinery. `requireOrg(ctx, "")` already means exactly
// "only a token that is not scoped to an organisation may do this": MayActOn
// returns nil for an unscoped principal and refuses a scoped one that has not
// named its organisation. Reusing it keeps one implementation of the boundary
// rather than a second one that has to be kept in step -- and a second one is
// how a boundary comes to hold for new records and not for edits.
//
// # Why a separate scope
//
// `organizations:write` rather than folding it into `users:write`, on the same
// reasoning as `subjects:erase`: the blast radius is different in kind. A token
// issued to a provisioning system that creates tenants has no business editing
// the people inside them, and a support desk token that edits people has no
// business creating tenants.
//
// # Suspension rather than deletion
//
// There is no DELETE here, and that is a decision rather than an omission.
// `organizations.instance_id` is ON DELETE RESTRICT, and every user, client,
// session, token and audit event in the deployment hangs off an organisation. A
// one-call tenant deletion is an irreversible destruction of everything a
// customer has, reachable by a single mistyped identifier, and no confirmation
// parameter makes that a good shape for an HTTP API. Removing the data is a
// deliberate operation with the database in front of you. Suspension is
// `status = 'suspended'`, set by PATCH below (6.09) and read at every entry
// point; the enforcement shipped first, then this writer, because for years
// this paragraph said it stopped the tenant working while nothing read it.

// slugPattern is what may appear in a URL and a configuration file without
// quoting.
//
// Deliberately narrow. A slug ends up in generated identifiers and paths, so
// permitting anything that needs escaping means every consumer has to remember
// to escape it and one of them will not.
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type createOrganizationRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	// InstanceID may be omitted when the deployment has exactly one instance,
	// which is the common case. It is required as soon as there are several,
	// because guessing which one a new tenant belongs to would put it somewhere
	// the caller did not choose.
	InstanceID string `json:"instance_id"`
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createOrganizationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	// Trimmed but NOT lowercased. The first version folded the case and it was
	// wrong twice over.
	//
	// The uniqueness index is on `(instance_id, slug)` with no lower(), so
	// "Upper" and "upper" would otherwise be two organisations whose slugs are
	// indistinguishable to a person reading a URL. Folding silently prevents
	// that pair, but at the cost of the second problem: a caller who creates
	// "Upper" then holds an identifier the deployment does not have, and their
	// next request for it is a 404 they cannot explain.
	//
	// Refusing gets both properties. Only one spelling is ever accepted, so the
	// confusable pair cannot exist, and nothing a caller sent is quietly turned
	// into something else.
	req.Slug = strings.TrimSpace(req.Slug)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if !slugPattern.MatchString(req.Slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_slug",
			"detail": "a slug is 1-63 characters of lowercase letters, digits " +
				"and hyphens, starting and ending with a letter or digit. " +
				"Uppercase is refused rather than folded, so that the slug you " +
				"send is the slug that exists",
		})
		return
	}
	if req.DisplayName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_display_name", "detail": "a display name is required",
		})
		return
	}

	// Before anything else. An organisation-scoped token must be refused here
	// rather than deeper in, so no row is read on its behalf.
	if err := requireOrg(ctx, ""); err != nil {
		writeCrossOrg(w, err)
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}

	var orgID, instanceID string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		instanceID = req.InstanceID
		if instanceID == "" {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.instances`).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				return errAmbiguousInstance
			}
			if err := tx.QueryRow(ctx,
				`SELECT id::text FROM core.instances`).Scan(&instanceID); err != nil {
				return err
			}
		}

		if err := tx.QueryRow(ctx, `
			INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ($1::uuid, $2, $3)
			RETURNING id::text`,
			instanceID, req.Slug, req.DisplayName).Scan(&orgID); err != nil {
			return err
		}

		// OrgID is the NEW organisation. The event belongs to the tenant that
		// came into existence, not to the caller -- an audit trail that filed
		// tenant creation under whoever happened to run it would leave the new
		// organisation with no record of its own beginning.
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.organization_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID,
			Detail: map[string]any{
				"slug": req.Slug, "instance_id": instanceID,
			},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errAmbiguousInstance):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "instance_required",
			"detail": "this deployment has more or fewer than one instance, so " +
				"the organisation's instance_id must be named",
		})
		return
	case err != nil && strings.Contains(err.Error(), "organizations_instance_id_slug_key"):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "already_exists", "detail": "that slug is taken on this instance",
		})
		return
	case err != nil && strings.Contains(err.Error(), "organizations_instance_id_fkey"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_instance", "detail": "no instance has that id",
		})
		return
	case err != nil:
		s.log.Error("creating an organisation", "slug", req.Slug, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	s.log.Info("organisation created", "org_id", orgID, "slug", req.Slug,
		"instance_id", instanceID, "config_version", version)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": orgID, "slug": req.Slug, "display_name": req.DisplayName,
		"instance_id": instanceID, "config_version": version,
	})
}

var errAmbiguousInstance = errors.New("the instance is ambiguous")

// organization is what the reads return: what a tenant is, never what it holds.
type organization struct {
	ID          string `json:"id"`
	InstanceID  string `json:"instance_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

const organizationColumns = `id::text, instance_id::text, slug, display_name, status,
	to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

// listOrganizations is every organisation for a deployment-wide token, and its
// own for one scoped to an organisation.
func (s *Server) listOrganizations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, ok := principalFrom(ctx)
	if !ok {
		writeCrossOrg(w, requireOrg(ctx, ""))
		return
	}
	rows, err := s.db.Query(ctx, `SELECT `+organizationColumns+` FROM core.organizations
		WHERE $1 = '' OR id::text = $1 ORDER BY created_at, id`, p.OrgID)
	if err != nil {
		s.log.Error("listing organisations", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()
	out := []organization{}
	for rows.Next() {
		var o organization
		if err := rows.Scan(&o.ID, &o.InstanceID, &o.Slug, &o.DisplayName, &o.Status, &o.CreatedAt); err != nil {
			s.log.Error("listing organisations", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing organisations", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, map[string]any{"organizations": out})
}

func (s *Server) getOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var o organization
	err := s.db.QueryRow(ctx, `SELECT `+organizationColumns+` FROM core.organizations
		WHERE id::text = $1`, orgID).
		Scan(&o.ID, &o.InstanceID, &o.Slug, &o.DisplayName, &o.Status, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if err != nil {
		s.log.Error("reading an organisation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, o)
}

// patchOrganizationRequest is the body of an organisation PATCH.
type patchOrganizationRequest struct {
	Status *string `json:"status"`
}

// patchOrganization suspends or reactivates an organisation (6.09).
//
// Suspension refuses the organisation at every entry point the engine has --
// sign-in, its sessions, its clients at every endpoint, its tokens at
// userinfo and introspection, directory binds, SCIM, its outposts, sign-up,
// recovery and its own admin tokens -- from the next request, and ends
// nothing: reactivated, a session or grant with time left resumes. Ending
// them is a separate, deliberate act.
//
// Deployment-wide tokens only. A tenant that could reactivate itself would be
// a suspension it lifts at will, and its own tokens are refused while it is
// suspended anyway.
func (s *Server) patchOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")

	var req patchOrganizationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Status == nil || (*req.Status != "active" && *req.Status != "suspended") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status",
			"detail": `status is "active" or "suspended"`})
		return
	}
	if err := requireOrg(ctx, ""); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_organisation",
			"detail": "only a deployment-wide token may suspend or reactivate an organisation"})
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	var was string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT status FROM core.organizations WHERE id::text = $1 FOR UPDATE`,
			orgID).Scan(&was); err != nil {
			return err
		}
		if was == *req.Status {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE core.organizations SET status = $2, updated_at = now()
			WHERE id::text = $1`, orgID, *req.Status); err != nil {
			return err
		}
		typ := "admin.organization_suspended"
		if *req.Status == "active" {
			typ = "admin.organization_reactivated"
		}
		return audit.Write(ctx, tx, audit.Event{Type: typ, AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"was": was}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, pgx.ErrNoRows):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	case err != nil:
		s.log.Error("setting an organisation's status", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	s.log.Warn("organisation status set", "org_id", orgID, "status", *req.Status, "was", was,
		"config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{"id": orgID, "status": *req.Status, "was": was,
		"config_version": version})
}
