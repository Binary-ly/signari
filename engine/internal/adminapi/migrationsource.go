package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// An organisation's migration source (2.01): the provider whose password grant,
// or the directory whose bind, verifies a migrating person at their first
// sign-in. Configured here and by `signari migration-source`, both through
// store.SetMigrationSource. Nothing could create one before.
//
// organizations:write, as the organisation's other settings: a source decides
// where people's passwords are sent, which is no smaller a decision.

type migrationSourceRequest struct {
	Kind           string `json:"kind"`
	DisplayName    string `json:"display_name"`
	URL            string `json:"url"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	Scope          string `json:"scope"`
	BindDNTemplate string `json:"bind_dn_template"`
	StartTLS       bool   `json:"start_tls"`
	CAPEM          string `json:"ca_pem"`
	// Enabled is left as it is when absent; a new source starts disabled.
	Enabled *bool `json:"enabled"`
}

func (s *Server) getMigrationSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	src, err := store.MigrationSourceOf(ctx, s.db, orgID)
	switch {
	case errors.Is(err, store.ErrMigrationSourceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "migration_source_not_found"})
		return
	case err != nil:
		s.log.Error("reading a migration source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, src)
}

func (s *Server) putMigrationSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req migrationSourceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var src *store.MigrationSourceStatus
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if _, err := store.SetMigrationSource(ctx, tx, s.root, orgID, store.MigrationSourceConfig{
			Kind: req.Kind, DisplayName: req.DisplayName, URL: req.URL, ClientID: req.ClientID,
			ClientSecret: req.ClientSecret, Scope: req.Scope, BindDNTemplate: req.BindDNTemplate,
			StartTLS: req.StartTLS, CAPEM: req.CAPEM,
		}); err != nil {
			return err
		}
		if req.Enabled != nil {
			if err := store.SetMigrationSourceEnabled(ctx, tx, orgID, *req.Enabled); err != nil {
				return err
			}
		}
		var err error
		if src, err = store.MigrationSourceOf(ctx, tx, orgID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.migration_source_set", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"kind": src.Kind, "url": src.URL, "enabled": src.Enabled,
				"secret_given": req.ClientSecret != ""},
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrInvalidMigrationSource):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_migration_source", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("setting a migration source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, src)
}

// migrationSourceTestRequest is the account a test asks the source about.
type migrationSourceTestRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) verifier() *delegated.Verifier {
	if s.verify == nil {
		return delegated.New()
	}
	return s.verify
}

// hookClient is what a `hook` source's provider is called through.
func (s *Server) hookClient(timeout time.Duration) *http.Client {
	if s.outbound == nil {
		return safedial.Client(timeout)
	}
	return s.outbound(timeout)
}

// testMigrationSource asks the organisation's source whether a credential is
// correct, as a pending person's first sign-in does, and answers the step that
// failed (7.18): a wrong CA, template or client is seen before somebody's
// sign-in meets it. It changes nothing but the record that it ran: the
// outcome, never the username. The source is asked before the transaction
// opens, so a slow directory does not hold the version lock.
func (s *Server) testMigrationSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req migrationSourceTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_field",
			"detail": "username and password are the account the source is asked about"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	src, err := store.MigrationSourceToTest(ctx, s.db, s.root, orgID)
	switch {
	case errors.Is(err, store.ErrMigrationSourceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "migration_source_not_found"})
		return
	case err != nil:
		s.log.Error("loading a migration source to test", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var result delegated.Result
	if src.Kind == "hook" {
		result = store.TryPasswordProvider(ctx, s.db, s.root, s.hookClient, orgID, req.Username, req.Password)
	} else {
		result = s.verifier().Test(ctx, src, req.Username, req.Password)
	}

	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		return audit.Write(ctx, tx, audit.Event{Type: "admin.migration_source_tested",
			AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"ok": result.OK, "step": result.Step}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case err != nil:
		s.log.Error("recording a migration source test", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.OK, "step": result.Step, "detail": result.Detail,
		"config_version": version})
}

func (s *Server) deleteMigrationSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if err := store.RemoveMigrationSource(ctx, tx, orgID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.migration_source_removed", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, store.ErrMigrationSourceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "migration_source_not_found"})
		return
	case err != nil:
		s.log.Error("removing a migration source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
