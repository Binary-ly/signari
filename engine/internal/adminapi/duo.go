package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/duo"
	"signari.dev/engine/internal/store"
)

// Duo as a second factor (6.07), as `signari duo set|enroll` configures it:
// the organisation's Duo application, checked against Duo before anything is
// stored and its secret sealed with the root key, and which Duo username each
// person has there. Removing a person's Duo factor is DELETE
// /admin/users/{userID}/factors/duo.

type duoView struct {
	OrgID      string `json:"org_id"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
	ClientID   string `json:"client_id"`
	APIHost    string `json:"api_host"`
	FailOpen   bool   `json:"fail_open"`
	Enrolled   int    `json:"enrolled"`
}

type putDuoRequest struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
	APIHost  string `json:"api_host"`
	// FailOpen lets people sign in without the second factor while Duo is
	// unreachable: whoever can stop one person's traffic to Duo has removed it.
	FailOpen bool `json:"fail_open"`
}

type enrollDuoRequest struct {
	DuoUsername string `json:"duo_username"`
}

func (s *Server) getDuo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	d, err := store.DuoIntegrationOf(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading the Duo integration", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, duoView{OrgID: orgID, Configured: d.Configured, Enabled: d.Enabled, ClientID: d.ClientID,
		APIHost: d.APIHost, FailOpen: d.FailOpen, Enrolled: d.Enrolled})
}

func (s *Server) putDuo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putDuoRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	cfg := &duo.Config{ClientID: strings.TrimSpace(req.ClientID), ClientSecret: req.Secret,
		APIHost: strings.TrimSpace(req.APIHost),
		// Not used by the check, and required by Validate.
		RedirectURI: "https://configured-at-runtime.invalid/login/duo/callback"}
	if err := cfg.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_duo", "detail": err.Error()})
		return
	}
	// The development stand-in the engine and the command honour, under the
	// same flag, so the three give one answer.
	if base := os.Getenv("SIGNARI_DUO_BASE_URL"); base != "" {
		if err := cfg.SetInsecureBaseURL(base, os.Getenv("SIGNARI_INSECURE_ISSUER") == "1"); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_duo", "detail": err.Error()})
			return
		}
	}
	// Before anything is stored, and outside the transaction: keys that do not
	// work would be a second factor nobody can present.
	if err := cfg.HealthCheck(ctx); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duo_check_failed",
			"detail": "Duo refused these keys or could not be reached; nothing was stored: " + err.Error()})
		return
	}
	sealed, err := s.root.Seal([]byte(req.Secret), "duo_secret")
	if err != nil {
		s.log.Error("sealing the Duo secret", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SetDuoIntegration(ctx, tx, orgID, cfg.ClientID, sealed, cfg.APIHost, req.FailOpen); err != nil {
			return err
		}
		// Never the secret.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.duo_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"client_id": cfg.ClientID, "api_host": cfg.APIHost,
				"fail_open": req.FailOpen}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("configuring Duo", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"org_id": orgID, "client_id": cfg.ClientID, "api_host": cfg.APIHost,
		"fail_open": req.FailOpen, "config_version": version})
}

var errDuoNotConfigured = errors.New("the organisation has no Duo integration")

func (s *Server) enrollDuo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	var req enrollDuoRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	// The name the person has IN DUO, which Duo returns and the sign-in is
	// checked against; frequently not their address.
	name := strings.TrimSpace(req.DuoUsername)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duo_username_required"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var orgID string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		d, err := store.DuoIntegrationOf(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if !d.Configured || !d.Enabled {
			return errDuoNotConfigured
		}
		if err := store.EnrollDuo(ctx, tx, userID, orgID, name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.duo_enrolled", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID})
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
	case errors.Is(err, errDuoNotConfigured):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duo_not_configured",
			"detail": "configure the organisation's Duo application first, or the enrolment would be a factor nobody can present"})
		return
	case err != nil:
		s.log.Error("enrolling a person in Duo", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "duo_username": name, "config_version": version})
}
