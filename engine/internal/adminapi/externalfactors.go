package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// External factors (10.03), as `signari external-factor` registers them: the
// services an external_factor stage may ask. Read back with their keys counted
// rather than shown, as attesters are.

type externalFactorView struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Issuer    string    `json:"issuer"`
	AMR       []string  `json:"amr"`
	Keys      int       `json:"keys"`
	CreatedAt time.Time `json:"created_at"`
}

type putExternalFactorRequest struct {
	// URL is where the browser is sent, https, with `challenge` added.
	URL string `json:"url"`
	// Issuer is the iss its answers are signed as.
	Issuer string `json:"issuer"`
	// JWKS is its public key set.
	JWKS json.RawMessage `json:"jwks"`
	// AMR is the most it may claim to have proved.
	AMR []string `json:"amr"`
}

func (s *Server) listExternalFactors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.ExternalFactors(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing external factors", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]externalFactorView, 0, len(got))
	for _, f := range got {
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(f.JWKS, &set); err != nil {
			s.log.Error("reading an external factor's keys", "org_id", orgID, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, externalFactorView{Name: f.Name, URL: f.URL, Issuer: f.Issuer, AMR: f.AMR,
			Keys: len(set.Keys), CreatedAt: f.CreatedAt})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "external_factors": out})
}

func (s *Server) putExternalFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	var req putExternalFactorRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var keys int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if keys, err = store.SetExternalFactor(ctx, tx, orgID, store.ExternalFactor{
			Name: name, URL: req.URL, Issuer: req.Issuer, JWKS: req.JWKS, AMR: req.AMR}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.external_factor_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": name, "keys": keys, "amr": req.AMR}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrInvalidExternalFactor):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_external_factor", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("registering an external factor", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "keys": keys, "config_version": version})
}

func (s *Server) deleteExternalFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		removed, err := store.RemoveExternalFactor(ctx, tx, orgID, name)
		if err != nil {
			return err
		}
		if !removed {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.external_factor_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": name}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "external_factor_not_found"})
		return
	case errors.Is(err, store.ErrExternalFactorInUse):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "external_factor_in_use", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("removing an external factor", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
