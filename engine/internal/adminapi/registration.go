package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Dynamic client registration (RFC 7591), as `signari registration` manages
// it (6.07): whether /oauth2/register is on and for whom, and the initial
// access tokens that let a caller register when it is not open.

type registrationView struct {
	OrgID             string   `json:"org_id"`
	Enabled           bool     `json:"enabled"`
	Open              bool     `json:"open"`
	MaxClients        int      `json:"max_clients"`
	AllowedScopes     []string `json:"allowed_scopes"`
	AllowConfidential bool     `json:"allow_confidential"`
}

func viewRegistration(orgID string, p *store.RegistrationPolicy) registrationView {
	v := registrationView{OrgID: orgID, Enabled: p.Enabled, Open: p.Open, MaxClients: p.MaxClients,
		AllowedScopes: p.AllowedScopes, AllowConfidential: p.AllowConfidential}
	if v.AllowedScopes == nil {
		v.AllowedScopes = []string{}
	}
	return v
}

// putRegistrationRequest turns registration on with the whole policy, so
// confidential registration and openness are off unless asked for each time.
type putRegistrationRequest struct {
	Open              bool     `json:"open"`
	MaxClients        int      `json:"max_clients"`
	AllowedScopes     []string `json:"allowed_scopes"`
	AllowConfidential bool     `json:"allow_confidential"`
}

type registrationTokenView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Remaining *int       `json:"remaining"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	CreatedAt time.Time  `json:"created_at"`
}

type createRegistrationTokenRequest struct {
	Name string `json:"name"`
	// Uses 0 is unlimited.
	Uses int `json:"uses"`
	// ExpiresInS 0 is never.
	ExpiresInS int `json:"expires_in_s"`
}

func (s *Server) getRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	p, err := store.LoadRegistrationPolicy(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading the registration policy", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, viewRegistration(orgID, p))
}

func (s *Server) putRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putRegistrationRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.MaxClients < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy",
			"detail": "max_clients is how many clients registration may make, 0 for the default"})
		return
	}
	// Registrants make applications this token never names.
	if clientFilter(ctx) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_clients",
			"detail": "a token limited to named applications cannot let others register new ones"})
		return
	}
	policy := store.RegistrationPolicy{Open: req.Open, MaxClients: req.MaxClients,
		AllowedScopes: cleanList(req.AllowedScopes, false), AllowConfidential: req.AllowConfidential}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var after *store.RegistrationPolicy
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SetRegistrationPolicy(ctx, tx, orgID, policy); err != nil {
			return err
		}
		var err error
		if after, err = store.LoadRegistrationPolicy(ctx, tx, orgID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.registration_policy_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"open": after.Open, "max_clients": after.MaxClients,
				"allowed_scopes": after.AllowedScopes, "allow_confidential": after.AllowConfidential}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("setting the registration policy", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, struct {
		registrationView
		ConfigVersion int64 `json:"config_version"`
	}{viewRegistration(orgID, after), version})
}

func (s *Server) deleteRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		was, err := store.DisableRegistration(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if !was {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.registration_disabled", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "registration_off",
			"detail": "dynamic registration is already off"})
		return
	case err != nil:
		s.log.Error("turning registration off", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}

func (s *Server) listRegistrationTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	tokens, err := store.RegistrationTokens(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing registration tokens", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]registrationTokenView, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, registrationTokenView{ID: t.ID, Name: t.Name, Remaining: t.Remaining,
			ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, CreatedAt: t.CreatedAt})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "registration_tokens": out})
}

func (s *Server) createRegistrationToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req createRegistrationTokenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || req.Uses < 0 || req.ExpiresInS < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_token_request",
			"detail": "a name, and uses and expires_in_s of 0 (unlimited, never) or more"})
		return
	}
	if clientFilter(ctx) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_clients",
			"detail": "a token limited to named applications cannot let others register new ones"})
		return
	}
	var expires *time.Time
	if req.ExpiresInS > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInS) * time.Second)
		expires = &t
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var secret, id string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if secret, id, err = store.NewRegistrationToken(ctx, tx, orgID, req.Name, req.Uses, expires); err != nil {
			return err
		}
		// Never the secret.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.registration_token_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"token_id": id, "name": req.Name, "uses": req.Uses,
				"expires_in_s": req.ExpiresInS}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("minting a registration token", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "token": secret, "config_version": version})
}

func (s *Server) revokeRegistrationToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, tokenID := r.PathValue("orgID"), r.PathValue("tokenID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		revoked, err := store.RevokeRegistrationToken(ctx, tx, orgID, tokenID)
		if err != nil {
			return err
		}
		if !revoked {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.registration_token_revoked", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"token_id": tokenID}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "registration_token_not_found",
			"detail": "no unrevoked registration token with that id in the organisation"})
		return
	case err != nil:
		s.log.Error("revoking a registration token", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
