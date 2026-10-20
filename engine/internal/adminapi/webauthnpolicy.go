package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// An organisation's authenticator policy: what attestation to ask for, which
// models are accepted, and whether a copied authenticator is refused.
//
// The CLI was the only way to set it, so the console, Terraform and anything
// else on this API could neither read nor change which devices an
// organisation trusts. The same store.SetWebAuthnPolicy writes it either way.

type webauthnPolicyBody struct {
	Attestation   string   `json:"attestation"`
	AllowedModels []string `json:"allowed_aaguids"`
	// RefuseCloned is a pointer so an absent field means the default, on,
	// rather than false.
	RefuseCloned *bool `json:"refuse_cloned"`
	// The ceremony (migration 0170). A field left out takes its default, as
	// the whole policy is written each time.
	UserVerification string   `json:"user_verification"`
	ResidentKey      string   `json:"resident_key"`
	Attachment       string   `json:"attachment"`
	Algorithms       []int    `json:"algorithms"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	Hints            []string `json:"hints"`
}

func (s *Server) getWebAuthnPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	p, err := store.LoadWebAuthnPolicy(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading the WebAuthn policy", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, policyJSON(p))
}

func (s *Server) putWebAuthnPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req webauthnPolicyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	want := store.WebAuthnPolicy{Conveyance: req.Attestation, AllowedAAGUIDs: req.AllowedModels,
		RefuseCloned:     req.RefuseCloned == nil || *req.RefuseCloned,
		UserVerification: req.UserVerification, ResidentKey: req.ResidentKey, Attachment: req.Attachment,
		Algorithms: req.Algorithms, TimeoutSeconds: req.TimeoutSeconds, Hints: req.Hints}
	if want.Conveyance == "" {
		want.Conveyance = "none"
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var saved store.WebAuthnPolicy
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		var err error
		if saved, err = store.SetWebAuthnPolicy(ctx, tx, orgID, want); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.webauthn_policy_set", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: policyJSON(saved),
		})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, store.ErrInvalidWebAuthnPolicy):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("setting the WebAuthn policy", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out := policyJSON(saved)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}

func policyJSON(p store.WebAuthnPolicy) map[string]any {
	ids := p.AllowedAAGUIDs
	if ids == nil {
		ids = []string{}
	}
	return map[string]any{"attestation": p.Conveyance, "allowed_aaguids": ids, "refuse_cloned": p.RefuseCloned,
		"user_verification": p.UserVerification, "resident_key": p.ResidentKey, "attachment": p.Attachment,
		"algorithms": p.Algorithms, "timeout_seconds": p.TimeoutSeconds, "hints": p.Hints}
}
