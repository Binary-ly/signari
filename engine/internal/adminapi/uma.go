package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/uma"
)

// UMA resource-owner intervention (6.07), as `signari uma` manages it: whether
// a refused request from an identified party waits for a decision, how often
// its client polls, and the decisions. Approving grants a relation in the
// authorization model, so it is an organisation's write.

type umaSettingsView struct {
	OrgID             string `json:"org_id"`
	OwnerIntervention bool   `json:"owner_intervention"`
	PollIntervalS     int    `json:"poll_interval_s"`
}

// putUMASettingsRequest sets both; a poll interval of 0 is the command's 30s.
type putUMASettingsRequest struct {
	OwnerIntervention bool `json:"owner_intervention"`
	PollIntervalS     int  `json:"poll_interval_s"`
}

type umaRequestView struct {
	ID              string           `json:"id"`
	ClientID        string           `json:"client_id"`
	ResourceServer  string           `json:"resource_server"`
	RequestingParty string           `json:"requesting_party"`
	Permissions     []uma.Permission `json:"permissions"`
	// Relations would each let the whole request through if granted.
	Relations []string  `json:"relations"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type approveUMARequest struct {
	Relation string `json:"relation"`
}

// decider is the person deciding, recorded on the request; none for a token.
func decider(ctx context.Context) string {
	if p, ok := principalFrom(ctx); ok {
		return p.UserID
	}
	return ""
}

func (s *Server) getUMASettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.LoadUMASettings(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading UMA settings", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, umaSettingsView{OrgID: orgID, OwnerIntervention: got.OwnerIntervention,
		PollIntervalS: seconds(got.PollInterval)})
}

func (s *Server) putUMASettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putUMASettingsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.PollIntervalS == 0 {
		req.PollIntervalS = 30
	}
	settings := store.UMASettings{OwnerIntervention: req.OwnerIntervention, PollInterval: secondsOf(req.PollIntervalS)}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SetUMASettings(ctx, tx, orgID, settings); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.uma_settings_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"owner_intervention": req.OwnerIntervention,
				"poll_interval_s": req.PollIntervalS}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrUMAPollInterval):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_poll_interval", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("setting UMA settings", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"org_id": orgID, "owner_intervention": req.OwnerIntervention,
		"poll_interval_s": req.PollIntervalS, "config_version": version})
}

func (s *Server) listUMARequests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	pending, err := store.ListPendingRequests(ctx, s.db, orgID)
	var model interface {
		RelationsFor(objectType, action string) ([]string, bool)
	}
	if err == nil {
		m, merr := store.LoadModel(ctx, s.db, orgID)
		err = merr
		if m != nil {
			model = m
		}
	}
	if err != nil {
		s.log.Error("listing UMA requests", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]umaRequestView, 0, len(pending))
	for _, p := range pending {
		who := p.RequestingPartyEmail
		if who == "" {
			who = p.RequestingParty
		}
		relations := []string{}
		if model != nil {
			relations = store.UMACandidateRelations(model, p)
		}
		out = append(out, umaRequestView{ID: p.ID, ClientID: p.ClientID, ResourceServer: p.ResourceServer,
			RequestingParty: who, Permissions: p.Permissions, Relations: relations,
			CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "requests": out})
}

func (s *Server) approveUMA(w http.ResponseWriter, r *http.Request) {
	orgID, requestID := r.PathValue("orgID"), r.PathValue("requestID")
	var req approveUMARequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	s.decideUMA(w, r, orgID, requestID, req.Relation, true)
}

func (s *Server) denyUMA(w http.ResponseWriter, r *http.Request) {
	s.decideUMA(w, r, r.PathValue("orgID"), r.PathValue("requestID"), "", false)
}

func (s *Server) decideUMA(w http.ResponseWriter, r *http.Request, orgID, requestID, relation string, approve bool) {
	ctx := r.Context()
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if approve {
			p, err := store.ApproveUMARequest(ctx, tx, orgID, requestID, relation, decider(ctx))
			if err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Event{Type: "admin.uma_request_approved", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, ClientID: p.ClientID, Detail: map[string]any{"request_id": requestID,
					"relation": relation, "resources": len(p.Permissions)}})
		}
		if err := store.DenyUMARequest(ctx, tx, orgID, requestID, decider(ctx)); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.uma_request_denied", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"request_id": requestID}})
	})
	var rel store.UMARelationError
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrPendingUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_not_found"})
		return
	case errors.Is(err, store.ErrUMADecided):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_decided", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrUMANoModel):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no_authorization_model", "detail": err.Error()})
		return
	case errors.As(err, &rel):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "relation_does_not_satisfy",
			"detail": rel.Error(), "relations": rel.Candidates})
		return
	case err != nil:
		s.log.Error("deciding a UMA request", "org_id", orgID, "request_id", requestID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	state := "denied"
	if approve {
		state = "approved"
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": requestID, "state": state, "config_version": version})
}
