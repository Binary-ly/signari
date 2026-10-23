package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Event subscriptions (6.07), as `signari events` manages them: where an
// organisation's recorded events are delivered, signed. A subscription's
// secret is shown once, when it is made or rotated, and never read back.

type subscriptionView struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	URL            string   `json:"url"`
	EventTypes     []string `json:"event_types"`
	Enabled        bool     `json:"enabled"`
	DisabledReason string   `json:"disabled_reason"`
	Delivered      int      `json:"delivered"`
	Outstanding    int      `json:"outstanding"`
}

// createSubscriptionRequest subscribes a URL to the event types named, or to
// every event of the organisation when none is.
type createSubscriptionRequest struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	EventTypes []string `json:"event_types"`
}

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.OrgSubscriptions(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing event subscriptions", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]subscriptionView, 0, len(got))
	for _, sub := range got {
		out = append(out, subscriptionView{ID: sub.ID, Name: sub.Name, URL: sub.URL, EventTypes: sub.EventTypes,
			Enabled: sub.Enabled, DisabledReason: sub.DisabledReason, Delivered: sub.Delivered,
			Outstanding: sub.Outstanding})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "subscriptions": out})
}

func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req createSubscriptionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name_required"})
		return
	}
	// Refused before anything is written: an event carries the shape of the
	// organisation, and a private destination is the engine posting into its
	// own network.
	if err := safedial.CheckURL(req.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_url", "detail": err.Error()})
		return
	}
	types := cleanList(req.EventTypes, false)
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var sub store.Subscription
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if sub, err = store.CreateSubscription(ctx, tx, s.root, orgID, req.Name, req.URL, types); err != nil {
			return err
		}
		// Never the secret.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.subscription_created", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"subscription": sub.ID, "name": req.Name, "event_types": types}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrUnknownEventType):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_event_type", "detail": err.Error()})
		return
	case err != nil && strings.Contains(err.Error(), "event_subscriptions_org_id_display_name_key"):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists",
			"detail": "the organisation has a subscription of that name"})
		return
	case err != nil:
		s.log.Error("creating an event subscription", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": sub.ID, "name": sub.DisplayName, "secret": sub.Secret,
		"config_version": version})
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	s.changeSubscription(w, r, "remove")
}

func (s *Server) rotateSubscriptionSecret(w http.ResponseWriter, r *http.Request) {
	s.changeSubscription(w, r, "rotate")
}

func (s *Server) enableSubscription(w http.ResponseWriter, r *http.Request) {
	s.changeSubscription(w, r, "enable")
}

func (s *Server) testSubscription(w http.ResponseWriter, r *http.Request) {
	s.changeSubscription(w, r, "test")
}

// changeSubscription removes, rotates the secret of, re-enables or sends a
// test delivery to the subscription the path names, as `signari events
// remove|rotate|enable|test` does.
func (s *Server) changeSubscription(w http.ResponseWriter, r *http.Request, action string) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	out := map[string]any{"name": name}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		switch action {
		case "remove":
			removed, err := store.RemoveSubscription(ctx, tx, orgID, name)
			if err != nil {
				return err
			}
			if !removed {
				return store.ErrSubscriptionUnknown
			}
			out["removed"] = true
			return audit.Write(ctx, tx, audit.Event{Type: "admin.subscription_removed", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"name": name}})
		case "rotate":
			secret, err := store.RotateSubscriptionSecret(ctx, tx, s.root, orgID, name)
			if err != nil {
				return err
			}
			out["secret"] = secret
			return audit.Write(ctx, tx, audit.Event{Type: "admin.subscription_secret_rotated",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{"name": name}})
		case "enable":
			if err := store.EnableSubscription(ctx, tx, orgID, name); err != nil {
				return err
			}
			out["enabled"] = true
			return audit.Write(ctx, tx, audit.Event{Type: "admin.subscription_enabled", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"name": name}})
		default:
			id, err := store.SendTestEvent(ctx, tx, orgID, name)
			if err != nil {
				return err
			}
			out["event_id"] = id
			return audit.Write(ctx, tx, audit.Event{Type: "admin.subscription_tested", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"name": name, "event_id": id}})
		}
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrSubscriptionUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "subscription_not_found"})
		return
	case err != nil:
		s.log.Error("changing an event subscription", "org_id", orgID, "action", action, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}
