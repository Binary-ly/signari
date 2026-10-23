package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// An instance's signing keys (6.07), as `signari keys list|rotate|retire`
// manage them: never their private halves, and each step of rotation the safe
// one for now. The keys sign for every organisation of the instance, so only a
// deployment-wide token reads or rotates them.

type signingKeyView struct {
	KID         string     `json:"kid"`
	Algorithm   string     `json:"algorithm"`
	State       string     `json:"state"`
	PublishedAt time.Time  `json:"published_at"`
	DemotedAt   *time.Time `json:"demoted_at"`
	// RetirableInS, for a passive key, is how long until it may leave the
	// published set; 0 once it may.
	RetirableInS *int `json:"retirable_in_s,omitempty"`
}

type rotateKeysRequest struct {
	// Algorithm rotates only that one; every one in use when empty.
	Algorithm string `json:"algorithm"`
	// PromoteNow promotes a published key before its publication wait is
	// over: right for a compromised key, and relying parties whose key cache
	// predates it reject its signatures until they refresh.
	PromoteNow bool `json:"promote_now"`
}

type rotationStepView struct {
	Algorithm string `json:"algorithm"`
	Published string `json:"published,omitempty"`
	Promoted  string `json:"promoted,omitempty"`
	Demoted   string `json:"demoted,omitempty"`
	Forced    bool   `json:"forced,omitempty"`
	// WaitS is how long until the published key may be promoted, when nothing
	// was.
	WaitS int `json:"wait_s,omitempty"`
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceID := r.PathValue("instanceID")
	if !deploymentWide(w, ctx) {
		return
	}
	exists, err := store.InstanceExists(ctx, s.db, instanceID)
	if err == nil && !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance_not_found"})
		return
	}
	var set *keys.Set
	var dwell time.Duration
	if err == nil {
		set, err = keys.LoadSet(ctx, s.db, instanceID, s.root)
	}
	if err == nil {
		dwell, _, err = keys.RequiredPassiveDwell(ctx, s.db, instanceID)
	}
	if err != nil {
		s.log.Error("listing signing keys", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	waits := map[string]int{}
	for _, p := range keys.PassiveKeys(set, dwell) {
		if !p.Undated {
			waits[p.Key.KID()] = seconds(p.Wait)
		}
	}
	out := []signingKeyView{}
	for _, k := range set.Keys() {
		v := signingKeyView{KID: k.KID(), Algorithm: string(k.Algorithm()), State: string(k.State()),
			PublishedAt: k.PublishedAt()}
		if d := k.DemotedAt(); !d.IsZero() {
			v.DemotedAt = &d
		}
		if wait, ok := waits[k.KID()]; ok {
			v.RetirableInS = &wait
		}
		out = append(out, v)
	}
	s.writeList(w, r, map[string]any{"instance_id": instanceID, "keys": out})
}

func (s *Server) rotateSigningKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceID := r.PathValue("instanceID")
	var req rotateKeysRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if !deploymentWide(w, ctx) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var steps []keys.Step
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		exists, err := store.InstanceExists(ctx, tx, instanceID)
		if err != nil {
			return err
		}
		if !exists {
			return store.ErrInstanceUnknown
		}
		steps, err = keys.Rotate(ctx, tx, instanceID, s.root, keys.Algorithm(strings.TrimSpace(req.Algorithm)),
			req.PromoteNow, "admin_api")
		if err != nil {
			return err
		}
		// Each step is recorded as keys.rotated; this says who asked.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.signing_keys_rotated", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "steps": len(steps), "promote_now": req.PromoteNow}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrInstanceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance_not_found"})
		return
	case errors.Is(err, keys.ErrNotRotatable):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot_rotate", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("rotating signing keys", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out := make([]rotationStepView, 0, len(steps))
	for _, st := range steps {
		out = append(out, rotationStepView{Algorithm: string(st.Algorithm), Published: st.Published,
			Promoted: st.Promoted, Demoted: st.Demoted, Forced: st.Forced, WaitS: seconds(st.Wait)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instanceID, "steps": out, "config_version": version})
}

func (s *Server) retireSigningKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceID := r.PathValue("instanceID")
	if !deploymentWide(w, ctx) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var retired []keys.Key
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		exists, err := store.InstanceExists(ctx, tx, instanceID)
		if err != nil {
			return err
		}
		if !exists {
			return store.ErrInstanceUnknown
		}
		retired, err = keys.RetireDue(ctx, tx, instanceID, s.root, "admin_api")
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.signing_keys_retired", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "retired": len(retired)}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, store.ErrInstanceUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance_not_found"})
		return
	case err != nil:
		s.log.Error("retiring signing keys", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	kids := make([]string, 0, len(retired))
	for _, k := range retired {
		kids = append(kids, k.KID())
	}
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instanceID, "retired": kids, "config_version": version})
}
