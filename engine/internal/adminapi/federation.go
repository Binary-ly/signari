package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
)

// OpenID Federation (6.07), as `signari federation enable` and `signari
// trust-mark` act: an instance's membership of a federation, the Trust Marks
// it issues and revokes as an accreditation authority, and the ones others
// granted it, which its Entity Configuration publishes. An instance spans
// organisations, so only a deployment-wide token acts on one.

type federationView struct {
	InstanceID       string   `json:"instance_id"`
	EntityID         string   `json:"entity_id"`
	Enabled          bool     `json:"enabled"`
	AuthorityHints   []string `json:"authority_hints"`
	TrustAnchorHints []string `json:"trust_anchor_hints"`
	OrganizationName string   `json:"organization_name"`
	HomepageURI      string   `json:"homepage_uri"`
	Contacts         []string `json:"contacts"`
	LifetimeSeconds  int      `json:"lifetime_s"`
}

// putFederationRequest is `federation enable`'s flags. A list left out keeps
// what is set, and an empty one clears it; authority_hints are required.
type putFederationRequest struct {
	AuthorityHints   []string  `json:"authority_hints"`
	OrganizationName string    `json:"organization_name"`
	HomepageURI      string    `json:"homepage_uri"`
	TrustAnchorHints *[]string `json:"trust_anchor_hints"`
	Contacts         *[]string `json:"contacts"`
	LifetimeSeconds  *int      `json:"lifetime_s"`
}

type issueTrustMarkRequest struct {
	Type       string `json:"type"`
	Subject    string `json:"subject"`
	LogoURI    string `json:"logo_uri"`
	Ref        string `json:"ref"`
	Delegation string `json:"delegation"`
	// LifetimeSeconds is 0 for a mark with no exp, which §7.1 permits.
	LifetimeSeconds int `json:"lifetime_s"`
}

type revokeTrustMarkRequest struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

type acceptTrustMarkRequest struct {
	TrustMark string `json:"trust_mark"`
}

type delegateRequest struct {
	Type            string `json:"type"`
	Delegate        string `json:"delegate"`
	Ref             string `json:"ref"`
	LifetimeSeconds int    `json:"lifetime_s"`
}

type issuedTrustMarkView struct {
	Type      string     `json:"type"`
	Subject   string     `json:"subject"`
	Status    string     `json:"status"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	Reason    string     `json:"reason"`
}

type heldTrustMarkView struct {
	Type      string     `json:"type"`
	Issuer    string     `json:"issuer"`
	Published bool       `json:"published"`
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// federationInstance answers for a request that is not deployment-wide or
// names no instance, and otherwise gives the instance's Entity Identifier.
func (s *Server) federationInstance(w http.ResponseWriter, r *http.Request) (instanceID, entityID string, ok bool) {
	ctx := r.Context()
	if !deploymentWide(w, ctx) {
		return "", "", false
	}
	instanceID = r.PathValue("instanceID")
	issuer, found, err := store.InstanceIssuer(ctx, s.db, instanceID)
	switch {
	case err != nil:
		s.log.Error("reading an instance", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return "", "", false
	case !found:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance_not_found"})
		return "", "", false
	}
	return instanceID, issuer, true
}

func (s *Server) getFederation(w http.ResponseWriter, r *http.Request) {
	instanceID, entityID, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	out := federationView{InstanceID: instanceID, EntityID: entityID, AuthorityHints: []string{},
		TrustAnchorHints: []string{}, Contacts: []string{}}
	// No row is the ordinary case: this instance is in no federation.
	if cfg, err := store.FederationConfig(r.Context(), s.db, instanceID); err == nil {
		out.Enabled, out.OrganizationName, out.HomepageURI = true, cfg.OrganizationName, cfg.HomepageURI
		out.LifetimeSeconds = cfg.LifetimeSeconds
		out.AuthorityHints = append(out.AuthorityHints, cfg.AuthorityHints...)
		out.TrustAnchorHints = append(out.TrustAnchorHints, cfg.TrustAnchorHints...)
		out.Contacts = append(out.Contacts, cfg.Contacts...)
	}
	s.writeList(w, r, out)
}

func (s *Server) putFederation(w http.ResponseWriter, r *http.Request) {
	instanceID, entityID, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req putFederationRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	change := store.FederationChange{AuthorityHints: cleanList(req.AuthorityHints, false),
		OrganizationName: strings.TrimSpace(req.OrganizationName), HomepageURI: strings.TrimSpace(req.HomepageURI)}
	if req.TrustAnchorHints != nil {
		l := cleanList(*req.TrustAnchorHints, false)
		change.TrustAnchorHints = &l
	}
	if req.Contacts != nil {
		l := cleanList(*req.Contacts, false)
		change.Contacts = &l
	}
	if req.LifetimeSeconds != nil {
		d := time.Duration(*req.LifetimeSeconds) * time.Second
		change.Lifetime = &d
	}
	if err := change.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_federation", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var generated string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		if generated, err = store.EnableFederation(ctx, tx, s.root, instanceID, entityID, change); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.federation_enabled", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "authority_hints": change.AuthorityHints,
				"generated_key": generated}})
	})
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	// The Entity Configuration's route is registered when serve starts, so
	// the first enable is served after a restart; a later change is read on
	// the next request.
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instanceID, "entity_id": entityID,
		"generated_key": generated, "restart_required": generated != "", "config_version": version})
}

func (s *Server) listTrustMarks(w http.ResponseWriter, r *http.Request) {
	instanceID, entityID, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	issued, err := store.ListIssuedTrustMarks(ctx, s.db, instanceID)
	var held []*store.HeldTrustMark
	if err == nil {
		held, err = store.ListHeldTrustMarks(ctx, s.db, instanceID)
	}
	if err != nil {
		s.log.Error("listing trust marks", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	now := time.Now()
	optional := func(t time.Time) *time.Time {
		if t.IsZero() || t.Unix() == 0 {
			return nil
		}
		return &t
	}
	issuedOut := make([]issuedTrustMarkView, 0, len(issued))
	for _, m := range issued {
		issuedOut = append(issuedOut, issuedTrustMarkView{Type: m.Type, Subject: m.Subject, Status: m.StatusAt(now),
			IssuedAt: m.IssuedAt, ExpiresAt: optional(m.ExpiresAt), RevokedAt: optional(m.RevokedAt), Reason: m.Reason})
	}
	heldOut := make([]heldTrustMarkView, 0, len(held))
	for _, m := range held {
		// An expired mark is kept and not published, so a lapse is seen
		// rather than vanishing from the document.
		heldOut = append(heldOut, heldTrustMarkView{Type: m.Type, Issuer: m.Issuer, AddedAt: m.AddedAt,
			ExpiresAt: optional(m.ExpiresAt), Published: m.ExpiresAt.IsZero() || m.ExpiresAt.After(now)})
	}
	s.writeList(w, r, map[string]any{"instance_id": instanceID, "entity_id": entityID, "issued": issuedOut,
		"held": heldOut})
}

func (s *Server) issueTrustMark(w http.ResponseWriter, r *http.Request) {
	instanceID, entityID, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req issueTrustMarkRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var signed string
	var tm *oidfed.TrustMark
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		signed, tm, err = store.IssueSignedTrustMark(ctx, tx, s.root, instanceID, entityID, oidfed.TrustMarkParams{
			Subject: strings.TrimSpace(req.Subject), Type: strings.TrimSpace(req.Type),
			Lifetime: time.Duration(req.LifetimeSeconds) * time.Second, LogoURI: req.LogoURI, Ref: req.Ref,
			Delegation: strings.TrimSpace(req.Delegation)}, time.Now())
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.trust_mark_issued", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "type": tm.Type, "subject": tm.Subject,
				"expires": tm.Expiry != 0}})
	})
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	out := map[string]any{"type": tm.Type, "subject": tm.Subject, "trust_mark": signed, "expires_at": nil,
		"config_version": version}
	if tm.Expiry != 0 {
		out["expires_at"] = time.Unix(tm.Expiry, 0).UTC()
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) revokeTrustMark(w http.ResponseWriter, r *http.Request) {
	instanceID, _, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req revokeTrustMarkRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "revoked by an operator"
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := store.RevokeTrustMark(ctx, tx, instanceID, req.Type, req.Subject, reason); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.trust_mark_revoked", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "type": req.Type, "subject": req.Subject,
				"reason": reason}})
	})
	if errors.Is(err, store.ErrTrustMarkUnknown) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "trust_mark_not_found",
			"detail": "this entity has no active trust mark of that type for that subject"})
		return
	}
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	// Readers learn of it from the status endpoint (§8.4); the subject keeps
	// publishing its copy, and nothing in the protocol tells it.
	writeJSON(w, http.StatusOK, map[string]any{"type": req.Type, "subject": req.Subject, "revoked": true,
		"config_version": version})
}

func (s *Server) acceptTrustMark(w http.ResponseWriter, r *http.Request) {
	instanceID, entityID, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req acceptTrustMarkRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var tm *oidfed.TrustMark
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		if tm, err = store.AcceptTrustMark(ctx, tx, instanceID, entityID, strings.TrimSpace(req.TrustMark),
			time.Now()); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.trust_mark_accepted", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "type": tm.Type, "issuer": tm.Issuer}})
	})
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"type": tm.Type, "issuer": tm.Issuer, "published": true,
		"config_version": version})
}

func (s *Server) dropTrustMark(w http.ResponseWriter, r *http.Request) {
	instanceID, _, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	markType, issuer := r.URL.Query().Get("type"), r.URL.Query().Get("issuer")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := store.RemoveHeldTrustMark(ctx, tx, instanceID, markType, issuer); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.trust_mark_dropped", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "type": markType, "issuer": issuer}})
	})
	if errors.Is(err, store.ErrTrustMarkUnknown) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "trust_mark_not_found",
			"detail": "this entity holds no trust mark of that type from that issuer"})
		return
	}
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"type": markType, "issuer": issuer, "removed": true,
		"config_version": version})
}

func (s *Server) delegateTrustMark(w http.ResponseWriter, r *http.Request) {
	instanceID, entityID, ok := s.federationInstance(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var req delegateRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var signed string
	// Nothing is stored: the delegate presents the delegation with the marks
	// it issues. The record is the audit event.
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var err error
		if signed, err = store.SignDelegation(ctx, tx, s.root, instanceID, entityID, oidfed.DelegationParams{
			Delegate: strings.TrimSpace(req.Delegate), Type: strings.TrimSpace(req.Type),
			Lifetime: time.Duration(req.LifetimeSeconds) * time.Second, Ref: req.Ref}, time.Now()); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.trust_mark_delegated", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "type": req.Type, "delegate": req.Delegate}})
	})
	if s.writeFederationFailure(w, err, instanceID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"type": req.Type, "delegate": req.Delegate,
		"delegation": signed, "config_version": version})
}

// writeFederationFailure answers a refused or failed federation write, and
// reports whether it wrote anything.
func (s *Server) writeFederationFailure(w http.ResponseWriter, err error, instanceID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case errors.Is(err, store.ErrFederationRefused):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "federation_refused", "detail": err.Error()})
	case errors.Is(err, store.ErrNoFederationKey):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "federation_not_enabled",
			"detail": "this instance has no federation signing key; enable federation first"})
	default:
		s.log.Error("writing federation configuration", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}

// decodeStrict reads a JSON body refusing unknown fields, and answers when
// it will not.
func decodeStrict(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return false
	}
	return true
}
