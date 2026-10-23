package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/store"
)

// Extension providers (6.07), as `signari provider` registers them: an
// operator's own service consulted at a named hook (ADR-011). A provider's
// signing secret is shown once, when it is first registered or rotated, and
// never read back.

type providerView struct {
	ID            string   `json:"id"`
	Hook          string   `json:"hook"`
	URL           string   `json:"url"`
	Mode          string   `json:"mode"`
	TimeoutMS     int      `json:"timeout_ms"`
	Enabled       bool     `json:"enabled"`
	Signed        bool     `json:"signed"`
	Called        bool     `json:"called"`
	AllowedClaims []string `json:"allowed_claims"`
}

// putProviderRequest registers or replaces the provider for the hook the path
// names. Mode has no default, as on the command line: an authorization hook
// that fails open stops enforcing exactly when something is wrong, and a
// claims hook that fails closed locks everybody out because a directory was
// slow.
type putProviderRequest struct {
	URL       string `json:"url"`
	Mode      string `json:"mode"`
	TimeoutMS int    `json:"timeout_ms"`
}

type providerClaimsRequest struct {
	Claims []string `json:"claims"`
}

// defaultProviderTimeout is what `signari provider add` waits without
// -provider-timeout.
const defaultProviderTimeout = 2 * time.Second

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.ListProviders(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing providers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]providerView, 0, len(got))
	for _, p := range got {
		out = append(out, providerView{ID: p.ID, Hook: p.Hook, URL: p.URL, Mode: p.Mode,
			TimeoutMS: int(p.Timeout / time.Millisecond), Enabled: p.Enabled, Signed: p.Signed,
			Called: provider.Hook(p.Hook).Called(), AllowedClaims: p.AllowedClaims})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "providers": out})
}

// narrowedTokenRefused answers a token narrowed to named applications or
// groups, for a change that acts on applications and people the token never
// names: a provider is consulted on every sign-in or token in the
// organisation, and an outpost verifies anybody's password.
func narrowedTokenRefused(w http.ResponseWriter, r *http.Request, detail string) bool {
	ctx := r.Context()
	if clientFilter(ctx) == nil && groupFilter(ctx) == nil {
		return false
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_objects",
		"detail": "a token limited to named applications or groups cannot " + detail})
	return true
}

const providerRefusal = "change a decision every sign-in in the organisation passes through"

func (s *Server) putProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, hook := r.PathValue("orgID"), r.PathValue("hook")
	var req putProviderRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	timeout := defaultProviderTimeout
	if req.TimeoutMS != 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	p := provider.Provider{Name: "provider-" + hook, Hook: provider.Hook(hook), URL: strings.TrimSpace(req.URL),
		Mode: provider.Mode(req.Mode), Timeout: timeout}
	// Checked before anything is written, so a refusal names the request and
	// not the write: an unknown hook, a missing mode, a timeout above the
	// ceiling, a URL the outbound dialer would refuse.
	if err := p.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_provider", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, providerRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var id, secret string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if id, secret, err = store.SaveProvider(ctx, tx, s.root, orgID, p); err != nil {
			return err
		}
		// Never the secret.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.provider_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"provider": id, "hook": hook, "url": p.URL, "mode": req.Mode,
				"timeout_ms": int(timeout / time.Millisecond), "secret_minted": secret != ""}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("registering a provider", "org_id", orgID, "hook", hook, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	// secret is empty when a registration was replaced: the provider keeps the
	// one it holds, so changing a timeout does not break a provider that checks
	// signatures.
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "hook": hook, "secret": secret,
		"called": p.Hook.Called(), "config_version": version})
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request) {
	s.changeProvider(w, r, "remove", nil)
}

func (s *Server) rotateProviderSecret(w http.ResponseWriter, r *http.Request) {
	s.changeProvider(w, r, "rotate", nil)
}

func (s *Server) putProviderClaims(w http.ResponseWriter, r *http.Request) {
	var req providerClaimsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	s.changeProvider(w, r, "claims", cleanList(req.Claims, false))
}

// changeProvider removes, rotates the secret of, or sets the claims a token
// hook may add for the provider the path names, as `signari provider
// remove|rotate|claims` does.
func (s *Server) changeProvider(w http.ResponseWriter, r *http.Request, action string, claims []string) {
	ctx := r.Context()
	orgID, hook := r.PathValue("orgID"), provider.Hook(r.PathValue("hook"))
	if !hook.Known() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider_not_found",
			"detail": "no hook of that name is consulted"})
		return
	}
	if narrowedTokenRefused(w, r, providerRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	out := map[string]any{"hook": string(hook)}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		switch action {
		case "remove":
			removed, err := store.DeleteProvider(ctx, tx, orgID, hook)
			if err != nil {
				return err
			}
			if !removed {
				return store.ErrProviderNotRegistered
			}
			out["removed"] = true
			return audit.Write(ctx, tx, audit.Event{Type: "admin.provider_removed", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"hook": string(hook)}})
		case "rotate":
			secret, err := store.RotateProviderSecret(ctx, tx, s.root, orgID, hook)
			if err != nil {
				return err
			}
			out["secret"] = secret
			return audit.Write(ctx, tx, audit.Event{Type: "admin.provider_secret_rotated",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{"hook": string(hook)}})
		default:
			if err := store.SetProviderClaims(ctx, tx, orgID, hook, claims); err != nil {
				return err
			}
			out["allowed_claims"] = claims
			return audit.Write(ctx, tx, audit.Event{Type: "admin.provider_claims_set", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"hook": string(hook), "allowed_claims": claims}})
		}
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrProviderNotRegistered):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider_not_found", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrProtocolClaim):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol_claim", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("changing a provider", "org_id", orgID, "hook", hook, "action", action, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}
