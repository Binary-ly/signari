package adminapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Upstream identity providers (6.07), as `signari idp` configures them: the
// providers people sign in through, and the issuers whose assertions the
// jwt-bearer grant accepts. A provider is addressed by its slug, which is
// unique across the deployment because /login/with/<slug> names no
// organisation.

type identityProviderView struct {
	ID                     string           `json:"id"`
	Slug                   string           `json:"slug"`
	Name                   string           `json:"name"`
	Kind                   string           `json:"kind"`
	Issuer                 string           `json:"issuer"`
	Enabled                bool             `json:"enabled"`
	AllowSignup            bool             `json:"allow_signup"`
	AllowLinking           bool             `json:"allow_linking"`
	AllowAssertions        bool             `json:"allow_assertions"`
	TrustEmailVerification bool             `json:"trust_email_verification"`
	RequireVerifiedEmail   bool             `json:"require_verified_email"`
	MFAAMR                 []string         `json:"mfa_amr"`
	MFAACR                 []string         `json:"mfa_acr"`
	Linked                 int              `json:"linked"`
	AttributeMap           []map[string]any `json:"attribute_map"`
}

// patchIdentityProviderRequest is `idp enable|disable`, `idp assertions`,
// `idp verified-email` and `idp trust-mfa`: what is given changes.
type patchIdentityProviderRequest struct {
	Enabled                *bool     `json:"enabled"`
	AllowAssertions        *bool     `json:"allow_assertions"`
	TrustEmailVerification *bool     `json:"trust_email_verification"`
	RequireVerifiedEmail   *bool     `json:"require_verified_email"`
	MFAAMR                 *[]string `json:"mfa_amr"`
	MFAACR                 *[]string `json:"mfa_acr"`
}

type idpAttributeMapRequest struct {
	Claim     string `json:"claim"`
	Attribute string `json:"attribute"`
	Overwrite bool   `json:"overwrite"`
	MaxLength int    `json:"max_length"`
}

const idpRefusal = "change how anybody in the organisation may sign in through another provider"

func (s *Server) listIdentityProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.IdentityProviders(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing identity providers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]identityProviderView, 0, len(got))
	for _, p := range got {
		maps := make([]map[string]any, 0, len(p.AttributeMap))
		for _, m := range p.AttributeMap {
			maps = append(maps, map[string]any{"claim": m.Claim, "attribute": m.Attribute, "overwrite": m.Overwrite,
				"max_length": m.MaxLength})
		}
		out = append(out, identityProviderView{ID: p.ID, Slug: p.Slug, Name: p.Name, Kind: p.Kind, Issuer: p.Issuer,
			Enabled: p.Enabled, AllowSignup: p.AllowSignup, AllowLinking: p.AllowLinking,
			AllowAssertions: p.AllowAssertions, TrustEmailVerification: p.TrustEmailVerification,
			RequireVerifiedEmail: p.RequireVerifiedEmail, MFAAMR: p.MFAAMR, MFAACR: p.MFAACR, Linked: p.Linked,
			AttributeMap: maps})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "providers": out})
}

func (s *Server) patchIdentityProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchIdentityProviderRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	change := store.IdentityProviderChange{Enabled: req.Enabled, AllowAssertions: req.AllowAssertions,
		TrustEmailVerification: req.TrustEmailVerification, RequireVerifiedEmail: req.RequireVerifiedEmail}
	if req.MFAAMR != nil {
		l := cleanList(*req.MFAAMR, false)
		change.MFAAMR = &l
	}
	if req.MFAACR != nil {
		l := cleanList(*req.MFAACR, false)
		change.MFAACR = &l
	}
	if change.Empty() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change"})
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
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
		if err := store.ChangeIdentityProvider(ctx, tx, orgID, slug, change); err != nil {
			return err
		}
		detail := map[string]any{"provider": slug}
		if req.Enabled != nil {
			detail["enabled"] = *req.Enabled
		}
		if req.AllowAssertions != nil {
			detail["allow_assertions"] = *req.AllowAssertions
		}
		if req.TrustEmailVerification != nil {
			detail["trust_email_verification"] = *req.TrustEmailVerification
		}
		if req.RequireVerifiedEmail != nil {
			detail["require_verified_email"] = *req.RequireVerifiedEmail
		}
		if change.MFAAMR != nil {
			detail["mfa_amr"] = *change.MFAAMR
		}
		if change.MFAACR != nil {
			detail["mfa_acr"] = *change.MFAACR
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.identity_provider_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "config_version": version})
}

func (s *Server) putIdPAttributeMap(w http.ResponseWriter, r *http.Request) {
	var req idpAttributeMapRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.changeIdPAttributeMap(w, r, req, true)
}

func (s *Server) deleteIdPAttributeMap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeIdPAttributeMap(w, r, idpAttributeMapRequest{Claim: q.Get("claim"), Attribute: q.Get("attribute")}, false)
}

// changeIdPAttributeMap routes a claim from the provider into a declared
// local attribute, or stops it, as `signari idp attribute-map` does.
func (s *Server) changeIdPAttributeMap(w http.ResponseWriter, r *http.Request, req idpAttributeMapRequest, add bool) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	req.Claim, req.Attribute = strings.TrimSpace(req.Claim), strings.TrimSpace(req.Attribute)
	if req.Claim == "" || req.Attribute == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_mapping",
			"detail": "give claim and attribute"})
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
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
		detail := map[string]any{"provider": slug, "claim": req.Claim, "attribute": req.Attribute}
		if add {
			if err := store.SetIdPAttributeMap(ctx, tx, orgID, slug, req.Claim, req.Attribute, req.Overwrite,
				req.MaxLength); err != nil {
				return err
			}
			detail["overwrite"] = req.Overwrite
			return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_attribute_mapped", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: detail})
		}
		if err := store.RemoveIdPAttributeMap(ctx, tx, orgID, slug, req.Claim, req.Attribute); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_attribute_unmapped", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "claim": req.Claim, "attribute": req.Attribute,
		"mapped": add, "config_version": version})
}

// writeIdPFailure answers a refused or failed identity provider write, and
// reports whether it wrote anything.
func (s *Server) writeIdPFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, store.ErrIdPInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_identity_provider", "detail": err.Error()})
	case errors.Is(err, store.ErrProviderUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider_not_found"})
	case errors.Is(err, store.ErrIdPMappingUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mapping_not_found"})
	default:
		s.log.Error("writing an identity provider", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
