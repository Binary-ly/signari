package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/store"
)

// An organisation's own appearance (10.09), worn over its instance's: what it
// leaves out falls through, and the four colours fall through together. Unlike the
// instance's brand, this is a tenant's to change, as nobody else's pages wear it.

type orgBrandView struct {
	OrgID            string `json:"org_id"`
	Branded          bool   `json:"branded"`
	ProductName      string `json:"product_name"`
	LogoURL          string `json:"logo_url"`
	SupportURL       string `json:"support_url"`
	ColourPrimary    string `json:"colour_primary"`
	ColourOnPrimary  string `json:"colour_on_primary"`
	ColourBackground string `json:"colour_background"`
	ColourText       string `json:"colour_text"`
}

func viewOrgBrand(orgID string, b *brand.Brand) orgBrandView {
	v := orgBrandView{OrgID: orgID}
	if b == nil {
		return v
	}
	v.Branded = true
	v.ProductName, v.LogoURL, v.SupportURL = b.ProductName, b.LogoURL, b.SupportURL
	v.ColourPrimary, v.ColourOnPrimary, v.ColourBackground, v.ColourText = b.Primary, b.OnPrimary, b.Background, b.Text
	return v
}

func (s *Server) getOrgBrand(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	b, err := store.OrgBrandOf(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading an organisation's brand", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, viewOrgBrand(orgID, b))
}

func (s *Server) putOrgBrand(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putBrandRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	b := &brand.Brand{ProductName: req.ProductName, LogoURL: req.LogoURL, SupportURL: req.SupportURL,
		Primary: req.ColourPrimary, OnPrimary: req.ColourOnPrimary, Background: req.ColourBackground, Text: req.ColourText}
	// The contrast check lives here too: a tenant's sign-in page is read by
	// the same people as anybody's.
	if err := b.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_brand", "detail": err.Error()})
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
		if err := store.SaveOrgBrand(ctx, tx, orgID, b); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.org_brand_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"product_name": b.ProductName,
				"logo": b.LogoURL != "", "support": b.SupportURL != "", "colours": b.Primary != ""}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case err != nil:
		s.log.Error("branding an organisation", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, struct {
		orgBrandView
		ConfigVersion int64 `json:"config_version"`
	}{viewOrgBrand(orgID, b), version})
}

func (s *Server) deleteOrgBrand(w http.ResponseWriter, r *http.Request) {
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
		removed, err := store.RemoveOrgBrand(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if !removed {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.org_brand_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_branded",
			"detail": "the organisation already wears its instance's appearance"})
		return
	case err != nil:
		s.log.Error("removing an organisation's brand", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
