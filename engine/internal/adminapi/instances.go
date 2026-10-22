package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/store"
)

// Instances and their appearance (6.07). An instance is an issuer, and every
// organisation under it shares it, so these are read and changed by a
// deployment-wide caller only: a tenant's token that could see the other
// issuers, or brand a host its neighbours sign in at, has left its tenancy.

type instanceView struct {
	ID          string    `json:"id"`
	Issuer      string    `json:"issuer"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
}

type brandView struct {
	InstanceID       string `json:"instance_id"`
	Branded          bool   `json:"branded"`
	ProductName      string `json:"product_name"`
	LogoURL          string `json:"logo_url"`
	SupportURL       string `json:"support_url"`
	ColourPrimary    string `json:"colour_primary"`
	ColourOnPrimary  string `json:"colour_on_primary"`
	ColourBackground string `json:"colour_background"`
	ColourText       string `json:"colour_text"`
}

// putBrandRequest replaces the instance's appearance; a field left out is the
// built-in one. Colours are all four or none.
type putBrandRequest struct {
	ProductName      string `json:"product_name"`
	LogoURL          string `json:"logo_url"`
	SupportURL       string `json:"support_url"`
	ColourPrimary    string `json:"colour_primary"`
	ColourOnPrimary  string `json:"colour_on_primary"`
	ColourBackground string `json:"colour_background"`
	ColourText       string `json:"colour_text"`
}

func viewBrand(instanceID string, b *brand.Brand) brandView {
	v := brandView{InstanceID: instanceID}
	if b == nil {
		return v
	}
	v.Branded = true
	v.ProductName, v.LogoURL, v.SupportURL = b.ProductName, b.LogoURL, b.SupportURL
	v.ColourPrimary, v.ColourOnPrimary, v.ColourBackground, v.ColourText = b.Primary, b.OnPrimary, b.Background, b.Text
	return v
}

// deploymentWide refuses a token scoped to one organisation.
func deploymentWide(w http.ResponseWriter, ctx context.Context) bool {
	if err := requireOrg(ctx, ""); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "outside_token_organisation",
			"detail": "an instance spans organisations, so only a deployment-wide token reads or changes it"})
		return false
	}
	return true
}

var errUnknownInstance = errors.New("no instance with that id")

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !deploymentWide(w, ctx) {
		return
	}
	got, err := store.Instances(ctx, s.db)
	if err != nil {
		s.log.Error("listing instances", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]instanceView, 0, len(got))
	for _, i := range got {
		out = append(out, instanceView{ID: i.ID, Issuer: i.Issuer, DisplayName: i.DisplayName, CreatedAt: i.CreatedAt})
	}
	s.writeList(w, r, map[string]any{"instances": out})
}

func (s *Server) getBrand(w http.ResponseWriter, r *http.Request) {
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
	var b *brand.Brand
	if err == nil {
		b, err = store.BrandOf(ctx, s.db, instanceID)
	}
	if err != nil {
		s.log.Error("reading a brand", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, viewBrand(instanceID, b))
}

func (s *Server) putBrand(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceID := r.PathValue("instanceID")
	var req putBrandRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if !deploymentWide(w, ctx) {
		return
	}
	b := &brand.Brand{ProductName: req.ProductName, LogoURL: req.LogoURL, SupportURL: req.SupportURL,
		Primary: req.ColourPrimary, OnPrimary: req.ColourOnPrimary, Background: req.ColourBackground, Text: req.ColourText}
	// Before the version is taken: a sign-in page nobody can read is refused
	// here, by name, not at the next render.
	if err := b.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_brand", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		exists, err := store.InstanceExists(ctx, tx, instanceID)
		if err != nil {
			return err
		}
		if !exists {
			return errUnknownInstance
		}
		if err := store.SaveBrand(ctx, tx, instanceID, b); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.brand_set", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID, "product_name": b.ProductName,
				"logo": b.LogoURL != "", "support": b.SupportURL != "", "colours": b.Primary != ""}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errUnknownInstance):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance_not_found"})
		return
	case err != nil:
		s.log.Error("branding an instance", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, struct {
		brandView
		ConfigVersion int64 `json:"config_version"`
	}{viewBrand(instanceID, b), version})
}

func (s *Server) deleteBrand(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	instanceID := r.PathValue("instanceID")
	if !deploymentWide(w, ctx) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		removed, err := store.RemoveBrand(ctx, tx, instanceID)
		if err != nil {
			return err
		}
		if !removed {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.brand_removed", AdminTokenID: TokenIDFrom(ctx),
			Detail: map[string]any{"instance_id": instanceID}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_branded",
			"detail": "the instance already shows the built-in appearance"})
		return
	case err != nil:
		s.log.Error("removing a brand", "instance_id", instanceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "config_version": version})
}
