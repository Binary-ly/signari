package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"signari.dev/terraform-provider-signari/internal/signari"
)

// An admin token minted through Terraform against a REAL Admin API (6.17):
// its secret, from the apply, reads what its scope allows and nothing more;
// it imports with what it is limited to; destroyed, it is revoked, and the
// refresh after that drops it so the next plan mints another.
func TestE2EAnAdminTokenIsMintedUsedAndRevoked(t *testing.T) {
	endpoint, token, org := os.Getenv("SIGNARI_E2E_ENDPOINT"), os.Getenv("SIGNARI_E2E_TOKEN"),
		os.Getenv("SIGNARI_E2E_ORG_ID")
	if endpoint == "" || token == "" || org == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID not set")
	}
	ctx := context.Background()
	api := &signari.Client{Endpoint: endpoint, Token: token}
	h := newHarness[adminTokenModel](t, &adminTokenResource{}, &providerData{client: api, conditional: true})
	scopes, _ := types.SetValueFrom(ctx, types.StringType, []string{"groups:read"})
	st, d := h.create(adminTokenModel{ID: types.StringUnknown(), Name: types.StringValue(fmt.Sprintf("tf-%d",
		time.Now().UnixNano())), Scopes: scopes, OrgID: types.StringValue(org), ClientIDs: types.SetNull(types.StringType),
		GroupIDs: types.SetNull(types.StringType), ExpiresInS: types.Int64Value(3600), Secret: types.StringUnknown(),
		ExpiresAt: types.StringUnknown()})
	if d.HasError() {
		t.Fatalf("minting: %v", d)
	}
	m := h.model(st)
	if m.Secret.ValueString() == "" || m.ExpiresAt.ValueString() == "" {
		t.Fatalf("the apply kept no secret or expiry: %+v", m.ExpiresAt)
	}
	as := &signari.Client{Endpoint: endpoint, Token: m.Secret.ValueString()}
	var page map[string]any
	if _, err := as.Get(ctx, "/admin/groups", &page); err != nil {
		t.Errorf("the minted token cannot do what its scope allows: %v", err)
	}
	if _, err := as.Get(ctx, "/admin/users", &page); err == nil {
		t.Error("the minted token reads users, outside its scope")
	}

	if im, d := h.imported(m.ID.ValueString()); d.HasError() || h.model(im).OrgID.ValueString() != org ||
		!h.model(im).Scopes.Equal(scopes) {
		t.Errorf("importing: %v %+v", d, h.model(im))
	}

	if d := h.destroy(st); d.HasError() {
		t.Fatalf("revoking: %v", d)
	}
	_, err := as.Get(ctx, "/admin/groups", &page)
	var refused *signari.APIError
	if !errors.As(err, &refused) || refused.Status != 401 {
		t.Errorf("after the destroy the token answered %v, want 401", err)
	}
	if _, still, d := h.read(st); d.HasError() || still {
		t.Errorf("a revoked token stayed in state (%v)", d)
	}
}
