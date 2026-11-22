package httpapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// Two switches the request path read and nothing could set, found when the
// write-path guard stopped counting WHERE clauses as writes.

// A disabled inbound SCIM source's token is refused from the next request, and
// enabling it restores the source as it was.
func TestADisabledSCIMSourcesTokenIsRefused(t *testing.T) {
	f := newSCIMFixture(t)
	ctx := context.Background()
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Users", ""); status != http.StatusOK {
		t.Fatalf("the enabled source's token gave %d", status)
	}
	if err := store.SetSCIMSourceEnabled(ctx, f.pool, f.orgID, "client-test", false); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Users", ""); status != http.StatusUnauthorized {
		t.Fatalf("the disabled source's token gave %d, want 401", status)
	}
	if err := store.SetSCIMSourceEnabled(ctx, f.pool, f.orgID, "client-test", true); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, http.MethodGet, "/scim/v2/Users", ""); status != http.StatusOK {
		t.Fatalf("the re-enabled source's token gave %d", status)
	}
	if err := store.SetSCIMSourceEnabled(ctx, f.pool, f.orgID, "no-such-source", false); !errors.Is(err, store.ErrSCIMSourceUnknown) {
		t.Errorf("an unknown slug gave %v", err)
	}
}

// A revoked invitation's link creates no account, and only an open invitation
// in the right organisation can be revoked.
func TestARevokedInvitationCannotBeClaimed(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	token, err := store.CreateInvitation(ctx, f.pool, f.orgID, "", nil, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	var id string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.invitations WHERE token_hash = $1`,
		sum[:]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeekInvitation(ctx, f.pool, token); err != nil {
		t.Fatalf("the open invitation did not peek: %v", err)
	}

	if err := store.RevokeInvitation(ctx, f.pool, "00000000-0000-4000-8000-000000000001", id); !errors.Is(err, store.ErrInvitationNotRevocable) {
		t.Errorf("another organisation revoked this one: %v", err)
	}
	if err := store.RevokeInvitation(ctx, f.pool, f.orgID, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInvitation(ctx, f.pool, token); !errors.Is(err, store.ErrInvitationNotUsable) {
		t.Errorf("a revoked invitation was claimed: %v", err)
	}
	if err := store.RevokeInvitation(ctx, f.pool, f.orgID, id); !errors.Is(err, store.ErrInvitationNotRevocable) {
		t.Errorf("a revoked invitation was revoked again: %v", err)
	}
	if err := store.RevokeInvitation(ctx, f.pool, f.orgID, "not-a-uuid"); !errors.Is(err, store.ErrInvitationNotRevocable) {
		t.Errorf("a malformed id gave %v", err)
	}
}
