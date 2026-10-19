package store

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
)

// A provider's signing secret (2.04): minted at registration, sealed rather than
// stored, kept by a re-registration, replaced by a rotation, opened on load.
// The column had existed since the table did and the load selected NULL in its
// place, so no call to a provider could ever be authenticated.
func TestAProviderSecretIsSealedKeptAndRotated(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Rolled back: visible to this connection, residue for nobody.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	var orgID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://providersecret-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'providersecret-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := provider.Provider{Name: "provider-authorize", Hook: provider.HookAuthorize,
		URL: "https://pdp.example.test/decide", Mode: provider.FailClosed, Timeout: time.Second}

	_, first, err := SaveProvider(ctx, tx, root, orgID, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 40 {
		t.Fatalf("the minted secret %q is too short to be one", first)
	}
	var stored []byte
	if err := tx.QueryRow(ctx, `SELECT token_wrapped FROM core.providers WHERE org_id = $1::uuid`,
		orgID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(first)) {
		t.Fatal("the secret is stored in the clear")
	}
	load := func(r *keys.RootKey) (*provider.Provider, error) {
		return LoadProvider(ctx, tx, r, orgID, provider.HookAuthorize)
	}
	if got, err := load(root); err != nil || got.Secret != first {
		t.Fatalf("load gave %v, %v; want the minted secret", got, err)
	}

	p.Timeout = 2 * time.Second
	if _, again, err := SaveProvider(ctx, tx, root, orgID, p); err != nil || again != "" {
		t.Fatalf("re-registering gave secret %q, %v; want none, the provider keeps its own", again, err)
	}
	if got, _ := load(root); got.Secret != first {
		t.Error("re-registering replaced the secret the provider holds")
	}

	rotated, err := RotateProviderSecret(ctx, tx, root, orgID, provider.HookAuthorize)
	if err != nil || rotated == "" || rotated == first {
		t.Fatalf("rotation gave %q, %v", rotated, err)
	}
	if got, _ := load(root); got.Secret != rotated {
		t.Error("after rotation the provider is still loaded with the old secret")
	}

	// A sealed secret with no root key to open it is refused, not called unsigned.
	if _, err := load(nil); err == nil {
		t.Error("a sealed secret loaded with no root key")
	}
	if _, err := RotateProviderSecret(ctx, tx, root, orgID, provider.HookTokenIssue); err == nil {
		t.Error("rotating a hook with no provider succeeded")
	}
}
