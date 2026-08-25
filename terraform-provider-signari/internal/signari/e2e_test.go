package signari

import (
	"context"
	"errors"
	"os"
	"testing"
)

// End-to-end against a REAL Signari Admin API.
//
// The tests in client_test.go prove the client is self-consistent against a fake
// that mirrors the documented contract. They cannot prove the contract is right.
// A fake that agreed with a wrong belief -- an ETag the real server never sends
// on reads, a 412 body with different field names -- would pass every one of
// them while the feature was dead in production, silently downgrading every
// write to unconditional.
//
// So this drives the same client against the real server:
//
//	SIGNARI_E2E_ENDPOINT=http://127.0.0.1:18081 \
//	SIGNARI_E2E_TOKEN=sgnadm_... \
//	SIGNARI_E2E_CLIENT_ID=seed-app \
//	go test -run E2E ./internal/signari/
//
// Skipped when unset, so `go test ./...` stays runnable without a database.

func e2eClient(t *testing.T) (*Client, string) {
	t.Helper()
	endpoint := os.Getenv("SIGNARI_E2E_ENDPOINT")
	token := os.Getenv("SIGNARI_E2E_TOKEN")
	clientID := os.Getenv("SIGNARI_E2E_CLIENT_ID")
	if endpoint == "" || token == "" || clientID == "" {
		t.Skip("SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_CLIENT_ID not set")
	}
	return &Client{Endpoint: endpoint, Token: token}, clientID
}

// The real server puts an ETag on a READ.
//
// If it did not, every version would parse as 0, every update would go out
// unconditional, and the whole feature would be inert while looking healthy.
// That failure is invisible to a fake, which is exactly why this exists.
func TestE2EAReadCarriesTheVersion(t *testing.T) {
	c, clientID := e2eClient(t)

	got, version, err := c.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("reading %q: %v", clientID, err)
	}
	if got.ClientID != clientID {
		t.Errorf("read back client_id %q, want %q", got.ClientID, clientID)
	}
	if version <= 0 {
		t.Fatalf("the read returned version %d. Without a version from a read, "+
			"every subsequent write is unconditional and the precondition is inert", version)
	}
	if got.OrgID == "" {
		t.Error("no org_id on the read; the resource cannot be placed")
	}
	t.Logf("real server: client=%s version=%d enabled=%t", got.ClientID, version, got.Enabled)
}

// The whole point, against the real server: a write planned at one version is
// refused after somebody else writes.
//
// The interfering write is a real mutation through the real API, not a simulated
// one -- so the version moves the way it moves in production, via ADR-008's
// same-transaction bump.
func TestE2EAStaleWriteIsRefusedByTheRealServer(t *testing.T) {
	c, clientID := e2eClient(t)
	ctx := context.Background()

	// Plan: read the world.
	before, planned, err := c.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Somebody else writes. A real, conditional mutation through the real API,
	// which bumps core.config_version in its own transaction.
	if _, err := c.SetClientEnabled(ctx, clientID, before.Enabled, planned); err != nil {
		t.Fatalf("the interfering write failed, so there is nothing to be stale "+
			"against: %v", err)
	}

	// Apply, still holding the version from the plan. This is the exact shape of
	// the lost update: without the precondition the server would accept it and
	// the interfering change would be gone with nobody told.
	_, err = c.SetClientEnabled(ctx, clientID, !before.Enabled, planned)

	var conflict *ErrConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("the real server accepted a write planned at version %d after the "+
			"configuration had moved. err = %v", planned, err)
	}
	if conflict.Expected != planned {
		t.Errorf("conflict reports expected=%d, want the planned %d",
			conflict.Expected, planned)
	}
	if conflict.Actual <= planned {
		t.Errorf("conflict reports actual=%d, which is not ahead of the planned %d",
			conflict.Actual, planned)
	}

	// And it truly wrote nothing.
	after, _, err := c.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.Enabled != before.Enabled {
		t.Errorf("the refused write still landed: enabled %t -> %t",
			before.Enabled, after.Enabled)
	}
}

// A write conditional on the CURRENT version is accepted, and the response
// carries the new one.
//
// The other half of the contract. A precondition that refused everything would
// pass the test above and be useless.
func TestE2EAFreshWriteIsAcceptedAndAdvancesTheVersion(t *testing.T) {
	c, clientID := e2eClient(t)
	ctx := context.Background()

	before, version, err := c.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	res, err := c.SetClientEnabled(ctx, clientID, !before.Enabled, version)
	if err != nil {
		t.Fatalf("a write conditional on the current version %d was refused: %v",
			version, err)
	}
	if res.Version <= version {
		t.Errorf("the mutation responded with version %d, not ahead of %d. A caller "+
			"looping on this would send a stale tag on its next write", res.Version, version)
	}

	// It landed, and the state is what was asked for.
	after, newVersion, err := c.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.Enabled == before.Enabled {
		t.Errorf("the accepted write did not change anything: enabled still %t", after.Enabled)
	}
	if newVersion != res.Version {
		t.Errorf("the version from the write (%d) and from the next read (%d) disagree",
			res.Version, newVersion)
	}

	// Put it back, so the test is repeatable.
	if _, err := c.SetClientEnabled(ctx, clientID, before.Enabled, newVersion); err != nil {
		t.Fatalf("restoring: %v", err)
	}
}

// A 404 from the real server is recognised as ErrNotFound, because the provider
// turns exactly that into "removed outside Terraform, offer to recreate".
func TestE2EAMissingClientIsNotFound(t *testing.T) {
	c, _ := e2eClient(t)

	_, _, err := c.GetClient(context.Background(), "no-such-client-fbe1a4")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound. Anything else makes Terraform fail "+
			"hard where it should offer to recreate", err)
	}
}
