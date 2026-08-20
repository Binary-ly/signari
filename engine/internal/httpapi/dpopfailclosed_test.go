package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oidc"
)

func TestDPoPFailsClosedWhenReplayDetectionIsUnavailable(t *testing.T) {
	f := newTokenFixture(t)

	// A pool that parses but cannot serve: connections fail on first use.
	// Deliberately a separate pool, so the fixture's own cleanup is unaffected.
	broken, err := pgxpool.New(context.Background(),
		"postgres://127.0.0.1:1/definitely-not-a-database?connect_timeout=1")
	if err != nil {
		t.Fatalf("building the broken pool: %v", err)
	}
	t.Cleanup(broken.Close)

	key := newProofKey(t)
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, nil)
	req.Header.Set("DPoP", key.proof(t, "fail-closed-probe"))

	// Sanity: with the real database the same proof verifies, so a failure below
	// is the outage and not a malformed proof.
	if _, err := f.srv.verifyDPoPForRequest(req, ""); err != nil {
		t.Fatalf("the proof did not verify against a healthy store, so this test "+
			"could not distinguish an outage from a bad proof: %v", err)
	}

	// Now the same shape of request against a store that cannot answer.
	//
	// The pool is swapped on this test's own Server and restored afterwards,
	// rather than copying the struct: Server contains a sync.Mutex, and copying
	// it is what `go vet` refuses — correctly, since a copied mutex protects
	// nothing. newTokenFixture builds a fresh Server per test, so the swap is
	// confined to this one.
	healthy := f.srv.db
	f.srv.db = broken
	t.Cleanup(func() { f.srv.db = healthy })

	req2 := httptest.NewRequest(http.MethodPost, oidc.PathToken, nil)
	req2.Header.Set("DPoP", key.proof(t, "fail-closed-probe-2"))

	jkt, err := f.srv.verifyDPoPForRequest(req2, "")
	if err == nil {
		t.Fatalf("a DPoP proof was accepted (thumbprint %q) while replay detection "+
			"was unavailable. Replay protection is then off precisely when the "+
			"database is unhappy, and the 60-second proof window — four times "+
			"another implementation's — stops being defensible", jkt)
	}
	if !errors.Is(err, errDPoPUnavailable) {
		t.Errorf("refused, but not as an availability failure: %v. The distinction "+
			"matters: a replay and an outage need different operator responses", err)
	}
}
