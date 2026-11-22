package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The console and the Terraform provider send back the version they read. An
// operator's CLI change made since must refuse that write, as another
// administrator's Admin API change does; the CLI moved no version, so a plan
// read before `client disable` applied over it and put the client back.
func TestACLIChangeBetweenAReadAndAConditionalWriteIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	clientID := newPreconditionClient(t, s)
	tag := fmt.Sprintf(`"%d"`, currentVersion(t, s))

	// The CLI's own session, marked as cmd/signari marks it.
	cli, err := pgx.Connect(ctx, os.Getenv("SIGNARI_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close(ctx) }()
	if _, err := cli.Exec(ctx, `SELECT set_config('signari.cli_write', 'on', false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Exec(ctx,
		`UPDATE core.clients SET enabled = false WHERE client_id = $1`, clientID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/clients/"+clientID,
		`{"enabled":true}`, tag))
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("a write conditional on the version read before the CLI disabled the client "+
			"answered %d, want 412: %s", rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := s.db.QueryRow(ctx, `SELECT enabled FROM core.clients WHERE client_id = $1`,
		clientID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Error("the stale write re-enabled the client the CLI had disabled")
	}
}
