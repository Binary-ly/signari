package keys

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The database half of retirement: what the loader will and will not publish,
// what Retire refuses, and how the dwell is derived from credential lifetimes.

func retireConn(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	if _, err := conn.Exec(ctx, "SET ROLE signari_maintenance"); err != nil {
		t.Fatal(err)
	}
	return conn, ctx
}

// newInstance makes an isolated instance so these tests never depend on, or
// disturb, whatever else is seeded in the database.
func newInstance(t *testing.T, conn *pgx.Conn, ctx context.Context) string {
	t.Helper()
	var id string
	err := conn.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name, status)
		VALUES ($1, $1, 'active') RETURNING id::text`,
		"https://retire-test-"+NewKID()+".example.com").Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup in dependency order, and loudly.
	//
	// The first version deleted the instance while its organisation still
	// existed. core.organizations references instances ON DELETE RESTRICT, so the
	// delete failed -- and because the error was discarded, it failed in silence.
	// Three instances, three organisations and six credential configurations were
	// left in the shared test database, where they broke an unrelated httpapi test
	// asserting that an issuer with no credential configurations publishes no
	// issuer metadata. A test that pollutes a shared fixture is worse than no
	// test: it fails somewhere else, for a reason nothing points at.
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM core.credential_configurations WHERE org_id IN (
			     SELECT id FROM core.organizations WHERE instance_id = $1)`,
			`DELETE FROM core.organizations WHERE instance_id = $1`,
			`DELETE FROM core.signing_keys WHERE instance_id = $1`,
			`DELETE FROM core.instances WHERE id = $1`,
		} {
			if _, err := conn.Exec(ctx, q, id); err != nil {
				t.Errorf("cleanup left rows behind, which will break another test: %v", err)
			}
		}
	})
	return id
}

func testRoot(t *testing.T) *RootKey {
	t.Helper()
	r, err := NewRootKey("test-root", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// saveKey persists a key and forces its demotion stamp, since the upsert stamps
// now() and these tests need a key demoted in the past.
func saveKey(t *testing.T, conn *pgx.Conn, ctx context.Context, instanceID string,
	root *RootKey, state State, demotedAt time.Time) Key {
	t.Helper()
	k, err := Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	k, err = WithState(k, state)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ctx, tx, instanceID, k, root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if !demotedAt.IsZero() {
		if _, err := conn.Exec(ctx,
			`UPDATE core.signing_keys SET demoted_at = $2 WHERE kid = $1`, k.KID(), demotedAt); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

// The point of the whole feature: a retired key stops being published. If the
// loader still reads it, retirement changed a label and nothing else.
func TestARetiredKeyLeavesTheJWKS(t *testing.T) {
	conn, ctx := retireConn(t)
	root := testRoot(t)
	inst := newInstance(t, conn, ctx)

	active := saveKey(t, conn, ctx, inst, root, StateActive, time.Time{})
	old := saveKey(t, conn, ctx, inst, root, StatePassive, time.Now().UTC().Add(-72*time.Hour))

	set, err := LoadSetFor(ctx, conn, inst, PurposeOIDC, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.ByKID(old.KID()); !ok {
		t.Fatal("the passive key was not loaded before retirement; this test proves nothing")
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Retire(ctx, tx, inst, old.KID(), MinPassiveBeforeRetire); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	set, err = LoadSetFor(ctx, conn, inst, PurposeOIDC, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.ByKID(old.KID()); ok {
		t.Error("a retired key is still in the loaded set")
	}
	for _, jwk := range set.JWKS().Keys {
		if jwk.KeyID == old.KID() {
			t.Error("a retired key is still published in the JWKS")
		}
	}
	if _, ok := set.ByKID(active.KID()); !ok {
		t.Error("retiring one key removed another")
	}

	// The row survives, which is the reason this is a state and not a DELETE.
	var state string
	var retireAfter *time.Time
	if err := conn.QueryRow(ctx,
		`SELECT state, retire_after FROM core.signing_keys WHERE kid = $1`,
		old.KID()).Scan(&state, &retireAfter); err != nil {
		t.Fatalf("the retired row is gone: %v", err)
	}
	if state != string(StateRetired) {
		t.Errorf("state = %q, want %q", state, StateRetired)
	}
	if retireAfter == nil {
		t.Error("retire_after was not recorded, so the decision is not auditable")
	}
}

// The SQL guard, not the Go one. Two processes both reading `passive` and both
// writing would be a lost update; the WHERE clause is what makes the second one
// match no rows. It must also refuse on its own terms, with no Set involved.
func TestRetireRefusesWhatItMustNotRemove(t *testing.T) {
	conn, ctx := retireConn(t)
	root := testRoot(t)
	inst := newInstance(t, conn, ctx)
	now := time.Now().UTC()

	cases := []struct {
		name  string
		state State
		demot time.Time
	}{
		{"still active", StateActive, now.Add(-72 * time.Hour)},
		{"not yet published long enough", StatePassive, now.Add(-1 * time.Hour)},
		{"no demotion time recorded", StatePassive, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := saveKey(t, conn, ctx, inst, root, tc.state, tc.demot)
			if tc.demot.IsZero() {
				if _, err := conn.Exec(ctx,
					`UPDATE core.signing_keys SET demoted_at = NULL WHERE kid = $1`, k.KID()); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := Retire(ctx, tx, inst, k.KID(), MinPassiveBeforeRetire); err == nil {
				t.Errorf("Retire removed a key that was %s", tc.name)
			}
		})
	}
}

// The dwell must follow the longest credential lifetime on the instance, not the
// 24-hour floor. Getting this wrong stops a long-lived credential verifying at a
// verifier this deployment does not run, weeks after anyone could connect it to a
// rotation.
func TestTheDwellFollowsTheLongestCredentialLifetime(t *testing.T) {
	conn, ctx := retireConn(t)
	inst := newInstance(t, conn, ctx)

	dwell, why, err := RequiredPassiveDwell(ctx, conn, inst)
	if err != nil {
		t.Fatal(err)
	}
	if dwell != MinPassiveBeforeRetire {
		t.Errorf("with no credential configurations dwell = %s, want the %s floor (%s)",
			dwell, MinPassiveBeforeRetire, why)
	}

	var orgID string
	if err := conn.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name, status)
		VALUES ($1, $2, 'Retire test', 'active') RETURNING id::text`,
		inst, "retire-"+NewKID()).Scan(&orgID); err != nil {
		t.Skipf("could not seed an organisation: %v", err)
	}

	// One short and one long, so the result must be a maximum rather than
	// whichever row the query happened to reach first.
	for _, c := range []struct {
		id   string
		life string
	}{{"short", "1 hour"}, {"long", "90 days"}} {
		if _, err := conn.Exec(ctx, `
			INSERT INTO core.credential_configurations
				(org_id, config_id, vct, always_claims, lifetime)
			VALUES ($1, $2, 'https://example.com/vct', ARRAY['sub'], $3::interval)`,
			orgID, c.id, c.life); err != nil {
			t.Fatalf("seeding %s: %v", c.id, err)
		}
	}

	dwell, why, err = RequiredPassiveDwell(ctx, conn, inst)
	if err != nil {
		t.Fatal(err)
	}
	if want := 90 * 24 * time.Hour; dwell != want {
		t.Errorf("dwell = %s, want %s -- the 90-day credential does not hold the key", dwell, want)
	}
	if why == "" {
		t.Error("no reason given, so the command cannot explain a 90-day dwell to an operator")
	}
}
