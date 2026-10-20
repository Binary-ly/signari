package keys

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Rotation advances unattended, one safe step at a time, and only when each
// step is due (3.16): a key past the period gets a `next`, which is promoted
// only after a day of publication, and the key it replaced is retired only
// once nothing can still be verifying against it. Time is moved by
// backdating the rows, on an instance of the test's own.
func TestRotationAdvancesUnattended(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	root, err := NewRootKey("rotator-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var instanceID string
	if err := pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://rotator-' || gen_random_uuid() || '.test', 'rotator') RETURNING id::text`).
		Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, instanceID)
		_, _ = pool.Exec(c, `DELETE FROM core.instances WHERE id = $1::uuid`, instanceID)
	})
	k, err := Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := WithState(k, StateActive)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ctx, tx, instanceID, first, root); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	backdate := func(column, kid string, by time.Duration) {
		t.Helper()
		if _, err := pool.Exec(ctx, fmt.Sprintf(`UPDATE core.signing_keys SET %s = now() - $3::interval
			WHERE instance_id = $1::uuid AND kid = $2`, column), instanceID, kid,
			fmt.Sprintf("%d seconds", int(by.Seconds()))); err != nil {
			t.Fatal(err)
		}
	}
	r := &Rotator{DB: pool, InstanceID: instanceID, Root: root, Every: 90 * 24 * time.Hour,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	pass := func(want string) {
		t.Helper()
		steps, err := r.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(steps, "; ")
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Fatalf("the pass did %q, want %q", got, want)
		}
	}
	state := func(kid string) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx, `SELECT state FROM core.signing_keys WHERE instance_id = $1::uuid AND kid = $2`,
			instanceID, kid).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	pass("") // a fresh key is not due
	backdate("published_at", first.KID(), 91*24*time.Hour)
	pass("published")
	var next string
	if err := pool.QueryRow(ctx, `SELECT kid FROM core.signing_keys WHERE instance_id = $1::uuid AND state = 'next'`,
		instanceID).Scan(&next); err != nil {
		t.Fatal(err)
	}
	pass("") // published a moment ago: not promotable for a day
	backdate("published_at", next, 25*time.Hour)
	pass("promoted " + next)
	if state(next) != "active" || state(first.KID()) != "passive" {
		t.Fatalf("after promotion: next %s, first %s", state(next), state(first.KID()))
	}
	pass("") // the demoted key stays published until nothing can verify against it
	backdate("demoted_at", first.KID(), 10*365*24*time.Hour)
	pass("retired " + first.KID())
	if state(first.KID()) != "retired" {
		t.Fatalf("after retirement the first key is %s", state(first.KID()))
	}

	var automatic int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE event_type = 'keys.rotated'
		AND detail->>'automatic' = 'true' AND (detail->>'published' = $1 OR detail->>'promoted' = $1
		    OR detail->>'retired' = $2)`, next, first.KID()).Scan(&automatic); err != nil {
		t.Fatal(err)
	}
	if automatic != 3 {
		t.Errorf("%d automatic keys.rotated rows for the publication, promotion and retirement, want 3", automatic)
	}
}
