package keys

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/migrate"
)

func rootKeyFor(t *testing.T, ref string) (*RootKey, []byte) {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	k, err := NewRootKey(ref, secret)
	if err != nil {
		t.Fatal(err)
	}
	return k, secret
}

// A ring opens what either key sealed and seals with its own (3.13), so a
// node mid-rotation reads every row and writes only under the new key.
func TestARingOpensEitherKeyAndSealsWithItsOwn(t *testing.T) {
	old, _ := rootKeyFor(t, "old")
	next, nextSecret := rootKeyFor(t, "new")
	ring, err := next.WithAccepted(old)
	if err != nil {
		t.Fatal(err)
	}
	byOld, err := old.Seal([]byte("sealed before"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ring.Open(byOld, "test"); err != nil || string(got) != "sealed before" {
		t.Errorf("the ring did not open what the old key sealed: %q %v", got, err)
	}
	byRing, err := ring.Seal([]byte("sealed during"), "test")
	if err != nil {
		t.Fatal(err)
	}
	newAlone, _ := NewRootKey("new", nextSecret)
	if _, err := newAlone.Open(byRing, "test"); err != nil {
		t.Errorf("the ring sealed with something the new key alone cannot open: %v", err)
	}
	if _, err := old.Open(byRing, "test"); err == nil {
		t.Error("the ring sealed with the old key")
	}
	if ring.Ref() != "new" || ring.Accepted().Ref() != "old" {
		t.Errorf("ring refs %q accepting %q", ring.Ref(), ring.Accepted().Ref())
	}
	if !strings.Contains(ring.PoolTag(), "seals="+next.tag) || !strings.Contains(ring.PoolTag(), "opens="+old.tag) {
		t.Errorf("PoolTag %q does not name both keys", ring.PoolTag())
	}
	if _, err := next.WithAccepted(newAlone); err == nil {
		t.Error("a ring of one key twice was accepted")
	}
	sameRef, _ := rootKeyFor(t, "new")
	if _, err := next.WithAccepted(sameRef); err == nil {
		t.Error("an accepted key with the root key's ref was accepted")
	}
}

// An application_name keeps its tag whole, however long the name.
func TestThePoolTagIsNeverCut(t *testing.T) {
	old, _ := rootKeyFor(t, "old")
	next, _ := rootKeyFor(t, "new")
	ring, _ := next.WithAccepted(old)
	got := WithPoolTag(strings.Repeat("a-very-long-deployment-name-", 4)+"workers", ring.PoolTag())
	if len(got) > 63 || !strings.HasSuffix(got, " "+ring.PoolTag()) {
		t.Errorf("%q (%d bytes) lost its tag or is over 63 bytes", got, len(got))
	}
	if WithPoolTag("signari", "") != "signari" {
		t.Error("an empty tag changed the name")
	}
}

// scratchDatabase is a migrated database of this test's own, dropped after.
func scratchDatabase(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("signari_keyringtest_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	for _, tier := range []migrate.Tier{migrate.TierBootstrap, migrate.TierCore} {
		if _, err := migrate.Up(ctx, conn, tier, 0, migrate.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	return u.String()
}

func newSubject(ctx context.Context, conn *pgx.Conn, root *RootKey) (string, error) {
	var id string
	if err := conn.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		return "", err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := LoadOrCreateSubjectKey(ctx, tx, id, root); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// A rotation done online, with nodes writing throughout, leaves every row
// openable by the new key alone (3.13). The nodes seal with the new key and
// accept the old one while the rewrap moves the old rows; afterwards nothing
// needs the old key.
func TestAnOnlineRotationUnderWriteLoadLeavesEveryRowOpenable(t *testing.T) {
	dsn := scratchDatabase(t)
	ctx := context.Background()
	old, _ := rootKeyFor(t, "old")
	next, nextSecret := rootKeyFor(t, "new")
	ring, err := next.WithAccepted(old)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	var ids []string
	for range 40 {
		id, err := newSubject(ctx, conn, old)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	// Four nodes on the second step write while the rewrap runs.
	stop := make(chan struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup
	var writeErr error
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := pgx.Connect(ctx, dsn)
			if err != nil {
				mu.Lock()
				writeErr = err
				mu.Unlock()
				return
			}
			defer func() { _ = c.Close(context.Background()) }()
			for {
				select {
				case <-stop:
					return
				default:
				}
				id, err := newSubject(ctx, c, ring)
				mu.Lock()
				if err != nil && writeErr == nil {
					writeErr = err
				}
				if err == nil {
					ids = append(ids, id)
				}
				mu.Unlock()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RewrapRoot(ctx, tx, old, ring); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	if writeErr != nil {
		t.Fatalf("a node writing during the rotation failed: %v", writeErr)
	}

	// The old key is gone: open every row with the new key on its own.
	newAlone, _ := NewRootKey("new", nextSecret)
	var unopened []string
	for _, id := range ids {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSubjectKey(ctx, tx, id, newAlone); err != nil {
			unopened = append(unopened, id)
		}
		_ = tx.Rollback(ctx)
	}
	if len(ids) <= 40 {
		t.Fatalf("only %d rows; the writers wrote nothing during the rotation", len(ids))
	}
	if len(unopened) > 0 {
		t.Fatalf("%d of %d rows cannot be opened by the new key alone", len(unopened), len(ids))
	}
	t.Logf("%d rows, %d written during the rotation, all open with the new key", len(ids), len(ids)-40)
}

// Signing keys wrapped under either key of a ring load (3.13), by the ref each
// row records; a key the process does not hold is refused by name. A node
// given the new key failed every refresh on rows still under the old one.
func TestSigningKeysUnderEitherRootKeyLoad(t *testing.T) {
	dsn := scratchDatabase(t)
	ctx := context.Background()
	old, _ := rootKeyFor(t, "old")
	next, nextSecret := rootKeyFor(t, "new")
	ring, _ := next.WithAccepted(old)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var instance string
	if err := conn.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://keyring.test', 'keyring') RETURNING id::text`).Scan(&instance); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		root *RootKey
		alg  Algorithm
	}{{old, ES256}, {ring, RS256}} {
		k, err := Generate(NewKID(), c.alg)
		if err != nil {
			t.Fatal(err)
		}
		if err := Save(ctx, tx, instance, k, c.root); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	set, err := LoadSet(ctx, conn, instance, ring)
	if err != nil || len(set.Keys()) != 2 {
		t.Fatalf("the ring loaded %v keys: %v", set, err)
	}
	newAlone, _ := NewRootKey("new", nextSecret)
	if _, err := LoadSet(ctx, conn, instance, newAlone); err == nil || !strings.Contains(err.Error(), `"old"`) {
		t.Errorf("a key under a root key not held: %v", err)
	}
}

// The rewrap's guard sees a node that still seals with the old key, and one
// of a release that cannot say, and not one that seals with the new key.
func TestNodesNotSealingWithSeesAnOldNode(t *testing.T) {
	dsn := scratchDatabase(t)
	ctx := context.Background()
	old, _ := rootKeyFor(t, "old")
	next, _ := rootKeyFor(t, "new")
	ring, _ := next.WithAccepted(old)
	oldRing, _ := old.WithAccepted(next)
	connect := func(name string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.RuntimeParams["application_name"] = name
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	self := connect("signari-cli")
	connect(WithPoolTag("signari", ring.PoolTag()))
	connect(WithPoolTag("idp-eu workers", ring.PoolTag()))
	if got, err := NodesNotSealingWith(ctx, self, ring); err != nil || len(got) != 0 {
		t.Fatalf("with every node on the new key: %v %v", got, err)
	}
	lagging := connect(WithPoolTag("signari workers", oldRing.PoolTag()))
	got, err := NodesNotSealingWith(ctx, self, ring)
	if err != nil || len(got) != 1 || !strings.Contains(got[0], "seals="+old.tag) {
		t.Errorf("a node sealing with the old key: %v %v", got, err)
	}
	_ = lagging.Close(ctx)
	connect("signari")
	if got, err := NodesNotSealingWith(ctx, self, ring); err != nil || len(got) != 1 || !strings.HasSuffix(got[0], ": signari") {
		t.Errorf("a node of an earlier release, which carries no tag: %v %v", got, err)
	}
}
