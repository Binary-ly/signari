package keys

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The journeys every Backend is held to (3.14), each run by the backend's own
// test file against the real thing: pkcs11_test.go against SoftHSM, vault_test.go
// against a transit engine.

func heldInstance(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
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
	var instanceID string
	if err := pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://held-' || gen_random_uuid() || '.test', 'held') RETURNING id::text`).
		Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, instanceID)
		_, _ = pool.Exec(c, `DELETE FROM core.instances WHERE id = $1::uuid`, instanceID)
	})
	return pool, instanceID
}

// heldRows is each key's row as stored: "sealed", or its key_ref when it
// carries no material.
func heldRows(t *testing.T, pool *pgxpool.Pool, instanceID string) map[string]string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT kid, CASE WHEN wrapped_private IS NULL THEN key_ref ELSE 'sealed' END
		  FROM core.signing_keys WHERE instance_id = $1::uuid`, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for rows.Next() {
		var kid, where string
		if err := rows.Scan(&kid, &where); err != nil {
			t.Fatal(err)
		}
		out[kid] = where
	}
	return out
}

// A node given a backend makes its keys there, stores a reference and no
// material, publishes the backend's public keys, and rotates to keys made
// there too. A node without it cannot load them, and names the setting.
func heldKeysAreMadeKeptAndRotated(t *testing.T, ring *RootKey, setting string) {
	scheme := ring.backend.Scheme()
	pool, instanceID := heldInstance(t)
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created, err := Ensure(ctx, conn.Conn(), instanceID, ring, ES256, RS256)
	conn.Release()
	if err != nil || len(created) != 2 {
		t.Fatalf("making the first keys: %v, %v", created, err)
	}
	for kid, where := range heldRows(t, pool, instanceID) {
		if where != scheme+":"+kid {
			t.Errorf("key %s is stored as %q, not as a reference into %s", kid, where, scheme)
		}
	}

	set, err := LoadSet(ctx, pool, instanceID, ring)
	if err != nil {
		t.Fatal(err)
	}
	published := set.JWKS()
	if len(published.Keys) != 2 {
		t.Fatalf("the JWKS has %d keys", len(published.Keys))
	}
	for _, alg := range []Algorithm{ES256, RS256} {
		k, err := set.Active(alg)
		if err != nil {
			t.Fatal(err)
		}
		held, err := ring.backend.Open(k.KID())
		if err != nil {
			t.Fatal(err)
		}
		served := published.Key(k.KID())
		if len(served) != 1 || !held.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(served[0].Key) {
			t.Errorf("%s: the JWKS does not serve the key %s holds", alg, scheme)
		}
		if _, err := x509.MarshalPKCS8PrivateKey(k.Signer()); err == nil {
			t.Errorf("%s: the private half came out of %s", alg, scheme)
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Left open by a failure, it holds the rows the cleanup deletes.
	defer func() { _ = tx.Rollback(ctx) }()
	steps, err := Rotate(ctx, tx, instanceID, ring, ES256, 0, false, "test")
	if err != nil || len(steps) != 1 || steps[0].Published == "" {
		t.Fatalf("publishing a successor: %+v, %v", steps, err)
	}
	steps, err = Rotate(ctx, tx, instanceID, ring, ES256, 0, true, "test")
	if err != nil || len(steps) != 1 || steps[0].Promoted == "" || steps[0].Demoted == "" {
		t.Fatalf("promoting it: %+v, %v", steps, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows := heldRows(t, pool, instanceID)
	if len(rows) != 3 {
		t.Fatalf("%d keys after one rotation", len(rows))
	}
	for kid, where := range rows {
		if where != scheme+":"+kid {
			t.Errorf("after rotating, key %s is stored as %q", kid, where)
		}
	}
	set, err = LoadSet(ctx, pool, instanceID, ring)
	if err != nil {
		t.Fatal(err)
	}
	if active, _ := set.Active(ES256); active == nil || active.KID() != steps[0].Promoted {
		t.Errorf("the promoted key is not the one signing")
	}
	if demoted, ok := set.ByKID(steps[0].Demoted); !ok || demoted.State() != StatePassive {
		t.Errorf("the demoted key is not published as passive")
	}

	plain, err := NewRootKey(ring.Ref(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSet(ctx, pool, instanceID, plain); err == nil || !strings.Contains(err.Error(), setting) {
		t.Errorf("a node with no %s loaded a key held in one: %v", scheme, err)
	}
}

// A deployment moves its keys in by configuring the backend: a key made before
// goes on loading from its sealed row, and the unattended rotation's successor
// is made in the backend.
func heldKeySucceedsASealedOne(t *testing.T, ring *RootKey) {
	scheme := ring.backend.Scheme()
	pool, instanceID := heldInstance(t)
	ctx := context.Background()

	before, err := Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := WithState(before, StateActive)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := Save(ctx, tx, instanceID, active, ring); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.signing_keys SET published_at = now() - interval '100 days'
		WHERE kid = $1`, before.KID()); err != nil {
		t.Fatal(err)
	}
	r := &Rotator{DB: pool, InstanceID: instanceID, Root: ring, Every: 90 * 24 * time.Hour,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	steps, err := r.Once(ctx)
	if err != nil || len(steps) != 1 || !strings.Contains(steps[0], "published") {
		t.Fatalf("the pass did %v, %v", steps, err)
	}
	rows := heldRows(t, pool, instanceID)
	if rows[before.KID()] != "sealed" {
		t.Errorf("the key made before is stored as %q", rows[before.KID()])
	}
	for kid, where := range rows {
		if kid != before.KID() && where != scheme+":"+kid {
			t.Errorf("its successor %s is stored as %q, not in %s", kid, where, scheme)
		}
	}
	if set, err := LoadSet(ctx, pool, instanceID, ring); err != nil || len(set.Keys()) != 2 {
		t.Errorf("loading both: %v, %v", set, err)
	}
}

// A backend answering with another key under a stored key's name is refused:
// signing with it would put a key nobody published to work.
func heldKeyMustBeThePublishedOne(t *testing.T, ring *RootKey) {
	pool, instanceID := heldInstance(t)
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created, err := Ensure(ctx, conn.Conn(), instanceID, ring, ES256)
	conn.Release()
	if err != nil {
		t.Fatal(err)
	}
	other, err := Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := json.Marshal(other.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core.signing_keys SET public_jwk = $2 WHERE kid = $1`,
		created[0].KID(), jwk); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSet(ctx, pool, instanceID, ring); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Errorf("a held key unlike the published one loaded: %v", err)
	}
}

// A root-key rotation moves what the root key sealed and leaves a reference
// into the backend as it is: there is nothing under the old key to move. The
// ring's ref must not be "new".
func rootRotationLeavesHeldKeys(t *testing.T, ring *RootKey) {
	scheme := ring.backend.Scheme()
	dsn := scratchDatabase(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var instanceID string
	if err := conn.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://held-rewrap.test', 'rewrap') RETURNING id::text`).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	created, err := Ensure(ctx, conn, instanceID, ring, ES256)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := rootKeyFor(t, "new")
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := RewrapRoot(ctx, tx, ring, next); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var ref string
	if err := conn.QueryRow(ctx, `SELECT key_ref FROM core.signing_keys WHERE kid = $1`,
		created[0].KID()).Scan(&ref); err != nil || ref != scheme+":"+created[0].KID() {
		t.Errorf("after the rotation the key is %q, %v", ref, err)
	}
	if _, err := LoadSet(ctx, conn, instanceID, next.WithBackend(ring.backend)); err != nil {
		t.Errorf("loading under the new root key: %v", err)
	}
}

// Every algorithm the backend makes is made there, and one it does not is
// refused by name rather than made here.
func everyAlgorithmIsMadeHeld(t *testing.T, ring *RootKey, refused ...Algorithm) {
	scheme := ring.backend.Scheme()
	for _, alg := range AllAlgorithms {
		k, err := ring.Generate(NewKID(), alg)
		if slices.Contains(refused, alg) {
			if err == nil || !strings.Contains(err.Error(), string(alg)) {
				t.Errorf("%s: made in %s: %v", alg, scheme, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", alg, err)
			continue
		}
		if k.(*signingKey).held != scheme+":"+k.KID() {
			t.Errorf("%s: made outside %s", alg, scheme)
		}
	}
}
