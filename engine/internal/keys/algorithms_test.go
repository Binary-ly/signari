package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Each ES algorithm is held to its own curve, whichever way the key arrives, and an RSA key
// to the floor (9.04). A P-256 key under ES384 gives what its name does not say.
func TestAKeyIsHeldToWhatItsAlgorithmNames(t *testing.T) {
	ec := func(c elliptic.Curve) *ecdsa.PrivateKey {
		t.Helper()
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, c := range []struct {
		alg   Algorithm
		right elliptic.Curve
		wrong []elliptic.Curve
	}{
		{ES256, elliptic.P256(), []elliptic.Curve{elliptic.P384(), elliptic.P521()}},
		{ES384, elliptic.P384(), []elliptic.Curve{elliptic.P256(), elliptic.P521()}},
		{ES512, elliptic.P521(), []elliptic.Curve{elliptic.P256(), elliptic.P384()}},
	} {
		if _, err := NewSoftwareKey("k", c.alg, StateNext, ec(c.right), time.Now()); err != nil {
			t.Errorf("%s on %s: %v", c.alg, c.right.Params().Name, err)
		}
		for _, wrong := range c.wrong {
			if _, err := NewSoftwareKey("k", c.alg, StateNext, ec(wrong), time.Now()); err == nil {
				t.Errorf("%s accepted a key on %s", c.alg, wrong.Params().Name)
			}
		}
		k, err := Generate("k", c.alg)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.Signer().Public().(*ecdsa.PublicKey).Curve; got != c.right {
			t.Errorf("%s generated a key on %s", c.alg, got.Params().Name)
		}
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- what is being refused.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSoftwareKey("k", RS256, StateNext, small, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "2048") {
		t.Errorf("a 1024-bit RSA key gave %v", err)
	}
}

// A size is asked for by name, on an RSA algorithm, and only one the server makes. The
// default stays, and a rotation keeps what was chosen: a key made small for a relying party
// must not grow behind that party's back, nor a large one shrink.
func TestAnRSAKeySizeIsChosenAndKept(t *testing.T) {
	bits := func(k Key) int { return k.Signer().Public().(*rsa.PublicKey).N.BitLen() }
	k, err := GenerateSized("k", RS256, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if bits(k) != 2048 {
		t.Errorf("asked for 2048, got %d", bits(k))
	}
	next, err := Successor("k2", k)
	if err != nil {
		t.Fatal(err)
	}
	if bits(next) != 2048 || next.Algorithm() != RS256 {
		t.Errorf("the successor of a 2048-bit RS256 key is %s at %d", next.Algorithm(), bits(next))
	}
	def, err := Generate("k3", RS256)
	if err != nil {
		t.Fatal(err)
	}
	if bits(def) != RSABits {
		t.Errorf("the default is %d", bits(def))
	}
	if nextDef, err := Successor("k4", def); err != nil || bits(nextDef) != RSABits {
		t.Errorf("the successor of a default key: %v", err)
	}
	ed, err := Generate("k5", EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := Successor("k6", ed); err != nil || s.Algorithm() != EdDSA {
		t.Errorf("the successor of an EdDSA key: %v", err)
	}
	for _, c := range []struct {
		alg  Algorithm
		bits int
	}{{RS256, 1024}, {RS256, 2047}, {RS256, 16384}, {ES256, 2048}, {EdDSA, 3072}} {
		if _, err := GenerateSized("k", c.alg, c.bits); err == nil {
			t.Errorf("%s at %d was made", c.alg, c.bits)
		}
	}
}

// The first key of an algorithm is published and promoted as any other (9.04). Five messages
// told an operator to do this with `keys rotate -alg`, which answered that the algorithm
// signed nothing, so EdDSA and PS256 could be chosen for a client and never held. A key
// asked for on an RSA algorithm has the size asked for, and what cannot be made is refused
// as what it is.
func TestTheFirstKeyOfAnAlgorithmIsPublishedAndPromoted(t *testing.T) {
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
	root, err := NewRootKey("algorithms-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var instanceID string
	if err := pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://algs-' || gen_random_uuid() || '.test', 'algs') RETURNING id::text`).
		Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, instanceID)
		_, _ = pool.Exec(c, `DELETE FROM core.instances WHERE id = $1::uuid`, instanceID)
	})
	rotate := func(only Algorithm, bits int, now bool) ([]Step, error) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		steps, err := Rotate(ctx, tx, instanceID, root, only, bits, now, "test")
		if err == nil {
			err = tx.Commit(ctx)
		}
		return steps, err
	}
	state := func() *Set {
		t.Helper()
		set, err := LoadSet(ctx, pool, instanceID, root)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}

	steps, err := rotate(ES384, 0, false)
	if err != nil || len(steps) != 1 || steps[0].Published == "" {
		t.Fatalf("publishing a first ES384 key: %+v, %v", steps, err)
	}
	if got := state().Algorithms(); len(got) != 0 {
		t.Errorf("a published key signs nothing yet, but %v are active", got)
	}
	if steps, err := rotate(ES384, 0, false); err != nil || len(steps) != 1 || steps[0].Wait == 0 {
		t.Errorf("a day early: %+v, %v", steps, err)
	}
	if steps, err := rotate(ES384, 0, true); err != nil || len(steps) != 1 || steps[0].Promoted == "" || steps[0].Demoted != "" {
		t.Fatalf("promoting it, with nothing to demote: %+v, %v", steps, err)
	}
	if got := state().Algorithms(); len(got) != 1 || got[0] != ES384 {
		t.Errorf("active after promotion: %v", got)
	}

	if _, err := rotate(RS256, 2048, false); err != nil {
		t.Fatalf("a 2048-bit RS256 key: %v", err)
	}
	for _, k := range state().Keys() {
		if k.Algorithm() == RS256 {
			if n := k.Signer().Public().(*rsa.PublicKey).N.BitLen(); n != 2048 {
				t.Errorf("asked for 2048, published %d", n)
			}
		}
	}
	if _, err := rotate(RS256, 2048, false); !errors.Is(err, ErrNotRotatable) {
		t.Errorf("a size with a key already published: %v", err)
	}
	for _, c := range []struct {
		name string
		only Algorithm
		bits int
	}{
		{"an algorithm that does not exist", "HS256", 0},
		{"a size with no algorithm", "", 2048},
		{"a size on one with no modulus", ES256, 2048},
		{"a size nobody makes", RS384, 1024},
	} {
		if _, err := rotate(c.only, c.bits, false); !errors.Is(err, ErrNotRotatable) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
