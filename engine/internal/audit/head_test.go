package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
)

// headKey is a signing key registered in the scratch database's signing_keys,
// as the engine's are.
type headKey struct {
	kid string
	key *ecdsa.PrivateKey
}

func newHeadKey(t *testing.T, conn *pgx.Conn, kid string) headKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(context.Background(), `
		WITH i AS (INSERT INTO core.instances (issuer, display_name)
		           VALUES ('https://head-' || $1 || '.test', 'heads') RETURNING id)
		INSERT INTO core.signing_keys (kid, instance_id, algorithm, state, public_jwk, key_ref)
		SELECT $1, id, 'ES256', 'active', $2::jsonb, 'test:in-memory' FROM i`, kid, string(pub)); err != nil {
		t.Fatal(err)
	}
	return headKey{kid, k}
}

func (h headKey) sign(t *testing.T, c *HeadClaims, typ string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: h.key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", h.kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(c)
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return jws
}

// signHead signs and records a head as serve's janitor does.
func signHead(t *testing.T, conn *pgx.Conn, k headKey) string {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := HeadToSign(ctx, tx, "https://heads.test", time.Now(), time.Hour)
	if err != nil || c == nil {
		t.Fatalf("no head to sign: %v %v", c, err)
	}
	jws := k.sign(t, c, HeadType)
	if err := RecordHead(ctx, tx, c, k.kid, jws); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return jws
}

// recompute rewrites every link from the start, as somebody with the
// database and without the signing key would after changing an entry.
func recompute(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	rows, err := conn.Query(ctx, `
		SELECT id, event_type, COALESCE(org_id::text,''), COALESCE(subject_id::text,''),
		       COALESCE(actor_id::text,''), COALESCE(client_id,''),
		       COALESCE(correlation_id::text,''), retention_class, detail::text,
		       COALESCE(admin_token_id::text,''), occurred_at, hash_version
		  FROM core.audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id      int64
		e       Event
		detail  string
		version int
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.e.Type, &r.e.OrgID, &r.e.SubjectID, &r.e.ActorID, &r.e.ClientID,
			&r.e.CorrelationID, &r.e.Retention, &r.detail, &r.e.AdminTokenID, &r.e.OccurredAt, &r.version); err != nil {
			t.Fatal(err)
		}
		all = append(all, r)
	}
	rows.Close()
	var prev []byte
	for _, r := range all {
		h := hashFor(r.version, prev, r.e, r.detail)
		if _, err := conn.Exec(ctx, `UPDATE core.audit_events SET prev_hash = $2, entry_hash = $3 WHERE id = $1`,
			r.id, prev, h); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
}

func headsJudge(t *testing.T, conn *pgx.Conn, head string) (*ChainState, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s, err := JudgeChain(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if head == "" {
		return s, nil
	}
	_, herr := CheckHead(ctx, tx, head)
	return s, herr
}

// A rewrite recomputed to verify is caught by a signed head, and, with every
// head in the database removed too, by one kept outside it (3.20). The chain
// was unkeyed: a rewrite recomputed after it verified as before.
func TestARecomputedRewriteIsCaughtByASignedHead(t *testing.T) {
	conn := scratchChain(t)
	k := newHeadKey(t, conn, "head-key")
	for i := range 5 {
		writeAt(t, conn, time.Time{}, 2, i)
	}
	kept := signHead(t, conn, k)
	writeAt(t, conn, time.Time{}, 2, 5)
	if s, err := headsJudge(t, conn, kept); !s.Verified || s.HeadsChecked != 1 || err != nil {
		t.Fatalf("an untouched chain with one head: %+v, the kept head: %v", s, err)
	}

	// Rewrite an entry the head covers, and recompute every link.
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `UPDATE core.audit_events SET detail = '{"n": 99}'
		WHERE id = (SELECT min(id) FROM core.audit_events) + 1`); err != nil {
		t.Fatal(err)
	}
	recompute(t, conn)
	s, err := headsJudge(t, conn, "")
	if err != nil {
		t.Fatal(err)
	}
	if s.Verified || s.HeadFailure == "" || !strings.Contains(s.HeadFailure, "rewritten") {
		t.Fatalf("a recomputed rewrite under a signed head: %+v", s)
	}

	// Remove the head as well, and recompute again: nothing in the database
	// is left to catch it, and the head kept outside does.
	if _, err := conn.Exec(ctx, `DELETE FROM core.audit_events WHERE event_type = $1`, HeadEvent); err != nil {
		t.Fatal(err)
	}
	recompute(t, conn)
	s, err = headsJudge(t, conn, kept)
	if !s.Verified || s.HeadsChecked != 0 {
		t.Errorf("with the heads gone, the hashes alone: %+v", s)
	}
	if err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Errorf("the head kept outside the database did not catch the rewrite: %v", err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, since, ok, err := HeadAge(ctx, tx, time.Now()); err != nil || ok || since == 0 {
		t.Errorf("doctor's view with every head gone: ok %v, %d entries, %v", ok, since, err)
	}
}

// A head that is not one: a key the deployment never held, another typ, or an
// altered payload.
func TestAForgedHeadIsRefused(t *testing.T) {
	conn := scratchChain(t)
	k := newHeadKey(t, conn, "real-key")
	writeAt(t, conn, time.Time{}, 2, 0)
	good := signHead(t, conn, k)
	ctx := context.Background()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := CheckHead(ctx, tx, good); err != nil {
		t.Fatalf("a real head: %v", err)
	}
	// The claims a forger wants: the chain's own hash at an entry, which is
	// what a head over a recomputed chain would have to say.
	var id int64
	var hash []byte
	if err := tx.QueryRow(ctx, `SELECT id, entry_hash FROM core.audit_events ORDER BY id LIMIT 1`).
		Scan(&id, &hash); err != nil {
		t.Fatal(err)
	}
	c := &HeadClaims{Issuer: "x", ThroughID: id, EntryHash: fmt.Sprintf("%x", hash), IssuedAt: 1}
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, jws := range map[string]string{
		"a key never held":                             headKey{"stranger", stranger}.sign(t, c, HeadType),
		"a real key, an ID token's typ":                k.sign(t, c, "JWT"),
		"another key signing under the real key's kid": headKey{k.kid, stranger}.sign(t, c, HeadType),
	} {
		if _, err := CheckHead(ctx, tx, jws); err == nil {
			t.Errorf("%s was accepted as a head", name)
		}
	}
}

// A head is due once an interval has passed and something was written since.
func TestAHeadIsSignedOnlyWhenDue(t *testing.T) {
	conn := scratchChain(t)
	k := newHeadKey(t, conn, "due-key")
	ctx := context.Background()
	due := func(interval time.Duration) bool {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		c, err := HeadToSign(ctx, tx, "https://heads.test", time.Now(), interval)
		if err != nil {
			t.Fatal(err)
		}
		return c != nil
	}
	if due(time.Hour) {
		t.Error("a head is due on an empty trail")
	}
	writeAt(t, conn, time.Time{}, 2, 0)
	if !due(time.Hour) {
		t.Error("no head is due with entries and none signed")
	}
	signHead(t, conn, k)
	if due(time.Hour) || due(0) {
		t.Error("a head is due with nothing written since the last")
	}
	writeAt(t, conn, time.Time{}, 2, 1)
	if due(time.Hour) || !due(0) {
		t.Error("the interval does not decide when the next head is due")
	}
}
