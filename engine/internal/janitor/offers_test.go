package janitor

import (
	"context"
	"testing"
)

// A credential offer is swept once no token minted from it can still be live,
// and not before: the credential endpoint reads the offer to learn what its
// token may be exchanged for. Nothing swept them at all (2.07c).
func TestASpentCredentialOfferIsSweptOnlyOnceItsTokenCannotBeLive(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	var orgID, userID string
	if err := pool.QueryRow(ctx, `SELECT org_id::text, id::text FROM core.users LIMIT 1`).
		Scan(&orgID, &userID); err != nil {
		t.Skipf("no user to make an offer for: %v", err)
	}
	plant := func(age, redeemed string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO core.preauthorized_codes (org_id, user_id, code_hash, configuration_ids,
			                                      expires_at, redeemed_at, access_token_jti)
			VALUES ($1::uuid, $2::uuid, decode(md5(gen_random_uuid()::text), 'hex'), ARRAY['cfg'],
			        now() - $3::interval,
			        CASE WHEN $4 = '' THEN NULL ELSE now() - $4::interval END,
			        CASE WHEN $4 = '' THEN NULL ELSE gen_random_uuid()::text END)
			RETURNING id::text`, orgID, userID, age, redeemed).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := plant("3 hours", "")               // expired long ago, never redeemed
	live := plant("10 minutes", "15 minutes") // redeemed; its token may still be live
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.preauthorized_codes WHERE id = ANY($1::uuid[])`,
			[]string{old, live})
	})

	exists := func(id string) bool {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.preauthorized_codes WHERE id = $1::uuid)`,
			id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for pass := 0; pass < 10 && exists(old); pass++ {
		if _, err := RunOnce(ctx, pool, discard()); err != nil {
			t.Fatal(err)
		}
	}
	if exists(old) {
		t.Error("an offer expired three hours ago survived the janitor")
	}
	if !exists(live) {
		t.Error("an offer whose token may still be live was swept")
	}
}
