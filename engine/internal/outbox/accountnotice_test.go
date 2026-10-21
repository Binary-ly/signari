package outbox

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"signari.dev/engine/internal/store"
)

func randomUUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// A notice the Admin API or the CLI queued for an account's holder waits for a
// process that can tell them, is told once that process drains it, and is
// closed rather than retried when the account is gone (4.14). Other packages
// queue notices into the same table, so only this test's are looked at.
func TestAccountNoticesWaitThenReachTheHolder(t *testing.T) {
	pool := drainTestPool(t)
	ctx := context.Background()
	held, gone := randomUUID(t), randomUUID(t)
	for _, u := range []string{held, gone} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnqueueAccountNotice(ctx, tx, store.AccountNotice{UserID: u,
			Notice: store.NoticeFactorRemoved, Factor: "totp"}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	state := func(u string) (delivered bool, lastError string) {
		t.Helper()
		var e *string
		if err := pool.QueryRow(ctx, `SELECT delivered_at IS NOT NULL, last_error FROM core.outbox
			WHERE topic = $1 AND payload->>'user_id' = $2`, store.AccountNoticeTopic, u).Scan(&delivered, &e); err != nil {
			t.Fatal(err)
		}
		if e != nil {
			lastError = *e
		}
		return
	}

	w := drainWorker(t, pool, 500)
	if n, err := w.DrainAccountNotices(ctx); err != nil || n != 0 {
		t.Fatalf("with no notifier the drain delivered %d (%v)", n, err)
	}
	if d, _ := state(held); d {
		t.Fatal("a notice was closed by a process that cannot tell anybody")
	}

	var mu sync.Mutex
	var told []store.AccountNotice
	w.SetAccountNotifier(func(_ context.Context, n store.AccountNotice) error {
		switch n.UserID {
		case gone:
			return ErrNoSuchAccount
		case held:
			mu.Lock()
			told = append(told, n)
			mu.Unlock()
		}
		return nil
	})
	if _, err := w.DrainAccountNotices(ctx); err != nil {
		t.Fatal(err)
	}
	if len(told) != 1 || told[0].Notice != store.NoticeFactorRemoved || told[0].Factor != "totp" {
		t.Fatalf("the holder was told %v", told)
	}
	if d, _ := state(held); !d {
		t.Error("a delivered notice is still queued")
	}
	if d, why := state(gone); !d || why == "" {
		t.Errorf("a notice for a deleted account: closed %v, reason %q", d, why)
	}
	if _, err := w.DrainAccountNotices(ctx); err != nil || len(told) != 1 {
		t.Errorf("a second drain told the holder again (%d, %v)", len(told), err)
	}
}
