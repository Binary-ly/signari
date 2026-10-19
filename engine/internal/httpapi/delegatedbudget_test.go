package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
)

// A wrong password for an account still being migrated was checked by the old
// provider and charged to no budget here: unlimited guessing, each guess
// forwarded to a third party in this server's name.
func TestADelegatedSignInFailureIsChargedLikeAnyOther(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerAccountWindow)
	ctx := context.Background()

	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root

	const oldPassword = "the-password-the-old-system-knows"
	var asked atomic.Int64
	old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("password") == oldPassword {
			_, _ = w.Write([]byte(`{"access_token":"accepted","token_type":"Bearer"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(old.Close)
	f.srv.delegator = delegated.NewWithClient(old.Client())

	var source string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.migration_sources (org_id, kind, display_name, token_endpoint, client_id, enabled)
		VALUES ($1::uuid, 'oidc_password', 'Old', $2, 'old-client', true) RETURNING id::text`,
		f.orgID, old.URL).Scan(&source); err != nil {
		t.Fatalf("migration source: %v", err)
	}
	// Removed with the test: every run left one, about 120 by the time it was
	// noticed, each an enabled source pointing at a port long gone.
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.migration_sources WHERE id = $1::uuid`, source)
	})
	pending := func(email string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.users (org_id, email, user_handle, migration_state, migration_source_id)
			VALUES ($1::uuid, $2, decode(md5($2) || md5($2 || 'x') || md5($2 || 'y') || md5($2 || 'z'), 'hex'),
			        'pending', $3::uuid)`, f.orgID, email, source); err != nil {
			t.Fatalf("pending user: %v", err)
		}
	}
	n := time.Now().UnixNano()
	target := fmt.Sprintf("pending-%d@example.test", n)
	pending(target)

	attempt := func(addr, username, password string) *httptest.ResponseRecorder {
		t.Helper()
		return passwordSignIn(t, f.srv, addr, username, password)
	}
	addr := func(i int) string { return fmt.Sprintf("198.18.%d.%d", (n/7)%250, i%250+1) }

	// A different address each time, so only the account's budget can stop it.
	for i := 0; i < signInPerAccountLimit; i++ {
		if rec := attempt(addr(i), target, "a-guess"); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("throttled after only %d delegated failures", i)
		}
	}
	before := asked.Load()
	if rec := attempt(addr(signInPerAccountLimit), target, "a-guess"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d delegated failures against one account the next gave %d, want 429",
			signInPerAccountLimit, rec.Code)
	}
	if asked.Load() != before {
		t.Error("the old provider was still asked once the account's budget was spent")
	}

	// The migration itself still works for somebody under budget.
	other := fmt.Sprintf("pending-%d-b@example.test", n)
	pending(other)
	if rec := attempt(addr(200), other, oldPassword); !strings.Contains(rec.Body.String(), "signed in") {
		t.Fatalf("the right password for a pending account gave %d: %.200s", rec.Code, rec.Body.String())
	}
	var migrated string
	if err := f.pool.QueryRow(ctx, `SELECT migration_state FROM core.users WHERE email = $1`, other).
		Scan(&migrated); err != nil || migrated == "pending" {
		t.Fatalf("the accepted account is still %q (%v)", migrated, err)
	}
}
