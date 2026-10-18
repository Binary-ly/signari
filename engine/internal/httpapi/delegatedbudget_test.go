package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		get := httptest.NewRequest(http.MethodGet, "/login", nil)
		get.RemoteAddr = addr + ":443"
		grec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(grec, get)
		var cookie string
		for _, c := range grec.Result().Cookies() {
			if c.Name == CSRFCookieName {
				cookie = c.Value
			}
		}
		const marker = `name="` + csrfFormField + `" value="`
		body := grec.Body.String()
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("the sign-in form carries no CSRF field: %d", grec.Code)
		}
		rest := body[i+len(marker):]
		form := url.Values{"username": {username}, "password": {password},
			csrfFormField: {rest[:strings.Index(rest, `"`)]}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookie})
		req.RemoteAddr = addr + ":443"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
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
