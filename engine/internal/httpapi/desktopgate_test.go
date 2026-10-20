package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store"
)

// The desktop outpost asks the sign-in flow whether a second factor is due, as
// LDAP, RADIUS and the outpost endpoint do. It asked only whether one was
// enrolled, so under an operator's unconditional mfa stage a person with
// nothing enrolled signed in at a desktop on a password the sign-in page would
// not have accepted alone.
func TestTheDesktopOutpostAsksTheFlowWhetherASecondFactorIsDue(t *testing.T) {
	f := newSignInFixture(t)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	ctx := context.Background()

	token := "desktop-" + hex.EncodeToString([]byte(t.Name()))[:16] + fmt.Sprint(time.Now().UnixNano())
	sum := sha256.Sum256([]byte(token))
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash)
		VALUES ($1::uuid, 'desk-gate', 'desktop', $2)`, f.orgID, sum[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outposts WHERE token_hash = $1`, sum[:])
	})
	post := func(code string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{
			"username": f.email, "password": signInTestPassword, "code": code,
		})
		r := httptest.NewRequest(http.MethodPost, "/outpost/desktop", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		result, _ := out["result"].(string)
		return rec.Code, result
	}

	if code, result := post(""); code != http.StatusOK || result != "authenticated" {
		t.Fatalf("under the built-in flow, with nothing enrolled, a password answered %d %q", code, result)
	}

	f.applyFlow(t, `
version: 1
flows:
  - name: mfa-for-everyone
    on: authentication
    stages:
      - password
      - mfa
      - session
    tests:
      - name: always challenged
        given: {}
        expect: [password, mfa, session]
`)
	if code, result := post(""); code != http.StatusUnauthorized {
		t.Fatalf("under an unconditional mfa stage, with nothing enrolled, a password answered %d %q, "+
			"want 401", code, result)
	}

	secret := giveTOTP(t, f)
	if code, result := post(""); code != http.StatusOK || result != "second_factor_required" {
		t.Fatalf("enrolled, without a code: %d %q, want second_factor_required", code, result)
	}
	right := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.DefaultDigits)
	if code, result := post(right); code != http.StatusOK || result != "authenticated" {
		t.Fatalf("enrolled, with the right code: %d %q", code, result)
	}
}

// Every desktop refusal costs a hash (1.90). An unknown person, an empty
// password and a person with no password credential were answered before any
// hashing, a wrong password after Argon2, so the time of the one answer the
// outpost gives said which it was. Timed, so the bound is loose: each must take
// at least half as long as a wrong password, best of three; unhashed they took
// a small fraction of it.
func TestEveryDesktopRefusalCostsAHash(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	token := desktopOutpost(t, f)
	var noPassword string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, $2, decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING email`, f.orgID, "nopassword-"+fmt.Sprint(time.Now().UnixNano())+"@example.test").Scan(&noPassword); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, noPassword)
	})

	timed := func(username, password string) time.Duration {
		t.Helper()
		best := time.Duration(1 << 62)
		for range 3 {
			body, _ := json.Marshal(map[string]string{"username": username, "password": password})
			r := httptest.NewRequest(http.MethodPost, "/outpost/desktop", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			start := time.Now()
			f.srv.Routes().ServeHTTP(rec, r)
			if took := time.Since(start); took < best {
				best = took
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s answered %d, want 401", username, rec.Code)
			}
		}
		return best
	}
	wrong := timed(f.email, "not-the-password-at-all")
	for name, try := range map[string][2]string{
		"an unknown person":         {"nobody-" + fmt.Sprint(time.Now().UnixNano()) + "@example.test", "anything-at-all"},
		"an empty password":         {f.email, ""},
		"a person with no password": {noPassword, "anything-at-all"},
	} {
		if took := timed(try[0], try[1]); took < wrong/2 {
			t.Errorf("%s was refused in %v and a wrong password in %v: the time tells them apart", name, took, wrong)
		}
	}
}

// desktopOutpost registers a desktop outpost in the fixture's organisation and
// returns its token.
func desktopOutpost(t *testing.T, f *signInFixture) string {
	t.Helper()
	token := "desktop-" + fmt.Sprint(time.Now().UnixNano())
	sum := sha256.Sum256([]byte(token))
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.outposts (org_id, name, kind, token_hash)
		VALUES ($1::uuid, $2, 'desktop', $3)`, f.orgID, token, sum[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outposts WHERE token_hash = $1`, sum[:])
	})
	return token
}

// The desktop draws on the account's sign-in failure budget, the form's and
// LDAP's (1.91). It charged nothing, so an outpost token could spend its whole
// allowance of calls guessing one person's password. A right password costs
// nothing; the guess past the budget is refused without a hash; and the form
// then refuses too, since the two doors share one budget.
func TestTheDesktopDrawsOnTheAccountsSignInBudget(t *testing.T) {
	f := newSignInFixture(t)
	token := desktopOutpost(t, f)
	post := func(password string) int {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"username": f.email, "password": password})
		r := httptest.NewRequest(http.MethodPost, "/outpost/desktop", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec.Code
	}
	for i := range signInPerAccountLimit {
		if code := post(signInTestPassword); code != http.StatusOK {
			t.Fatalf("right password %d answered %d; a right password must cost nothing", i+1, code)
		}
	}
	for i := range signInPerAccountLimit {
		if code := post("a-wrong-guess"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d answered %d, want 401", i+1, code)
		}
	}
	if code := post("a-wrong-guess"); code != http.StatusTooManyRequests {
		t.Fatalf("the guess past the account's budget answered %d, want 429", code)
	}
	if code := post(signInTestPassword); code != http.StatusTooManyRequests {
		t.Errorf("the right password while the budget is spent answered %d, want 429", code)
	}
	// The bucket the form reads (allowSignInAttempt), so the form refuses too.
	spent, err := store.CountRate(context.Background(), f.pool,
		"signin:fail:user:"+strings.ToLower(f.email), signInPerAccountWindow)
	if err != nil {
		t.Fatal(err)
	}
	if spent < signInPerAccountLimit {
		t.Errorf("the form's budget for the account holds %d failures after %d at the desktop: "+
			"two budgets on one credential", spent, signInPerAccountLimit)
	}
}
