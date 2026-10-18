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
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
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
