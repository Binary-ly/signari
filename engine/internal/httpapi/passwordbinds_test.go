package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// LDAP binds, RADIUS PAP and outposts carry a password and nothing else. None
// of them consulted the flow's mfa stage, so the sign-in page demanded a second
// factor while the directory port next to it accepted the password alone.

func (f *signInFixture) binder() *LDAPAuthenticator {
	return NewLDAPAuthenticator(f.pool, passwords.NewHasher(passwords.MemoryBudgetMiB), f.orgID,
		slog.New(slog.NewTextHandler(io.Discard, nil))).WithMFAGate(f.srv.BindDemandsMFA)
}

// A person whose password has not been rehashed to the current policy binds,
// as they sign in on the web (2.55). The bind query alone required
// `is_current`, which only drives the migration figures and which both
// importers set false, so everybody imported was refused at the directory
// until their first web sign-in -- with the password the form took.
func TestAPasswordNotYetRehashedStillBinds(t *testing.T) {
	f := newSignInFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.password_credentials SET is_current = false WHERE user_id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.binder().Authenticate(context.Background(), f.email, signInTestPassword); err != nil {
		t.Fatalf("a bind with the right password for a not-yet-rehashed credential was refused: %v", err)
	}
	if _, err := f.binder().Authenticate(context.Background(), f.email, "not-the-password"); err == nil {
		t.Error("a wrong password bound")
	}
}

func (f *signInFixture) setPasswordBinds(t *testing.T, policy string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.organizations SET password_only_binds = $2 WHERE id = $1::uuid`,
		f.orgID, policy); err != nil {
		t.Fatal(err)
	}
}

func (f *signInFixture) enrolSecondFactor(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.totp_credentials (user_id, org_id, secret_enc, confirmed_at)
		VALUES ($1::uuid, $2::uuid, decode(md5('s'),'hex'), now())`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
}

func (f *signInFixture) bindFailures(t *testing.T) int {
	t.Helper()
	n, err := store.CountRate(context.Background(), f.pool,
		"signin:fail:user:"+strings.ToLower(f.email), signInPerAccountWindow)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// An organisation created from now on refuses by default; the column default is
// the setting most deployments will never look at.
func TestANewOrganisationRefusesPasswordOnlyBindsUnderAnMFAMandate(t *testing.T) {
	f := newSignInFixture(t)
	var policy string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT password_only_binds FROM core.organizations WHERE id = $1::uuid`, f.orgID).
		Scan(&policy); err != nil {
		t.Fatal(err)
	}
	if policy != store.PasswordBindsRefuseWhenMFA {
		t.Fatalf("a new organisation starts with password_only_binds = %q, want %q",
			policy, store.PasswordBindsRefuseWhenMFA)
	}
}

func TestAPasswordAloneDoesNotBindSomebodyTheFlowWouldChallenge(t *testing.T) {
	f := newSignInFixture(t)
	f.setPasswordBinds(t, store.PasswordBindsRefuseWhenMFA)
	f.enrolSecondFactor(t)
	ctx := context.Background()

	id, err := f.binder().Authenticate(ctx, f.email, signInTestPassword)
	if err == nil || id != nil {
		t.Fatal("an LDAP bind with only a password signed in somebody with a second factor")
	}
	if !errors.Is(err, errMFARequired) {
		t.Errorf("refused as %q rather than for want of a second factor; a correct password "+
			"refused as a wrong one is charged to the person's guessing budget", err)
	}
	// The password was right: a VPN retrying it must not spend the person's
	// budget at the sign-in page.
	if n := f.bindFailures(t); n != 0 {
		t.Errorf("a correct password refused for want of a second factor charged %d failure(s)", n)
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		 WHERE subject_id = $1::uuid AND event_type = 'login.failed'
		   AND detail->>'reason' = 'second_factor_required'`, f.userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Errorf("%d audit records of the refusal, want 1", audited)
	}

	// RADIUS PAP is the same credential path under another label.
	radius := NewRADIUSAuthenticator(f.pool, passwords.NewHasher(passwords.MemoryBudgetMiB), f.orgID,
		slog.New(slog.NewTextHandler(io.Discard, nil))).WithMFAGate(f.srv.BindDemandsMFA)
	if err := radius.Authenticate(ctx, f.email, signInTestPassword); err == nil {
		t.Error("RADIUS PAP accepted a password alone from somebody with a second factor")
	}

	// And an outpost, through the real route.
	token := fmt.Sprintf("ldap-outpost-%d", time.Now().UnixNano())
	sum := sha256.Sum256([]byte(token))
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash) VALUES ($1::uuid, 'dir', 'ldap', $2)`,
		f.orgID, sum[:]); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"Username": f.email, "Password": signInTestPassword})
	r := httptest.NewRequest(http.MethodPost, "/outpost/authenticate", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("an LDAP outpost bind with only a password answered %d, want 401", rec.Code)
	}

	// `allow` is the old behaviour, and still a choice an operator can make.
	f.setPasswordBinds(t, store.PasswordBindsAllow)
	if id, err := f.binder().Authenticate(ctx, f.email, signInTestPassword); err != nil || id == nil {
		t.Fatalf("with password-only binds allowed the bind was refused: %v", err)
	}
}

// The setting refuses who the sign-in page would challenge, and nobody else.
func TestSomebodyTheFlowWouldNotChallengeStillBinds(t *testing.T) {
	f := newSignInFixture(t)
	f.setPasswordBinds(t, store.PasswordBindsRefuseWhenMFA)
	if id, err := f.binder().Authenticate(context.Background(), f.email, signInTestPassword); err != nil || id == nil {
		t.Fatalf("somebody with no second factor, under the built-in flow, could not bind: %v", err)
	}
}

// An unconditional mfa stage demands a second factor of everybody, so nobody
// binds with a password alone -- the same answer the sign-in page gives.
func TestAnUnconditionalMFAStageRefusesEveryPasswordOnlyBind(t *testing.T) {
	f := newSignInFixture(t)
	f.setPasswordBinds(t, store.PasswordBindsRefuseWhenMFA)
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
	_, err := f.binder().Authenticate(context.Background(), f.email, signInTestPassword)
	if !errors.Is(err, errMFARequired) {
		t.Fatalf("under an unconditional mfa stage a password-only bind gave %v, want a refusal", err)
	}
}

// Not knowing whether somebody has a second factor is not the same as knowing
// they have none.
func TestABindIsRefusedWhenTheMandateCannotBeChecked(t *testing.T) {
	f := newSignInFixture(t)
	f.setPasswordBinds(t, store.PasswordBindsRefuseWhenMFA)
	broken := f.binder().WithMFAGate(func(context.Context, string, string) (bool, error) {
		return false, errors.New("database unavailable")
	})
	if id, err := broken.Authenticate(context.Background(), f.email, signInTestPassword); err == nil || id != nil {
		t.Fatal("a bind went through while the second-factor check was failing")
	}
}
