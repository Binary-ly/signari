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
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store"
)

// The second-factor step's limits, through the real routes: the budget that
// answers 429, the ceiling that disables a factor and tells the account holder,
// and the desktop door onto the same factors.

// mfaStep is a browser holding a pending authentication for the fixture user,
// exactly what a correct password leaves behind on an account with a factor.
type mfaStep struct {
	f          *signInFixture
	pending    string
	csrfField  string
	csrfCookie string
	ip         string
}

func newMFAStep(t *testing.T, f *signInFixture) *mfaStep {
	t.Helper()
	m := &mfaStep{f: f, ip: testClientIP(t)}

	rec := httptest.NewRecorder()
	if err := f.srv.setPendingCookie(rec, f.userID, f.orgID, []string{"pwd"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == PendingCookieName {
			m.pending = c.Value
		}
	}

	get := httptest.NewRecorder()
	f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login", nil))
	match := csrfValue.FindStringSubmatch(get.Body.String())
	if match == nil {
		t.Fatal("the sign-in form carries no CSRF field")
	}
	m.csrfField = match[1]
	for _, c := range get.Result().Cookies() {
		if c.Name == CSRFCookieName {
			m.csrfCookie = c.Value
		}
	}
	if m.pending == "" || m.csrfCookie == "" {
		t.Fatal("no pending authentication or CSRF cookie to submit with")
	}
	return m
}

func (m *mfaStep) submit(code string) *httptest.ResponseRecorder {
	form := url.Values{"code": {code}, csrfFormField: {m.csrfField}}
	r := httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: PendingCookieName, Value: m.pending})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m.csrfCookie})
	r.RemoteAddr = m.ip + ":5555"
	rec := httptest.NewRecorder()
	m.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func sessionSet(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" && c.MaxAge >= 0 {
			return true
		}
	}
	return false
}

func giveRecoveryCodes(t *testing.T, f *signInFixture) []string {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	codes, err := store.GenerateRecoveryCodes(ctx, tx, f.userID, f.orgID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return codes
}

func clearSecondFactorBucket(t *testing.T, f *signInFixture) {
	t.Helper()
	clean := func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.rate_limits WHERE bucket_key = $1`, secondFactorAccountKey(f.userID))
	}
	clean()
	t.Cleanup(clean)
}

// An account whose second factor is not an authenticator app had no limit at
// the code step: wrong recovery codes were charged to nothing.
func TestRecoveryCodeGuessingIsRefusedPastTheBudget(t *testing.T) {
	f := newSignInFixture(t)
	clearSecondFactorBucket(t, f)
	clearOfWindowEdge(t, secondFactorPerAccountWindow)
	codes := giveRecoveryCodes(t, f)
	step := newMFAStep(t, f)

	const wrong = "AAAAA-BBBBB-CCCCC-DDDDD"
	for i := 1; i <= secondFactorPerAccountLimit; i++ {
		if rec := step.submit(wrong); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d answered %d, want 401", i, rec.Code)
		}
	}
	rec := step.submit(wrong)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("guess %d answered %d, want 429", secondFactorPerAccountLimit+1, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("the refusal does not say when to try again")
	}

	// Refused before it is checked, so the right code is not spent by a request
	// that was going to be refused anyway.
	if rec := step.submit(codes[0]); rec.Code != http.StatusTooManyRequests || sessionSet(rec) {
		t.Fatalf("the right code over budget answered %d (session=%v), want 429 and no session",
			rec.Code, sessionSet(rec))
	}
	var used, counted int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM core.recovery_codes WHERE user_id = $1::uuid AND used_at IS NOT NULL),
		       (SELECT COALESCE(max(failed_attempts), 0) FROM core.recovery_code_failures WHERE user_id = $1::uuid)`,
		f.userID).Scan(&used, &counted); err != nil {
		t.Fatal(err)
	}
	if used != 0 {
		t.Errorf("%d recovery code(s) spent by refused requests", used)
	}
	if counted != secondFactorPerAccountLimit {
		t.Errorf("recovery code failures counted %d, want %d", counted, secondFactorPerAccountLimit)
	}
}

// A guess is a guess whichever box it was typed into: the code step reads and
// charges the sign-in form's per-address budget.
func TestTheCodeStepDrawsOnTheAddressBudget(t *testing.T) {
	f := newSignInFixture(t)
	clearSecondFactorBucket(t, f)
	clearOfWindowEdge(t, signInPerIPWindow)
	giveRecoveryCodes(t, f)
	step := newMFAStep(t, f)
	ctx := context.Background()
	key := "signin:fail:ip:" + step.ip

	if rec := step.submit("AAAAA-BBBBB-CCCCC-DDDDD"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code answered %d, want 401", rec.Code)
	}
	if n, err := store.CountRate(ctx, f.pool, key, signInPerIPWindow); err != nil || n != 1 {
		t.Fatalf("the address budget holds %d after one wrong code (err %v), want 1", n, err)
	}

	for i := 1; i < signInPerIPLimit; i++ {
		if _, err := store.AllowRate(ctx, f.pool, key, signInPerIPLimit, signInPerIPWindow); err != nil {
			t.Fatal(err)
		}
	}
	if rec := step.submit("AAAAA-BBBBB-CCCCC-DDDDD"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a code from an address that spent its budget answered %d, want 429", rec.Code)
	}
}

// wrongTOTP returns a six-digit code that no window around now accepts.
func wrongTOTP(secret []byte) string {
	now := time.Now()
	valid := map[string]bool{}
	for i := int64(-2); i <= 2; i++ {
		valid[mfa.Code(secret, mfa.Counter(now, mfa.DefaultPeriod)+i, mfa.DefaultDigits)] = true
	}
	for n := 0; ; n++ {
		c := fmt.Sprintf("%06d", n)
		if !valid[c] {
			return c
		}
	}
}

// NIST SP 800-63B §3.2.2: the hundredth consecutive failure disables the
// authenticator. The holder is told, and a recovery code still gets them in.
func TestTheCeilingFailureDisablesTheFactorAndTellsTheHolder(t *testing.T) {
	f := newSignInFixture(t)
	clearSecondFactorBucket(t, f)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	ctx := context.Background()

	secret := giveTOTP(t, f)
	codes := giveRecoveryCodes(t, f)
	// Ninety-nine failures already behind it, and not currently paused.
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.totp_credentials SET failed_attempts = $2, locked_until = NULL
		 WHERE user_id = $1::uuid`, f.userID, store.MaxConsecutiveFactorFailures-1); err != nil {
		t.Fatal(err)
	}
	step := newMFAStep(t, f)

	if rec := step.submit(wrongTOTP(secret)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the hundredth wrong code answered %d, want 401", rec.Code)
	}
	var disabled bool
	if err := f.pool.QueryRow(ctx,
		`SELECT disabled_at IS NOT NULL FROM core.totp_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("the hundredth consecutive failure did not disable the authenticator")
	}

	subject := f.srv.notifierFor(ctx, f.userID).Text("mail.totp.disabled.subject")
	told := 0
	for _, m := range mailer.messages() {
		if m.To == f.email && m.Subject == subject {
			told++
		}
	}
	if told != 1 {
		t.Fatalf("the account holder was told %d time(s) that the authenticator was disabled, want 1", told)
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM core.audit_events
		 WHERE subject_id = $1::uuid AND event_type = 'mfa.factor_disabled'
		   AND detail->>'factor' = 'totp'`, f.userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Errorf("%d audit records of the authenticator being disabled, want 1", audited)
	}

	// The right code no longer works: disabled is not paused.
	right := mfa.Code(secret, mfa.Counter(time.Now(), mfa.DefaultPeriod), mfa.DefaultDigits)
	if rec := step.submit(right); sessionSet(rec) {
		t.Fatal("a disabled authenticator's code still signed somebody in")
	}
	// Nor is anybody told twice.
	if rec := step.submit(wrongTOTP(secret)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code after the ceiling answered %d", rec.Code)
	}
	told = 0
	for _, m := range mailer.messages() {
		if m.Subject == subject {
			told++
		}
	}
	if told != 1 {
		t.Errorf("failures after the ceiling sent %d notices in all, want the one", told)
	}

	// Still a multi-factor account, so the way in is a recovery code -- not a
	// password on its own.
	if has, err := store.HasSecondFactor(ctx, f.pool, f.userID); err != nil || !has {
		t.Fatalf("disabling the authenticator left the account without a second factor (%v, %v)", has, err)
	}
	if rec := step.submit(codes[0]); !sessionSet(rec) {
		t.Fatalf("a recovery code did not sign the holder in once the authenticator was disabled "+
			"(status %d)", rec.Code)
	}
}

// The desktop door verified codes inside a transaction it then rolled back on
// a wrong one, so the failure count -- pause and ceiling both -- was undone by
// the request that incurred it, and the authenticator could be guessed at
// without limit from there.
func TestTheDesktopDoorKeepsTheFailureCount(t *testing.T) {
	f := newSignInFixture(t)
	clearSecondFactorBucket(t, f)
	clearOfWindowEdge(t, secondFactorPerAccountWindow)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	ctx := context.Background()
	secret := giveTOTP(t, f)

	token := "desktop-" + hex.EncodeToString([]byte(t.Name()))[:16] + fmt.Sprint(time.Now().UnixNano())
	sum := sha256.Sum256([]byte(token))
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash)
		VALUES ($1::uuid, 'desk', 'desktop', $2)`, f.orgID, sum[:]); err != nil {
		t.Fatal(err)
	}

	post := func(code string) int {
		body, _ := json.Marshal(map[string]string{
			"username": f.email, "password": signInTestPassword, "code": code,
		})
		r := httptest.NewRequest(http.MethodPost, "/outpost/desktop", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec.Code
	}

	if code := post(wrongTOTP(secret)); code != http.StatusUnauthorized {
		t.Fatalf("a wrong desktop code answered %d, want 401", code)
	}
	var failures int
	if err := f.pool.QueryRow(ctx,
		`SELECT failed_attempts FROM core.totp_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 1 {
		t.Fatalf("after one wrong desktop code the authenticator has %d failures recorded, want 1", failures)
	}

	// And the desktop draws on the browser's per-account budget.
	for i := 2; i <= secondFactorPerAccountLimit; i++ {
		_ = post(wrongTOTP(secret))
	}
	if code := post(wrongTOTP(secret)); code != http.StatusTooManyRequests {
		t.Fatalf("a desktop code past the account's budget answered %d, want 429", code)
	}
}
