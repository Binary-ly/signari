package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// What an organisation asks of an authenticator reaches the browser, and what
// it refuses is refused: user verification, resident key, attachment,
// algorithms, timeout and hints were fixed in code, so an organisation could
// not issue security keys without a PIN, nor ask for platform authenticators
// only (4.11).

// setCeremony writes the organisation's policy through its one writer.
func setCeremony(t *testing.T, j *passkeyJourney, p store.WebAuthnPolicy) {
	t.Helper()
	ctx := context.Background()
	tx, err := j.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if p.Conveyance == "" {
		p.Conveyance = "none"
	}
	if _, err := store.SetWebAuthnPolicy(ctx, tx, j.orgID, p); err != nil {
		t.Fatalf("setting the policy: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.webauthn_policy WHERE org_id = $1::uuid`, j.orgID)
	})
}

type ceremonyOptions struct {
	PublicKey struct {
		Timeout          int                 `json:"timeout"`
		UserVerification string              `json:"userVerification"`
		Hints            []string            `json:"hints"`
		Extensions       map[string]any      `json:"extensions"`
		Params           []struct{ Alg int } `json:"pubKeyCredParams"`
		Selection        struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
			Attachment       string `json:"authenticatorAttachment"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

func optionsOf(t *testing.T, rec interface{ Bytes() []byte }) ceremonyOptions {
	t.Helper()
	var o ceremonyOptions
	if err := json.Unmarshal(rec.Bytes(), &o); err != nil {
		t.Fatalf("the ceremony options did not parse: %v", err)
	}
	return o
}

func TestTheCeremonyIsWhatTheOrganisationAsked(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	setCeremony(t, j, store.WebAuthnPolicy{RefuseCloned: true, UserVerification: "preferred",
		ResidentKey: "preferred", Attachment: "cross-platform", Algorithms: []int{-8, -7},
		TimeoutSeconds: 60, Hints: []string{"security-key", "hybrid"}})

	begin := j.post(t, "/account/passkeys/begin", nil, session)
	if begin.Code != http.StatusOK {
		t.Fatalf("registration begin answered %d: %s", begin.Code, begin.Body)
	}
	o := optionsOf(t, begin.Body).PublicKey
	sel := o.Selection
	if sel.ResidentKey != "preferred" || sel.UserVerification != "preferred" || sel.Attachment != "cross-platform" {
		t.Errorf("registration asked for resident key %q, verification %q, attachment %q",
			sel.ResidentKey, sel.UserVerification, sel.Attachment)
	}
	var algs []int
	for _, p := range o.Params {
		algs = append(algs, p.Alg)
	}
	if !slices.Equal(algs, []int{-8, -7}) {
		t.Errorf("registration offered algorithms %v, want EdDSA then ES256", algs)
	}
	if o.Timeout != 60000 || !slices.Equal(o.Hints, []string{"security-key", "hybrid"}) {
		t.Errorf("registration timeout %dms, hints %v", o.Timeout, o.Hints)
	}
	if o.Extensions["credProps"] != true {
		t.Errorf("registration did not ask whether the credential is discoverable: %v", o.Extensions)
	}

	login := j.post(t, "/login/passkey/begin", nil)
	if login.Code != http.StatusOK {
		t.Fatalf("sign-in begin answered %d: %s", login.Code, login.Body)
	}
	if o := optionsOf(t, login.Body).PublicKey; o.UserVerification != "preferred" || o.Timeout != 60000 ||
		!slices.Equal(o.Hints, []string{"security-key", "hybrid"}) {
		t.Errorf("sign-in asked for verification %q, timeout %dms, hints %v", o.UserVerification, o.Timeout, o.Hints)
	}

	// A key after a password: the policy's hints and timeout, and verification
	// preferred whatever the policy says, since the password is the other factor.
	j.register(t, session)
	step := j.passwordStep(t, "")
	mfa := step.begin(t)
	if mfa.Code != http.StatusOK {
		t.Fatalf("the second factor's ceremony answered %d: %s", mfa.Code, mfa.Body)
	}
	if o := optionsOf(t, mfa.Body).PublicKey; o.UserVerification != "preferred" || o.Timeout != 60000 ||
		!slices.Equal(o.Hints, []string{"security-key", "hybrid"}) {
		t.Errorf("the second factor asked for verification %q, timeout %dms, hints %v",
			o.UserVerification, o.Timeout, o.Hints)
	}
}

// Under a policy that only prefers user verification, a key without a PIN or
// biometric signs in as one factor: the assertion's flag decides, never the
// record's, which the library returns latched to true. Where the flow asks a
// second factor of an account that has one, the same key touched again is not
// it.
func TestAPasskeyThatDidNotVerifyItsUserIsOneFactor(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	cred := j.register(t, session)
	tap := func(p *ceremonyParts) { p.Flags = flagUP }

	// Required, the default: a tap without verification is refused.
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred, tap)); ok {
		t.Fatal("under the default policy a passkey without user verification signed in")
	}

	setCeremony(t, j, store.WebAuthnPolicy{RefuseCloned: true, UserVerification: "preferred"})

	// The built-in flow asks a second factor of an account with one, and the
	// key is one: the tap leaves a pending sign-in on the code page.
	rec := j.signIn(t, cred, tap)
	if _, _, ok := j.sessionFor(t, rec); ok {
		t.Fatal("a tap without verification signed in where the flow asks a second factor")
	}
	step := &mfaKeyStep{j: j, page: rec, pending: cookieFrom(rec, PendingCookieName)}
	if c := cookieFrom(rec, CSRFCookieName); c != nil {
		step.csrfCookie = c.Value
	}
	if m := csrfValue.FindStringSubmatch(rec.Body.String()); m != nil {
		step.csrfField = m[1]
	}
	if step.pending == nil || step.csrfCookie == "" || step.csrfField == "" {
		t.Fatalf("the tap did not leave a pending sign-in on the code page: %d %s", rec.Code, rec.Body)
	}
	begin := step.begin(t)
	if o := optionsOf(t, begin.Body).PublicKey; o.UserVerification != "required" {
		t.Errorf("after a key, the second key was asked for verification %q, want required", o.UserVerification)
	}
	again := step.submit(t, j.auth.get(t, begin.Body.Bytes(), cred, tap), cookieFrom(begin, CeremonyCookieName))
	if _, _, ok := j.sessionFor(t, again); ok {
		t.Fatal("the same key touched twice was taken for two factors")
	}
	amr, acr, ok := j.sessionFor(t, step.withKey(t, cred))
	if !ok || acr != oauth.ACRMultiFactor {
		t.Errorf("the key with verification after the tap: session %v, amr %v, acr %q", ok, amr, acr)
	}

	// A flow that does not ask: the tap is a session of one factor.
	j.applyFlow(t, `
version: 1
flows:
  - name: passkey-or-password
    on: authentication
    stages:
      - one_of:
          - {stage: passkey, when: proved_by_passkey}
          - {stage: password}
      - session
    tests:
      - name: a passkey
        given: {proved_by_passkey: true}
        expect: [passkey, session]
`)
	rec = j.signIn(t, cred, tap)
	amr, acr, ok = j.sessionFor(t, rec)
	if !ok {
		t.Fatalf("under a preferred policy a passkey without verification did not sign in: %d %s", rec.Code, rec.Body)
	}
	if slices.Contains(amr, "mfa") || acr == oauth.ACRMultiFactor {
		t.Errorf("a tap without verification was recorded as multi-factor: amr %v, acr %q", amr, acr)
	}
	amr, acr, ok = j.sessionFor(t, j.signIn(t, cred))
	if !ok || !slices.Contains(amr, "mfa") || acr != oauth.ACRMultiFactor {
		t.Errorf("a verified passkey under a preferred policy: session %v, amr %v, acr %q", ok, amr, acr)
	}
}

// The algorithms are held at the finish, not only offered at the begin: a
// browser that answers with a key the organisation did not offer is refused.
func TestAnAlgorithmThePolicyDidNotOfferIsRefused(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	setCeremony(t, j, store.WebAuthnPolicy{RefuseCloned: true, Algorithms: []int{-257}})

	begin := j.post(t, "/account/passkeys/begin", nil, session)
	body, _ := j.auth.create(t, begin.Body.Bytes()) // an ES256 key
	rec := j.post(t, "/account/passkeys/finish", body, session, cookieFrom(begin, CeremonyCookieName))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an ES256 credential under an RS256-only policy answered %d: %s", rec.Code, rec.Body)
	}
	var n int
	if err := j.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.webauthn_credentials
		WHERE user_id = $1::uuid`, j.userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d credentials were stored (%v)", n, err)
	}
}

// When a resident key is only preferred, whether the credential is
// discoverable is what the browser reported through credProps, and not
// discoverable when it reported nothing.
func TestWhetherACredentialIsDiscoverableIsWhatTheBrowserReported(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	setCeremony(t, j, store.WebAuthnPolicy{RefuseCloned: true, ResidentKey: "preferred"})

	for _, c := range []struct {
		name string
		ext  map[string]any
		want bool
	}{
		{"reported discoverable", map[string]any{"credProps": map[string]any{"rk": true}}, true},
		{"reported not discoverable", map[string]any{"credProps": map[string]any{"rk": false}}, false},
		{"reported nothing", nil, false},
	} {
		begin := j.post(t, "/account/passkeys/begin", nil, session)
		device := &virtualAuthenticator{origin: j.auth.origin}
		body, cred := device.create(t, begin.Body.Bytes(), func(p *ceremonyParts) { p.Extensions = c.ext })
		rec := j.post(t, "/account/passkeys/finish", body, session, cookieFrom(begin, CeremonyCookieName))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: registration answered %d: %s", c.name, rec.Code, rec.Body)
		}
		var got bool
		if err := j.pool.QueryRow(context.Background(), `SELECT is_discoverable FROM core.webauthn_credentials
			WHERE credential_id = $1`, cred.id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: stored discoverable %v, want %v", c.name, got, c.want)
		}
	}
}
