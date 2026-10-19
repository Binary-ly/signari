package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// A passkey, end to end, through the routes a browser calls: sign in with a
// password, register a passkey from the account, then sign in with it from a
// browser holding nothing, and see a session come back. Every part of this was
// tested on its own; nothing drove handlePasskeyLoginFinish with a real
// assertion, so a passkey sign-in could have stopped working with the suite
// green.

type passkeyJourney struct {
	*signInFixture
	h    http.Handler
	rpID string
	auth *virtualAuthenticator
}

// newPasskeyJourney is a sign-in fixture whose server issuer is its own
// instance's, so the usernameless sign-in resolves this organisation, with the
// instance's rp_id set to the issuer's host.
func newPasskeyJourney(t *testing.T) *passkeyJourney {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	var issuer string
	if err := f.pool.QueryRow(ctx, `
		SELECT i.issuer FROM core.instances i JOIN core.organizations o ON o.instance_id = i.id
		 WHERE o.id = $1::uuid`, f.orgID).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.instances SET rp_id = $2 WHERE issuer = $1`,
		issuer, u.Hostname()); err != nil {
		t.Fatalf("setting rp_id: %v", err)
	}
	srv, err := New(oidc.Config{Issuer: issuer, Keys: f.srv.cfg.Keys},
		f.pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.webauthn_credentials WHERE user_id = $1::uuid`, f.userID)
	})
	return &passkeyJourney{signInFixture: f, h: srv.Routes(), rpID: u.Hostname(),
		auth: &virtualAuthenticator{origin: issuer}}
}

func (j *passkeyJourney) post(t *testing.T, path string, body []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = []byte("{}")
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	j.h.ServeHTTP(rec, r)
	return rec
}

func cookieFrom(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// register adds a passkey to the signed-in account through the two
// registration routes and returns the authenticator's credential.
func (j *passkeyJourney) register(t *testing.T, session *http.Cookie) *virtualCredential {
	t.Helper()
	begin := j.post(t, "/account/passkeys/begin", nil, session)
	if begin.Code != http.StatusOK {
		t.Fatalf("registration begin answered %d: %s", begin.Code, begin.Body)
	}
	body, cred := j.auth.create(t, begin.Body.Bytes())
	finish := j.post(t, "/account/passkeys/finish?name=laptop", body,
		session, cookieFrom(begin, CeremonyCookieName))
	if finish.Code != http.StatusOK {
		t.Fatalf("registration finish answered %d: %s", finish.Code, finish.Body)
	}
	return cred
}

// signIn runs a usernameless sign-in with the credential, bent as asked, from
// a browser holding no session, and returns the finish response.
func (j *passkeyJourney) signIn(t *testing.T, cred *virtualCredential, bend ...func(*ceremonyParts)) *httptest.ResponseRecorder {
	t.Helper()
	begin := j.post(t, "/login/passkey/begin", nil)
	if begin.Code != http.StatusOK {
		t.Fatalf("sign-in begin answered %d: %s", begin.Code, begin.Body)
	}
	body := j.auth.get(t, begin.Body.Bytes(), cred, bend...)
	return j.post(t, "/login/passkey/finish", body, cookieFrom(begin, CeremonyCookieName))
}

func (j *passkeyJourney) sessionFor(t *testing.T, rec *httptest.ResponseRecorder) (amr []string, acr string, ok bool) {
	t.Helper()
	c := cookieFrom(rec, SessionCookieName)
	if c == nil {
		return nil, "", false
	}
	var userID string
	if err := j.pool.QueryRow(context.Background(), `
		SELECT user_id::text, amr, COALESCE(acr,'') FROM core.sessions
		 WHERE cookie_hash = $1 AND revoked_at IS NULL`, store.HashToken(c.Value)).
		Scan(&userID, &amr, &acr); err != nil {
		t.Fatalf("a session cookie was set with no live session behind it: %v", err)
	}
	if userID != j.userID {
		t.Fatalf("the session belongs to %s, not the passkey's owner %s", userID, j.userID)
	}
	return amr, acr, true
}

func TestAPasskeyRegisteredFromTheAccountSignsInWithNoUsername(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	if session.Value == "" {
		t.Fatal("the fixture user could not sign in with a password")
	}

	cred := j.register(t, session)
	var discoverable bool
	var rpID string
	if err := j.pool.QueryRow(ctx, `
		SELECT is_discoverable, rp_id FROM core.webauthn_credentials
		 WHERE user_id = $1::uuid AND credential_id = $2`, j.userID, cred.id).
		Scan(&discoverable, &rpID); err != nil {
		t.Fatalf("the registered credential was not stored: %v", err)
	}
	if !discoverable || rpID != j.rpID {
		t.Errorf("stored discoverable=%v rp_id=%q, want true and %q", discoverable, rpID, j.rpID)
	}

	rec := j.signIn(t, cred)
	amr, acr, ok := j.sessionFor(t, rec)
	if !ok {
		t.Fatalf("a valid passkey assertion produced no session: %d %s", rec.Code, rec.Body)
	}
	// What the assertion proved, and no more: a person was present, on a
	// device-bound key (not backup-eligible), who verified to it.
	for _, want := range []string{"user", "hwk", "mfa"} {
		if !slices.Contains(amr, want) {
			t.Errorf("the session's amr %q lacks %s", amr, want)
		}
	}
	if slices.Contains(amr, "swk") || slices.Contains(amr, "pwd") {
		t.Errorf("the session's amr %q claims what the passkey did not prove", amr)
	}
	if acr == "" {
		t.Error("the session carries no acr")
	}
	var count int64
	if err := j.pool.QueryRow(ctx, `SELECT sign_count FROM core.webauthn_credentials
		WHERE credential_id = $1`, cred.id).Scan(&count); err != nil || count != int64(cred.count) {
		t.Errorf("the stored counter is %d (%v), want the asserted %d", count, err, cred.count)
	}

	// A second sign-in with the same passkey works: the counter moved on.
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); !ok {
		t.Error("a second sign-in with the same passkey produced no session")
	}
}

// Under an approved-model allow-list, an authenticator naming an approved
// model proves nothing by naming it: not with no attestation, and not with
// packed SELF-attestation, which is signed by the credential's own key. Only a
// chain anchored in the FIDO catalogue's roots vouches for a model (1.03); the
// anchored case itself is fidomds' TestOnlyAnAnchoredChainVouchesForAnAAGUID,
// since only a vendor's key can make one.
func TestAnAllowListIsNotPassedByClaimingAnApprovedModel(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	const yubiKey5 = "ee882879-721c-4913-9775-3dfcce97072a"
	if _, err := j.pool.Exec(ctx, `
		INSERT INTO core.webauthn_policy (org_id, attestation_conveyance, allowed_aaguids)
		VALUES ($1::uuid, 'direct', ARRAY[$2::uuid])
		ON CONFLICT (org_id) DO UPDATE SET attestation_conveyance = 'direct',
		       allowed_aaguids = ARRAY[$2::uuid]`, j.orgID, yubiKey5); err != nil {
		t.Fatalf("setting the allow-list: %v", err)
	}
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.webauthn_policy WHERE org_id = $1::uuid`, j.orgID)
	})
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}

	var claimed [16]byte
	for i, h := range []byte{0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a} {
		claimed[i] = h
	}
	for _, format := range []string{"none", "packed"} {
		begin := j.post(t, "/account/passkeys/begin", nil, session)
		device := &virtualAuthenticator{origin: j.auth.origin}
		body, _ := device.create(t, begin.Body.Bytes(), func(p *ceremonyParts) {
			p.AAGUID, p.Format = claimed, format
		})
		rec := j.post(t, "/account/passkeys/finish", body, session, cookieFrom(begin, CeremonyCookieName))
		if rec.Code != http.StatusForbidden ||
			!bytes.Contains(rec.Body.Bytes(), []byte("authenticator_not_permitted")) {
			t.Errorf("%s attestation claiming an approved model answered %d: %s", format, rec.Code, rec.Body)
		}
	}
	var n int
	if err := j.pool.QueryRow(ctx, `SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid`,
		j.userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d credentials were stored (%v)", n, err)
	}
}

// Each forgery a browser or an attacker could present is refused with no
// session, and a credential the server still holds is never answered with the
// instruction to delete it.
func TestAPasskeyAssertionThatProvesTheWrongThingIsRefused(t *testing.T) {
	j := newPasskeyJourney(t)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	cred := j.register(t, session)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		bend func(*ceremonyParts)
	}{
		{"another origin", func(p *ceremonyParts) { p.Origin = "https://attacker.example" }},
		{"another relying party", func(p *ceremonyParts) { p.RPID = "attacker.example" }},
		{"a registration's client data", func(p *ceremonyParts) { p.Type = "webauthn.create" }},
		{"another challenge", func(p *ceremonyParts) { p.Challenge = b64([]byte("not the challenge issued here")) }},
		{"no user verification", func(p *ceremonyParts) { p.Flags = flagUP }},
		{"no user presence", func(p *ceremonyParts) { p.Flags = flagUV }},
		{"another key's signature", func(p *ceremonyParts) { p.Key = other }},
	} {
		rec := j.signIn(t, cred, c.bend)
		if _, _, ok := j.sessionFor(t, rec); ok {
			t.Errorf("%s: signed in", c.name)
			continue
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: answered %d, want 401", c.name, rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("signal_unknown_credential")) {
			t.Errorf("%s: told the browser to delete a credential the server still holds", c.name)
		}
	}

	// A credential the server does not hold, for this very account: refused,
	// and the browser is told which one so the authenticator stops offering it.
	stray := &virtualCredential{id: []byte("a credential nobody registered"), key: other,
		rpID: j.rpID, handle: cred.handle}
	rec := j.signIn(t, stray)
	if _, _, ok := j.sessionFor(t, rec); ok {
		t.Fatal("an unregistered credential signed in")
	}
	var refused struct {
		Signal struct {
			CredentialID string `json:"credentialId"`
		} `json:"signal_unknown_credential"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &refused)
	if refused.Signal.CredentialID != b64(stray.id) {
		t.Errorf("an unknown credential was refused without naming it: %s", rec.Body)
	}

	// A registration ceremony cannot be finished as a sign-in, even with an
	// assertion made over its own challenge. Two things refuse it: the
	// ceremony's purpose, and the library, which will not finish a discoverable
	// sign-in from session data that names a user. This holds the property; it
	// does not isolate either check.
	begin := j.post(t, "/account/passkeys/begin", nil, session)
	var creation struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	asked, _ := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": creation.PublicKey.Challenge, "rpId": j.rpID,
	}})
	body := j.auth.get(t, asked, cred)
	if _, _, ok := j.sessionFor(t, j.post(t, "/login/passkey/finish", body,
		cookieFrom(begin, CeremonyCookieName))); ok {
		t.Error("a registration challenge was finished as a sign-in")
	}

	// A deactivated account does not sign in with a passkey it still holds:
	// the status is read on the request, never remembered (ADR-007).
	if _, err := j.pool.Exec(context.Background(),
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, j.userID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); ok {
		t.Error("a deactivated account signed in with its passkey")
	}
}
