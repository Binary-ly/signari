package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// NIST SP 800-63B-4 §4.5: "CSPs SHALL promptly invalidate authenticators...
// when requested by the subscriber".
//
// There was no way to make the request. store.DeleteCredential was written,
// given an ownership check and a last-credential guard, tested — and had no
// caller anywhere in the tree.
//
// The binding notice this server sends made the gap concrete: "Sign in, remove
// the passkey you do not recognise". That instruction could not be followed.
func TestASubscriberCanRemoveAPasskey(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// Two credentials, so removing one is not the last-credential case.
	first := seedCredential(t, f, "Old Laptop")
	seedCredential(t, f, "Phone")

	cap := &captureMailer{}
	f.srv.mailer = cap
	const addr = "removal@example.test"
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.users SET email = $2 WHERE id = $1::uuid`, f.userID, addr); err != nil {
		t.Fatal(err)
	}

	code, body := f.deletePasskey(t, first)
	if code != http.StatusOK {
		t.Fatalf("removing a passkey gave %d: %s", code, body)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM core.webauthn_credentials WHERE id = $1::uuid`, first).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the credential is still there")
	}

	// §4.5: "The CSP SHOULD notify the subscriber when an authenticator is
	// invalidated". The mirror of binding — an attacker who removes a factor has
	// made the account weaker, and a thing that is simply gone is the hardest
	// change for its owner to notice.
	msgs := cap.messages()
	if len(msgs) != 1 {
		t.Fatalf("got %d notifications for a removal, want 1", len(msgs))
	}
	if !strings.Contains(msgs[0].Body, "Old Laptop") {
		t.Errorf("the notice does not name the passkey that went: %q", msgs[0].Body)
	}
	if !strings.Contains(strings.ToLower(msgs[0].Body), "did not") {
		t.Errorf("the notice gives no instructions for the case where it was not "+
			"the owner: %q", msgs[0].Body)
	}
}

// The last credential must not be removable — otherwise "remove the passkey you
// do not recognise" becomes a way to lock yourself out, and an attacker who
// obtains a session can strip the account's only factor.
func TestTheLastPasskeyCannotBeRemoved(t *testing.T) {
	f := newTokenFixture(t)
	only := seedCredential(t, f, "Only Key")

	code, body := f.deletePasskey(t, only)
	if code != http.StatusConflict {
		t.Fatalf("removing the only passkey gave %d, want 409: %s", code, body)
	}
	if !strings.Contains(body, "only passkey") {
		t.Errorf("the refusal should say why: %s", body)
	}
}

// Somebody else's credential must not be removable, and the answer must not
// reveal whether the id exists.
func TestAnotherUsersPasskeyCannotBeRemoved(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	var stranger string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, status, user_handle)
		VALUES ($1::uuid, 'stranger-' || gen_random_uuid() || '@example.test', 'active',
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING id::text`, f.orgID).Scan(&stranger); err != nil {
		t.Fatal(err)
	}
	var theirs string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, rp_id, friendly_name, is_discoverable)
		VALUES ($1::uuid, $2::uuid, decode(md5(gen_random_uuid()::text),'hex'),
		        '\x02'::bytea, 'localhost', 'Theirs', true)
		RETURNING id::text`, stranger, f.orgID).Scan(&theirs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.users WHERE id = $1::uuid`, stranger)
	})

	code, _ := f.deletePasskey(t, theirs)
	if code != http.StatusNotFound {
		t.Errorf("deleting another user's passkey gave %d, want 404", code)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM core.webauthn_credentials WHERE id = $1::uuid`, theirs).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("another user's credential was removed")
	}
}

// --- helpers ---

func seedCredential(t *testing.T, f *tokenFixture, name string) string {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, rp_id, friendly_name, is_discoverable)
		VALUES ($1::uuid, $2::uuid, decode(md5(gen_random_uuid()::text),'hex'),
		        '\x02'::bytea, 'localhost', $3, true)
		RETURNING id::text`, f.userID, f.orgID, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *tokenFixture) deletePasskey(t *testing.T, id string) (int, string) {
	t.Helper()
	cookie, csrf := f.signedInCookies(t)

	req := httptest.NewRequest(http.MethodPost, "/account/passkeys/delete",
		strings.NewReader("id="+id+"&"+csrfFormField+"="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrf})

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// signedInCookies creates a live session this fixture's user owns and returns the
// cookie value plus a matching CSRF token.
//
// The fixture's own session row stores an md5 of the sid as its cookie hash,
// which store.HashToken will never produce — it is there for tests that read the
// row, not for tests that present a cookie.
func (f *tokenFixture) signedInCookies(t *testing.T) (cookie, csrf string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	cookie = base64.RawURLEncoding.EncodeToString(raw)

	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		t.Fatal(err)
	}
	csrf = base64.RawURLEncoding.EncodeToString(tok)

	sid := "del-" + base64.RawURLEncoding.EncodeToString(raw[:8])
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '1', ARRAY['pwd'], now(), now() + interval '1 hour')`,
		sid, store.HashToken(cookie), f.orgID, f.userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.sessions WHERE sid = $1`, sid)
	})
	return cookie, csrf
}
