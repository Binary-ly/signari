package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A passkey made under the instance's RP ID is used from an origin the
// instance lists (4.23; WebAuthn §5.11), and not from one it does not; the
// list is served at /.well-known/webauthn on the RP ID's host, for the browser
// to check.
func TestARelatedOriginMayUseThePasskey(t *testing.T) {
	j := newPasskeyJourney(t)
	clearSignInBucket(t, j.pool)
	ctx := context.Background()
	const shop = "https://shop.example.test"
	if _, err := j.pool.Exec(ctx, `UPDATE core.instances SET webauthn_related_origins = ARRAY[$2]
		WHERE id = (SELECT instance_id FROM core.organizations WHERE id = $1::uuid)`, j.orgID, shop); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `UPDATE core.instances SET webauthn_related_origins = '{}'
			WHERE id = (SELECT instance_id FROM core.organizations WHERE id = $1::uuid)`, j.orgID)
	})
	// As serve does: the server knows which instance it is.
	var instanceID string
	if err := j.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		j.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	j.srv.SetInstance(instanceID)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}

	// Registered from the related origin, and used from it.
	j.auth = &virtualAuthenticator{origin: shop}
	cred := j.register(t, session)
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); !ok {
		t.Fatal("a passkey did not sign in from an origin the instance lists")
	}
	// From one it does not list: refused.
	j.auth.origin = "https://elsewhere.example.test"
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); ok {
		t.Fatal("a passkey signed in from an origin the instance does not list")
	}

	// The document, on the RP ID's host only.
	get := func(host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/.well-known/webauthn", nil)
		r.Host = host
		rec := httptest.NewRecorder()
		j.h.ServeHTTP(rec, r)
		return rec
	}
	rec := get(j.rpID)
	var doc struct {
		Origins []string `json:"origins"`
	}
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" ||
		json.Unmarshal(rec.Body.Bytes(), &doc) != nil || len(doc.Origins) != 1 || doc.Origins[0] != shop {
		t.Errorf("/.well-known/webauthn on %s: %d %q %s", j.rpID, rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if rec := get("other.example.test"); rec.Code != http.StatusNotFound {
		t.Errorf("/.well-known/webauthn on another host answered %d", rec.Code)
	}
}
