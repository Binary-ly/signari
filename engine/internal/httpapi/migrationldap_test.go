package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/delegated/ldaptest"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// passwordSignIn posts the sign-in form from addr, CSRF and all.
func passwordSignIn(t *testing.T, srv *Server, addr, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	get := httptest.NewRequest(http.MethodGet, "/login", nil)
	get.RemoteAddr = addr + ":443"
	grec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(grec, get)
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
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// A person still on the old directory signs in once against it, through a
// source configured the way an operator configures one, and leaves a local
// hash (2.01). Nothing could configure an LDAP source, and a directory that
// could not be reached was taken for a wrong password.
func TestAPersonMigratesFromTheOldDirectoryOnTheirFirstSignIn(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	f.srv.delegator = delegated.New()
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.AllowPrivate("") })

	n := time.Now().UnixNano()
	email := fmt.Sprintf("dir-%d@example.test", n)
	const password = "the-old-directory-knows-this"
	dirURL, caPEM, binds, stop := ldaptest.Directory(t, "uid="+email+",ou=people,dc=example", password)

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMigrationSource(ctx, tx, root, f.orgID, store.MigrationSourceConfig{
		Kind: "ldap", DisplayName: "Old directory", URL: dirURL,
		BindDNTemplate: "uid={username},ou=people,dc=example", CAPEM: caPEM,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMigrationSourceEnabled(ctx, tx, f.orgID, true); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.migration_sources WHERE org_id = $1::uuid`, f.orgID)
	})
	pending := func(email string) string {
		t.Helper()
		var id string
		if err := f.pool.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, user_handle, migration_state, migration_source_id)
			SELECT $1::uuid, $2, decode(md5($2) || md5($2 || 'x') || md5($2 || 'y') || md5($2 || 'z'), 'hex'),
			       'pending', id FROM core.migration_sources WHERE org_id = $1::uuid
			RETURNING id::text`, f.orgID, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	userID := pending(email)
	addr := func(i int) string { return fmt.Sprintf("198.18.%d.%d", (n/11)%250, i) }

	if rec := passwordSignIn(t, f.srv, addr(1), email, "not-it"); !strings.Contains(rec.Body.String(), "Incorrect") {
		t.Errorf("a wrong password answered %d: %.160s", rec.Code, rec.Body.String())
	}
	if rec := passwordSignIn(t, f.srv, addr(2), email, password); !strings.Contains(rec.Body.String(), "signed in") {
		t.Fatalf("the directory's password answered %d: %.200s", rec.Code, rec.Body.String())
	}
	var state string
	var hashed bool
	if err := f.pool.QueryRow(ctx, `SELECT u.migration_state, EXISTS (SELECT 1 FROM core.password_credentials pc
		WHERE pc.user_id = u.id) FROM core.users u WHERE u.id = $1::uuid`, userID).Scan(&state, &hashed); err != nil {
		t.Fatal(err)
	}
	if state != "complete" || !hashed {
		t.Errorf("after the directory accepted the password: migration_state %q, local hash %v", state, hashed)
	}
	asked := len(binds())
	if rec := passwordSignIn(t, f.srv, addr(3), email, password); !strings.Contains(rec.Body.String(), "signed in") {
		t.Errorf("the second sign-in answered %d", rec.Code)
	}
	if len(binds()) != asked {
		t.Error("the old directory was asked again after the person had migrated")
	}

	// The directory goes away: somebody still pending is told it is temporary,
	// not that their password is wrong.
	stop()
	other := fmt.Sprintf("dir-%d-b@example.test", n)
	pending(other)
	rec := passwordSignIn(t, f.srv, addr(4), other, password)
	if body := rec.Body.String(); !strings.Contains(body, "temporarily unavailable") || strings.Contains(body, "Incorrect") {
		t.Errorf("with the directory down the sign-in said: %.200s", body)
	}
}
