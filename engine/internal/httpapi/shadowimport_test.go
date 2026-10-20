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

	"signari.dev/engine/internal/importer"
)

// An /etc/shadow import signs in (4.09): the entries are imported, a person
// signs in through the sign-in form with the password the old system had, and
// the crypt hash is replaced with Argon2id. SHA-crypt was refused at every
// sign-in, because the verifier disagreed with every other implementation.
func TestAnImportedShadowEntrySignsInWithItsOldPassword(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	tag := fmt.Sprint(time.Now().UnixNano() % 1_000_000_000)
	sha512User, md5User, locked := "sha"+tag, "md5"+tag, "locked"+tag
	shadow := strings.Join([]string{
		// openssl passwd -6 -salt saltstring 'Hello world!'
		sha512User + ":$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1:19000:0:99999:7:::",
		// openssl passwd -1 -salt saltsalt 'Hello world!'
		md5User + ":$1$saltsalt$le8lFSqqnPaRFOlmAZpvH1:19000:0:99999:7:::",
		locked + ":!:19000:0:99999:7:::",
		"daemon" + tag[:3] + ":*:19000:0:99999:7:::",
		"yes" + tag + ":$y$j9T$abc$def:19000:0:99999:7:::",
	}, "\n")
	entries, err := importer.ParseShadow(strings.NewReader(shadow))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := importer.ImportShadow(ctx, tx, f.orgID, entries, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE org_id = $1::uuid
			AND username = ANY($2)`, f.orgID, []string{sha512User, md5User})
	})
	if res.UsersCreated != 2 || len(res.UsersSkipped) != 3 {
		t.Fatalf("created %d, skipped %v; want the two with verifiable passwords created and the "+
			"locked, system and yescrypt entries named", res.UsersCreated, res.UsersSkipped)
	}

	for _, name := range []string{sha512User, md5User} {
		get := httptest.NewRecorder()
		f.srv.handleLoginGet(get, httptest.NewRequest(http.MethodGet, "/login", nil))
		m := csrfValue.FindStringSubmatch(get.Body.String())
		form := url.Values{"username": {name}, "password": {"Hello world!"}, csrfFormField: {m[1]}}
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookieFrom(get, CSRFCookieName))
		r.RemoteAddr = testClientIP(t) + ":5555"
		rec := httptest.NewRecorder()
		f.srv.rateLimitedLogin(rec, r)
		if cookieFrom(rec, SessionCookieName) == nil {
			t.Errorf("%s did not sign in with the old password: %d", name, rec.Code)
			continue
		}
		var hash string
		var current bool
		if err := f.pool.QueryRow(ctx, `SELECT pc.hash, pc.is_current FROM core.password_credentials pc
			JOIN core.users u ON u.id = pc.user_id WHERE u.org_id = $1::uuid AND u.username = $2`,
			f.orgID, name).Scan(&hash, &current); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(hash, "$argon2id$") || !current {
			t.Errorf("%s's crypt hash was not replaced at the first sign-in: %.20s, current %v", name, hash, current)
		}
	}
}

func TestAShadowFileIsReadWhole(t *testing.T) {
	if _, err := importer.ParseShadow(strings.NewReader("root:x:1\nnot a shadow line\n")); err == nil ||
		!strings.Contains(err.Error(), "line 2") {
		t.Errorf("a malformed line: %v; want it named by number", err)
	}
	entries, err := importer.ParseShadow(strings.NewReader("# comment\n\nroot:*:1\nana:$6$s$h:1\n"))
	if err != nil || len(entries) != 2 || entries[1].Name != "ana" || entries[1].Hash != "$6$s$h" {
		t.Errorf("entries %+v, %v", entries, err)
	}
}
