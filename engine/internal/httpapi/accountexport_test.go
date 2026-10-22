package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A person downloads everything kept about them (5.08): the file is theirs and
// withholds every credential's value, the download is recorded, and every
// channel is told. The recent-sign-in and impersonation refusals are
// TestEveryAccountWriteRequiresRecentAuth's route table.
func TestAPersonDownloadsTheirOwnData(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	mailer := &captureMailer{}
	f.srv.mailer = mailer

	if acct := accountGET(f, cookie, "/account").Body.String(); !strings.Contains(acct, `href="/account/export"`) {
		t.Fatal("the account page does not link to downloading the account's data")
	}
	if page := accountGET(f, cookie, "/account/export").Body.String(); !strings.Contains(page, `action="/account/export"`) {
		t.Fatalf("the page has no form to download from: %s", truncate(page, 300))
	}

	rec := f.formPost(t, cookie, "/account/export", "/account/export", url.Values{})
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download: %d %q %q %q: %s", rec.Code, rec.Header().Get("Content-Type"),
			rec.Header().Get("Content-Disposition"), rec.Header().Get("Cache-Control"), truncate(rec.Body.String(), 300))
	}
	var exp store.SubjectExport
	if err := json.Unmarshal(rec.Body.Bytes(), &exp); err != nil {
		t.Fatalf("the file is not the export document: %v", err)
	}
	if exp.Format != store.ExportFormat || exp.SubjectID != f.userID ||
		len(exp.Tables["users"]) != 1 || exp.Tables["users"][0]["email"] != f.email {
		t.Fatalf("the file is not this person's: %s %s %v", exp.Format, exp.SubjectID, exp.Tables["users"])
	}
	if len(exp.Tables["sessions"]) == 0 {
		t.Error("the file has no sessions, and the download came from one")
	}
	var passwords int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.password_credentials WHERE user_id = $1::uuid`,
		f.userID).Scan(&passwords); err != nil {
		t.Fatal(err)
	}
	if passwords == 0 || len(exp.Tables["password_credentials"]) != passwords ||
		!slices.Contains(exp.Withheld["password_credentials"], "hash") {
		t.Errorf("the password is not there as a fact without its hash: %v, withheld %v",
			exp.Tables["password_credentials"], exp.Withheld["password_credentials"])
	}
	if strings.Contains(rec.Body.String(), "$argon2") {
		t.Error("the file holds the password's hash")
	}
	for _, row := range exp.Tables["sessions"] {
		if _, there := row["cookie_hash"]; there {
			t.Error("the file holds a session cookie's hash")
		}
	}

	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'account.exported' AND detail->>'by' = 'owner'`,
		f.userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	told := false
	for _, m := range mailer.messages() {
		told = told || (m.To == f.email && m.Subject == "Your account's data was downloaded")
	}
	if audited != 1 || !told {
		t.Errorf("recorded %d time(s), holder told %v; want 1, true", audited, told)
	}
}
