package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A passkey that stops being backed up is told to its holder (5.23), once per
// transition, with the way to their other factors.
func TestAPasskeyThatLosesItsBackupIsToldOnce(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = j.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, j.userID)
	})
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	begin := j.post(t, "/account/passkeys/begin", nil, session)
	body, cred := j.auth.create(t, begin.Body.Bytes(), func(p *ceremonyParts) { p.Flags |= flagBE | flagBS })
	if finish := j.post(t, "/account/passkeys/finish?name=laptop", body, session,
		cookieFrom(begin, CeremonyCookieName)); finish.Code != http.StatusOK {
		t.Fatalf("registering a backed-up passkey: %d %s", finish.Code, finish.Body)
	}
	notices := func() []string {
		t.Helper()
		rows, err := j.pool.Query(ctx, `SELECT payload->>'passkey' FROM core.outbox WHERE topic = $1
			AND payload->>'user_id' = $2 AND payload->>'notice' = $3`,
			store.AccountNoticeTopic, j.userID, store.NoticePasskeyBackupLost)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			out = append(out, n)
		}
		return out
	}
	backedUp := func(p *ceremonyParts) { p.Flags = flagUP | flagUV | flagBE | flagBS }
	notBackedUp := func(p *ceremonyParts) { p.Flags = flagUP | flagUV | flagBE }

	if _, _, ok := j.sessionFor(t, j.signIn(t, cred, backedUp)); !ok || len(notices()) != 0 {
		t.Fatalf("a sign-in still backed up: signed in %v, told %v", ok, notices())
	}
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred, notBackedUp)); !ok {
		t.Fatal("the sign-in after the backup went did not sign in")
	}
	if n := notices(); len(n) != 1 || n[0] != "laptop" {
		t.Fatalf("after the backup went: told %v, want [laptop]", n)
	}
	j.signIn(t, cred, notBackedUp)
	if n := notices(); len(n) != 1 {
		t.Errorf("told again with nothing changed: %v", n)
	}

	mailer := &captureMailer{}
	j.srv.mailer = mailer
	if err := j.srv.DeliverAccountNotice(ctx, store.AccountNotice{UserID: j.userID,
		Notice: store.NoticePasskeyBackupLost, Passkey: "laptop"}); err != nil {
		t.Fatal(err)
	}
	msgs := mailer.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0].Body, `"laptop"`) || !strings.Contains(msgs[0].Body, "/account/security") {
		t.Errorf("the notice: %+v", msgs)
	}
}
