package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// An emailed link registers a passkey with no session (4.24), through the
// routes a browser calls: the link is issued as the Admin API and the CLI
// issue it, its token reaches the person only in the email, the page it opens
// begins a ceremony, and the passkey it registers signs in.

// issueLink issues a link as the Admin API and the CLI do and delivers its
// email as serve's outbox does, returning the link and the token the email
// carried.
func issueLink(t *testing.T, j *passkeyJourney, mailer *captureMailer) (store.PasskeyLink, string) {
	t.Helper()
	ctx := context.Background()
	tx, err := j.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	link, err := store.IssuePasskeyLink(ctx, tx, j.userID, j.orgID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return link, deliverLink(t, j, mailer, link)
}

var linkInMail = regexp.MustCompile(`/enrol/passkey\?token=(\S+)`)

// deliverLink sends a link's email and returns the token in it.
func deliverLink(t *testing.T, j *passkeyJourney, mailer *captureMailer, link store.PasskeyLink) string {
	t.Helper()
	before := len(mailer.messages())
	if err := j.srv.DeliverAccountNotice(context.Background(), store.AccountNotice{
		UserID: j.userID, Notice: store.NoticePasskeyLink, LinkID: link.ID,
	}); err != nil {
		t.Fatalf("delivering the link: %v", err)
	}
	msgs := mailer.messages()
	if len(msgs) != before+1 {
		t.Fatalf("%d emails for one link", len(msgs)-before)
	}
	m := msgs[len(msgs)-1]
	if m.To != j.email {
		t.Fatalf("the link went to %q, not the account's address %q", m.To, j.email)
	}
	got := linkInMail.FindStringSubmatch(m.Body)
	if got == nil {
		t.Fatalf("no link in the email: %q", m.Body)
	}
	token, err := url.QueryUnescape(got[1])
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (j *passkeyJourney) linkPage(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/enrol/passkey?token="+url.QueryEscape(token), nil)
	rec := httptest.NewRecorder()
	j.h.ServeHTTP(rec, r)
	return rec
}

func (j *passkeyJourney) linkBegin(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return j.post(t, "/enrol/passkey/begin", []byte(`{"token":"`+token+`"}`))
}

// linkFinish creates a credential for a begun ceremony and finishes it.
func (j *passkeyJourney) linkFinish(t *testing.T, begin *httptest.ResponseRecorder) (*httptest.ResponseRecorder, *virtualCredential) {
	t.Helper()
	body, cred := j.auth.create(t, begin.Body.Bytes())
	return j.post(t, "/enrol/passkey/finish?name=new+laptop", body, cookieFrom(begin, CeremonyCookieName)), cred
}

func (j *passkeyJourney) passkeys(t *testing.T) int {
	t.Helper()
	var n int
	if err := j.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid`, j.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func newLinkJourney(t *testing.T) (*passkeyJourney, *captureMailer) {
	t.Helper()
	j := newPasskeyJourney(t)
	mailer := &captureMailer{}
	j.srv.mailer = mailer
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = j.pool.Exec(ctx, `DELETE FROM core.passkey_links WHERE user_id = $1::uuid`, j.userID)
		_, _ = j.pool.Exec(ctx, `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'user_id' = $2`,
			store.AccountNoticeTopic, j.userID)
	})
	return j, mailer
}

func TestAPasskeyLinkRegistersOnceAndThenRefuses(t *testing.T) {
	j, mailer := newLinkJourney(t)
	link, token := issueLink(t, j, mailer)

	// Nothing at rest holds the token: the row keeps its hash, and the queued
	// notice names the link by id.
	var hash []byte
	var payload string
	if err := j.pool.QueryRow(context.Background(), `
		SELECT l.token_hash, (SELECT string_agg(o.payload::text, ' ') FROM core.outbox o
		                       WHERE o.topic = $2 AND o.payload->>'link_id' = l.id::text)
		  FROM core.passkey_links l WHERE l.id = $1::uuid`, link.ID, store.AccountNoticeTopic).
		Scan(&hash, &payload); err != nil {
		t.Fatal(err)
	}
	if string(hash) != string(store.HashToken(token)) || strings.Contains(payload, token) {
		t.Fatalf("the token is held at rest: hash matches %v, in the outbox %v",
			string(hash) == string(store.HashToken(token)), strings.Contains(payload, token))
	}

	// Opening the page spends nothing, so a mail scanner that fetches the link
	// first leaves it working.
	for i := 0; i < 2; i++ {
		if rec := j.linkPage(t, token); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), j.email) {
			t.Fatalf("opening the link (%d): %d", i+1, rec.Code)
		}
	}

	// Two ceremonies begun from the link before either finishes: the first
	// registers and spends it, and the second is refused with nothing stored.
	first, second := j.linkBegin(t, token), j.linkBegin(t, token)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("beginning from a live link: %d, %d: %s", first.Code, second.Code, first.Body)
	}
	done, cred := j.linkFinish(t, first)
	if done.Code != http.StatusOK {
		t.Fatalf("finishing from a live link: %d: %s", done.Code, done.Body)
	}
	if n := j.passkeys(t); n != 1 {
		t.Fatalf("%d passkeys after one registration", n)
	}
	if rec, _ := j.linkFinish(t, second); rec.Code != http.StatusBadRequest {
		t.Errorf("a second ceremony from a spent link finished: %d: %s", rec.Code, rec.Body)
	}
	if n := j.passkeys(t); n != 1 {
		t.Errorf("%d passkeys: the link registered more than one", n)
	}

	// Spent everywhere: the page, a new ceremony, and the email a retried
	// delivery would send.
	if rec := j.linkPage(t, token); rec.Code != http.StatusNotFound {
		t.Errorf("a spent link's page: %d", rec.Code)
	}
	if rec := j.linkBegin(t, token); rec.Code != http.StatusBadRequest {
		t.Errorf("a spent link began a ceremony: %d", rec.Code)
	}
	before := len(mailer.messages())
	if err := j.srv.DeliverAccountNotice(context.Background(), store.AccountNotice{
		UserID: j.userID, Notice: store.NoticePasskeyLink, LinkID: link.ID,
	}); err != nil || len(mailer.messages()) != before {
		t.Errorf("delivering a spent link: %v, %d emails", err, len(mailer.messages())-before)
	}

	// What it registered is a passkey like any other: it signs in, and the
	// holder was told it was added.
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); !ok {
		t.Error("the passkey the link registered did not sign in")
	}
	var told bool
	for _, m := range mailer.messages() {
		told = told || strings.Contains(m.Subject, "passkey was added")
	}
	if !told {
		t.Error("the holder was not told a passkey was added")
	}
}

func TestAnExpiredPasskeyLinkRefuses(t *testing.T) {
	j, mailer := newLinkJourney(t)
	link, token := issueLink(t, j, mailer)

	// Expiring between the two halves of a ceremony refuses the finish.
	begin := j.linkBegin(t, token)
	if begin.Code != http.StatusOK {
		t.Fatalf("beginning: %d", begin.Code)
	}
	if _, err := j.pool.Exec(context.Background(), `UPDATE core.passkey_links
		SET created_at = now() - interval '2 days', expires_at = now() - interval '1 second'
		WHERE id = $1::uuid`, link.ID); err != nil {
		t.Fatal(err)
	}
	if rec, _ := j.linkFinish(t, begin); rec.Code != http.StatusBadRequest {
		t.Errorf("finishing from a link that expired since it began: %d: %s", rec.Code, rec.Body)
	}
	if rec := j.linkPage(t, token); rec.Code != http.StatusNotFound {
		t.Errorf("an expired link's page: %d", rec.Code)
	}
	if rec := j.linkBegin(t, token); rec.Code != http.StatusBadRequest {
		t.Errorf("an expired link began a ceremony: %d", rec.Code)
	}
	if n := j.passkeys(t); n != 0 {
		t.Errorf("%d passkeys from an expired link", n)
	}
}

func TestANewPasskeyLinkEndsTheOneBefore(t *testing.T) {
	j, mailer := newLinkJourney(t)
	_, old := issueLink(t, j, mailer)
	_, fresh := issueLink(t, j, mailer)
	if rec := j.linkPage(t, old); rec.Code != http.StatusNotFound {
		t.Errorf("a superseded link still opens: %d", rec.Code)
	}
	if rec := j.linkBegin(t, fresh); rec.Code != http.StatusOK {
		t.Errorf("the newer link: %d", rec.Code)
	}
}

func TestAPasskeyLinkForADeactivatedAccountRefuses(t *testing.T) {
	j, mailer := newLinkJourney(t)
	_, token := issueLink(t, j, mailer)
	if _, err := j.pool.Exec(context.Background(),
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, j.userID); err != nil {
		t.Fatal(err)
	}
	if rec := j.linkPage(t, token); rec.Code != http.StatusNotFound {
		t.Errorf("a deactivated account's link opens: %d", rec.Code)
	}
	if rec := j.linkBegin(t, token); rec.Code != http.StatusBadRequest {
		t.Errorf("a deactivated account's link began a ceremony: %d", rec.Code)
	}
}

// A link's ceremony and the account page's are not interchangeable: each
// finishes only where it began.
func TestALinkCeremonyFinishesOnlyFromALink(t *testing.T) {
	j, mailer := newLinkJourney(t)
	_, token := issueLink(t, j, mailer)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}

	begin := j.linkBegin(t, token)
	body, _ := j.auth.create(t, begin.Body.Bytes())
	if rec := j.post(t, "/account/passkeys/finish", body, session,
		cookieFrom(begin, CeremonyCookieName)); rec.Code != http.StatusBadRequest {
		t.Errorf("a link's ceremony finished on the account page: %d", rec.Code)
	}

	// Begun on the account page, finished at the link's finish.
	acct := j.post(t, "/account/passkeys/begin", nil, session)
	if acct.Code != http.StatusOK {
		t.Fatalf("account page begin: %d: %s", acct.Code, acct.Body)
	}
	if rec, _ := j.linkFinish(t, acct); rec.Code != http.StatusBadRequest {
		t.Errorf("the account page's ceremony finished at the link's: %d", rec.Code)
	}
	if n := j.passkeys(t); n != 0 {
		t.Errorf("%d passkeys from crossed ceremonies", n)
	}
}
