package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/store"
)

// A reset request writes a row, supersedes the earlier link and sends mail,
// and there was no pace at all.

func liveRecoveryRequests(t *testing.T, f *signInFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.recovery_requests
		 WHERE user_id = $1::uuid AND cancelled_at IS NULL AND consumed_at IS NULL`,
		f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// deliverRecoveries does what the outbox worker does with the resets queued for these
// people, and says how many there were.
func deliverRecoveries(t *testing.T, srv *Server, pool *pgxpool.Pool, userIDs ...string) int {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT id, payload FROM core.outbox
		WHERE topic = $1 AND payload->>'notice' = $2 AND payload->>'user_id' = ANY($3) ORDER BY id`,
		store.AccountNoticeTopic, store.NoticeRecovery, userIDs)
	if err != nil {
		t.Fatal(err)
	}
	type queued struct {
		id     int64
		notice store.AccountNotice
	}
	var found []queued
	for rows.Next() {
		var q queued
		var raw []byte
		if err := rows.Scan(&q.id, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &q.notice); err != nil {
			t.Fatal(err)
		}
		found = append(found, q)
	}
	rows.Close()
	for _, q := range found {
		if err := srv.DeliverAccountNotice(ctx, q.notice); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM core.outbox WHERE id = $1`, q.id); err != nil {
			t.Fatal(err)
		}
	}
	return len(found)
}

// stallingMailer is an SMTP server that has stopped answering, until it is released.
type stallingMailer struct {
	captureMailer
	release chan struct{}
}

func (m *stallingMailer) Send(ctx context.Context, msg mail.Message) error {
	<-m.release
	return m.captureMailer.Send(ctx, msg)
}

// The page says the same whatever is typed, and it did not take the same time (0.13):
// an account's answer waited on SMTP, a stranger's did not, and how long the page took
// said which was which. The request queues, and what is sent goes out after it.
func TestARecoveryRequestAnswersBeforeAnythingIsSent(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, time.Minute)
	ctx := context.Background()
	stalled := &stallingMailer{release: make(chan struct{})}
	f.srv.mailer = stalled

	asked := make(chan error, 1)
	go func() { asked <- f.srv.beginRecovery(ctx, f.email) }()
	select {
	case err := <-asked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		close(stalled.release)
		t.Fatal("a request for an account waited on the mail")
	}
	if n := liveRecoveryRequests(t, f); n != 0 {
		t.Errorf("%d reset(s) started in the request", n)
	}
	var payload string
	if err := f.pool.QueryRow(ctx, `SELECT payload::text FROM core.outbox WHERE topic = $1
		AND payload->>'user_id' = $2 AND payload->>'notice' = $3`, store.AccountNoticeTopic, f.userID,
		store.NoticeRecovery).Scan(&payload); err != nil {
		t.Fatalf("nothing was queued: %v", err)
	}
	if strings.Contains(payload, "token") {
		t.Errorf("a link sits in the outbox: %s", payload)
	}

	close(stalled.release)
	if n := deliverRecoveries(t, f.srv, f.pool, f.userID); n != 1 {
		t.Fatalf("%d queued, want 1", n)
	}
	sent := stalled.messages()
	if len(sent) != 1 || !strings.Contains(sent[0].Body, "/recover/reset?token=") {
		t.Fatalf("the delivery sent %+v", sent)
	}
	if n := liveRecoveryRequests(t, f); n != 1 {
		t.Errorf("the delivery left %d live reset(s), want 1", n)
	}

	// Deactivated since it was asked for: nothing to send, and no retry for ever.
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.DeliverAccountNotice(ctx, store.AccountNotice{UserID: f.userID, OrgID: f.orgID,
		Notice: store.NoticeRecovery}); err != nil {
		t.Errorf("a deactivated account's delivery failed, and would be tried again: %v", err)
	}
	if got := stalled.messages(); len(got) != 1 {
		t.Errorf("a deactivated account was sent a link: %d messages", len(got))
	}
}

func TestASecondResetRequestWithinAMinuteSendsNothing(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, time.Minute)
	ctx := context.Background()
	cap := &captureMailer{}
	f.srv.mailer = cap

	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	deliverRecoveries(t, f.srv, f.pool, f.userID)
	if len(cap.messages()) != 1 || liveRecoveryRequests(t, f) != 1 {
		t.Fatalf("the first request sent %d message(s) and left %d live request(s), want 1 and 1",
			len(cap.messages()), liveRecoveryRequests(t, f))
	}
	var first string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.recovery_requests
		 WHERE user_id = $1::uuid AND cancelled_at IS NULL`, f.userID).Scan(&first); err != nil {
		t.Fatal(err)
	}

	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	if n := deliverRecoveries(t, f.srv, f.pool, f.userID); n != 0 {
		t.Errorf("a second request within a minute queued %d", n)
	}
	if n := len(cap.messages()); n != 1 {
		t.Fatalf("a second request within a minute sent %d messages in all, want 1", n)
	}
	var still string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM core.recovery_requests
		 WHERE user_id = $1::uuid AND cancelled_at IS NULL`, f.userID).Scan(&still); err != nil || still != first {
		t.Fatalf("the paced request superseded the person's own link (%v): an attacker "+
			"could keep it from ever working", err)
	}

	// Five an hour, whatever the minutes: step the minute bucket back each time.
	stepMinute := func() {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `
			UPDATE core.rate_limits SET window_start = window_start - interval '2 minutes'
			 WHERE bucket_key = $1`, "recover:user:min:"+f.userID); err != nil {
			t.Fatal(err)
		}
	}
	for i := 2; i <= recoveryPerAccountHour; i++ {
		stepMinute()
		if err := f.srv.beginRecovery(ctx, f.email); err != nil {
			t.Fatal(err)
		}
		deliverRecoveries(t, f.srv, f.pool, f.userID)
	}
	if n := len(cap.messages()); n != recoveryPerAccountHour {
		t.Fatalf("%d paced requests sent %d messages, want %d", recoveryPerAccountHour, n, recoveryPerAccountHour)
	}
	stepMinute()
	if err := f.srv.beginRecovery(ctx, f.email); err != nil {
		t.Fatal(err)
	}
	deliverRecoveries(t, f.srv, f.pool, f.userID)
	if n := len(cap.messages()); n != recoveryPerAccountHour {
		t.Fatalf("a request over the hourly pace sent mail (%d in all)", n)
	}
}

func TestOneAddressCannotSweepResetMailAcrossAccounts(t *testing.T) {
	f := newSignInFixture(t)
	cap := &captureMailer{}
	f.srv.mailer = cap
	n := time.Now().UnixNano()
	addr := fmt.Sprintf("198.18.%d.%d", (n/13)%250, n%250+1)

	post := func(identifier string) int {
		t.Helper()
		get := httptest.NewRequest(http.MethodGet, "/recover", nil)
		get.RemoteAddr = addr + ":443"
		grec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(grec, get)
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
			t.Fatalf("the recovery form carries no CSRF field: %d", grec.Code)
		}
		rest := body[i+len(marker):]
		form := url.Values{"username": {identifier}, csrfFormField: {rest[:strings.Index(rest, `"`)]}}
		req := httptest.NewRequest(http.MethodPost, "/recover", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookie})
		req.RemoteAddr = addr + ":443"
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < recoveryPerAddressLimit; i++ {
		post(fmt.Sprintf("nobody-%d-%d@example.test", n, i))
	}
	if code := post(f.email); code != http.StatusOK {
		t.Fatalf("a paced request answered %d; it must answer the same page as any other", code)
	}
	deliverRecoveries(t, f.srv, f.pool, f.userID)
	if len(cap.messages()) != 0 || liveRecoveryRequests(t, f) != 0 {
		t.Fatalf("after %d requests from one address, a real account was still sent %d message(s)",
			recoveryPerAddressLimit, len(cap.messages()))
	}
}
