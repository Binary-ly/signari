package httpapi

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// An invitation the engine mails (5.18): the link in the mail is the one that
// opens it, and a revoked one sends nothing.
func TestAMailedInvitationCarriesTheLinkThatOpensIt(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	mailer := &captureMailer{}
	f.srv.mailer = mailer
	newInvite := func() (string, store.AccountNotice) {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		id, token, _, err := store.NewInvitation(ctx, tx, store.InvitationSpec{
			OrgID: f.orgID, Email: "Invitee-" + f.email, TTL: time.Hour, Send: true,
		})
		if err != nil || token != "" {
			t.Fatalf("making a sent invitation: token %q, %v", token, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			c := context.Background()
			_, _ = f.pool.Exec(c, `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'link_id' = $2`,
				store.AccountNoticeTopic, id)
			_, _ = f.pool.Exec(c, `DELETE FROM core.invitations WHERE id = $1::uuid`, id)
		})
		return id, store.AccountNotice{Notice: store.NoticeInvitation, LinkID: id}
	}

	_, n := newInvite()
	if err := f.srv.DeliverAccountNotice(ctx, n); err != nil {
		t.Fatal(err)
	}
	msgs := mailer.messages()
	if len(msgs) != 1 || msgs[0].To != strings.ToLower("invitee-"+f.email) {
		t.Fatalf("delivering sent %+v", msgs)
	}
	m := regexp.MustCompile(`/signup\?invite=(\S+)`).FindStringSubmatch(msgs[0].Body)
	if m == nil {
		t.Fatalf("no link in the mail: %q", msgs[0].Body)
	}
	token, _ := url.QueryUnescape(m[1])
	if _, err := store.PeekInvitation(ctx, f.pool, token); err != nil {
		t.Errorf("the mailed link does not open the invitation: %v", err)
	}

	id, n := newInvite()
	if err := store.RevokeInvitation(ctx, f.pool, f.orgID, id); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.DeliverAccountNotice(ctx, n); err != nil {
		t.Fatal(err)
	}
	if len(mailer.messages()) != 1 {
		t.Error("a revoked invitation was mailed")
	}
}
