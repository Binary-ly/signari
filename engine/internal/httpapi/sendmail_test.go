package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// useMailSender gives an organisation its own sender for the length of a test.
func useMailSender(t *testing.T, f *signInFixture, sender store.MailSender) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetOrgMailSender(ctx, tx, f.orgID, sender); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `UPDATE core.organizations
			SET mail_from = NULL, mail_from_name = NULL WHERE id = $1::uuid`, f.orgID)
	})
}

// A message sent past sendMail would go out from the deployment's address with no
// brand on it, and nothing else would notice: it still arrives. The list of
// senders is therefore one file, read from the source.
func TestEveryMessageLeavesThroughSendMail(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("reading the package: %v", err)
	}
	direct := regexp.MustCompile(`\.mailer\.Send\(`)
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		n := len(direct.FindAll(src, -1))
		seen += n
		if n > 0 && name != "sendmail.go" {
			t.Errorf("%s calls the mailer itself %d time(s): use sendMail or sendMailTo, or its "+
				"organisation's sender is dropped", name, n)
		}
	}
	if seen != 1 {
		t.Errorf("the mailer is called %d time(s), wanting the one in sendmail.go: the scan is broken", seen)
	}
}

// An organisation's mail comes from its own address and carries the brand, its
// neighbour's does not, and one with no sender keeps the deployment's.
func TestAnOrganisationsMailCarriesItsSenderAndTheLook(t *testing.T) {
	f := newSignInFixture(t)
	other := newSignInFixture(t)
	if f.orgID == other.orgID {
		t.Fatal("the two fixtures share an organisation, so this test proves nothing")
	}
	ctx := context.Background()
	cap, neighbour := &captureMailer{}, &captureMailer{}
	f.srv.mailer, other.srv.mailer = cap, neighbour
	notice := func(f *signInFixture) store.AccountNotice {
		return store.AccountNotice{UserID: f.userID, Notice: store.NoticePasswordChanged}
	}

	if err := f.srv.DeliverAccountNotice(ctx, notice(f)); err != nil {
		t.Fatal(err)
	}
	if m := cap.messages()[0]; m.From != "" || m.FromName != "" || m.Look.Product != "" {
		t.Errorf("before anything is set the message says %q %q, look %+v", m.FromName, m.From, m.Look)
	}

	useMailSender(t, f, store.MailSender{From: "id@acme.example", Name: "Acme Identity"})
	// The brand is the instance's, and the fixture's issuer names none.
	if err := f.pool.QueryRow(ctx, `SELECT i.issuer FROM core.instances i
		JOIN core.organizations o ON o.instance_id = i.id WHERE o.id = $1::uuid`, f.orgID).Scan(&f.srv.cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	tag, err := f.pool.Exec(ctx, `
		INSERT INTO core.brands (instance_id, product_name, colour_primary, colour_on_primary,
		                         colour_background, colour_text)
		SELECT id, 'Acme', '#aa0000', '#ffffff', '#fafafa', '#101010' FROM core.instances WHERE issuer = $1
		ON CONFLICT (instance_id) DO UPDATE SET product_name = EXCLUDED.product_name,
			colour_primary = EXCLUDED.colour_primary, colour_on_primary = EXCLUDED.colour_on_primary,
			colour_background = EXCLUDED.colour_background, colour_text = EXCLUDED.colour_text`, f.srv.cfg.Issuer)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("setting the brand: %d rows, %v", tag.RowsAffected(), err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.brands
			WHERE instance_id = (SELECT id FROM core.instances WHERE issuer = $1)`, f.srv.cfg.Issuer)
	})

	if err := f.srv.DeliverAccountNotice(ctx, notice(f)); err != nil {
		t.Fatal(err)
	}
	m := cap.messages()[1]
	if m.From != "id@acme.example" || m.FromName != "Acme Identity" {
		t.Errorf("a person's notice says %q %q", m.FromName, m.From)
	}
	if m.Look.Product != "Acme" || m.Look.Link != "#aa0000" || m.Look.Background != "#fafafa" || m.Look.Text != "#101010" {
		t.Errorf("the look is %+v", m.Look)
	}

	// Nobody's account: what stands behind an invitation is the organisation.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, _, _, err := store.NewInvitation(ctx, tx, store.InvitationSpec{
		OrgID: f.orgID, Email: "invited-" + f.email, TTL: 3600e9, Send: true})
	if err != nil {
		t.Fatal(err)
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
	if err := f.srv.DeliverAccountNotice(ctx, store.AccountNotice{Notice: store.NoticeInvitation, LinkID: id}); err != nil {
		t.Fatal(err)
	}
	if m := cap.messages()[2]; m.From != "id@acme.example" {
		t.Errorf("an invitation says %q", m.From)
	}

	if err := other.srv.DeliverAccountNotice(ctx, notice(other)); err != nil {
		t.Fatal(err)
	}
	if m := neighbour.messages()[0]; m.From != "" {
		t.Errorf("the neighbouring organisation's mail comes from %q", m.From)
	}
}
