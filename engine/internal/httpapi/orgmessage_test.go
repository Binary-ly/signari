package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/pages"
	"signari.dev/engine/internal/store"
)

func (b *brandedTenants) reword(t *testing.T, orgID, locale, key, text string) {
	t.Helper()
	if err := store.SetOrgMessage(context.Background(), b.f.pool, orgID,
		store.OrgMessage{Locale: locale, Key: key, Body: text}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = b.f.pool.Exec(context.Background(), `DELETE FROM core.org_messages WHERE org_id = $1::uuid`, orgID)
	})
}

func TestAnOrganisationsPagesSayItsWords(t *testing.T) {
	b := newBrandedTenants(t)
	f := b.f
	b.reword(t, f.orgID, "en", "login.heading", "Acme <staff> only")
	b.reword(t, f.orgID, "ar", "login.heading", "موظفو أكمي فقط")

	own := b.login(t, f.plainAuthz()).Body.String()
	if !strings.Contains(own, "Acme &lt;staff&gt; only") {
		t.Errorf("the page does not say the organisation's words")
	}
	if strings.Contains(own, "<staff>") {
		t.Error("a tenant's words reached the page as markup")
	}
	if its := b.login(t, b.neighbourAuthz).Body.String(); strings.Contains(its, "staff") {
		t.Error("one organisation's words are on another's page")
	}

	// The reader's language chooses among them.
	r := httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(f.plainAuthz()), nil)
	r.Header.Set("Accept-Language", "ar")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	if !strings.Contains(rec.Body.String(), "موظفو أكمي فقط") {
		t.Error("the page in Arabic does not say the organisation's Arabic")
	}

	// A sentence decided in Go, on a page, says theirs too.
	b.reword(t, f.orgID, "en", "mail.invitation.subject", "Join Acme, {Org}")
	req := httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(f.plainAuthz()), nil)
	if got := f.srv.tr(req).Text("mail.invitation.subject", map[string]any{"Org": "A&B"}); got != "Join Acme, A&B" {
		t.Errorf("a message decided in Go reads %q", got)
	}
}

func TestAnOrganisationsMailSaysItsWords(t *testing.T) {
	b := newBrandedTenants(t)
	f := b.f
	ctx := context.Background()
	b.reword(t, f.orgID, "en", "mail.invitation.subject", "Join Acme")

	if got := f.srv.notifierFor(ctx, f.userID).Text("mail.invitation.subject"); got != "Join Acme" {
		t.Errorf("a notice to a person of the organisation reads %q", got)
	}
	if got := f.srv.printerFor(ctx, b.neighbour, i18n.Default).Text("mail.invitation.subject"); got == "Join Acme" {
		t.Error("another organisation's mail says these words")
	}
	if got := f.srv.printerFor(ctx, "", i18n.Default).Text("mail.invitation.subject"); got == "Join Acme" {
		t.Error("a page that is nobody's says these words")
	}

	// Nobody's account yet, so the organisation is all that speaks for an invitation.
	mailer := &captureMailer{}
	f.srv.mailer = mailer
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
	if got := mailer.messages()[0].Subject; got != "Join Acme" {
		t.Errorf("an invitation's subject is %q", got)
	}
}

// A theme directory is read at startup, by slug, and only that organisation's
// people read it; a reworded message is said over either.
func TestAnOrganisationsThemeReachesItsPages(t *testing.T) {
	b := newBrandedTenants(t)
	f := b.f
	ctx := context.Background()
	slug, err := store.OrgSlug(ctx, f.pool, f.orgID)
	if err != nil || slug == "" {
		t.Fatalf("the slug is %q: %v", slug, err)
	}
	dir := t.TempDir()
	layout := strings.Replace(pages.BuiltIn()["layout"], "</body>", "<i hidden>org layout</i></body>", 1)
	orgDir := filepath.Join(dir, pages.OrgThemesDir, slug)
	if err := os.MkdirAll(orgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orgDir, "layout.html"), []byte(layout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(orgDir, "locales"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orgDir, "locales", "de.json"),
		[]byte(`{"login.heading": "Anmelden bei Acme"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	set, problems, err := pages.Load(dir)
	if err != nil || len(problems) != 0 {
		t.Fatalf("loading the theme: %v %v", problems, err)
	}
	f.srv.pages = set

	if !strings.Contains(b.login(t, f.plainAuthz()).Body.String(), "org layout") {
		t.Error("the organisation's theme is not on its page")
	}
	if strings.Contains(b.login(t, b.neighbourAuthz).Body.String(), "org layout") {
		t.Error("one organisation's theme is on another's page")
	}
	if strings.Contains(b.login(t, "").Body.String(), "org layout") {
		t.Error("a bare page wears an organisation's theme")
	}

	// A language only its theme has is one its readers can be answered in.
	german := func(authz string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/login?authz="+url.QueryEscape(authz), nil)
		r.Header.Set("Accept-Language", "de")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, r)
		return rec.Body.String()
	}
	if !strings.Contains(german(f.plainAuthz()), "Anmelden bei Acme") {
		t.Error("a language the organisation's theme adds was not spoken to its readers")
	}
	if strings.Contains(german(b.neighbourAuthz), "Anmelden") {
		t.Error("a language one organisation's theme adds reached another's page")
	}

	b.reword(t, f.orgID, "en", "login.heading", "Acme people")
	page := b.login(t, f.plainAuthz()).Body.String()
	if !strings.Contains(page, "org layout") || !strings.Contains(page, "Acme people") {
		t.Error("a theme and an organisation's words should both be on the page")
	}
}
