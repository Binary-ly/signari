package httpapi

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/i18n"
	"signari.dev/engine/internal/pages"
)

// An account-security notice is written in the ACCOUNT HOLDER's language.
//
// # Why this is a security property and not a nicety
//
// These notices exist to reach the account holder on a channel whoever
// triggered the action may not control — a passkey was added, your password
// changed, a reset was requested. The case they are FOR is the one where the
// trigger was somebody else.
//
// In that case the request carries the ATTACKER's `Accept-Language`. Rendering
// the warning from the request would send the victim the single most important
// message this system produces in a language they may not read. It would still
// arrive, still say the right thing, and be useless — while the deployment
// records that the person was notified.
//
// So the language comes from `core.users.locale`, and this test holds that from
// the outside: a user whose stored preference is Arabic gets Arabic, whatever
// the request said.

func localeServer(t *testing.T) (*Server, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	set, _, err := pages.Load("")
	if err != nil {
		t.Fatalf("loading pages: %v", err)
	}
	return &Server{
		db:    pool,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		pages: set,
	}, pool
}

// localeUser creates a user with a stored language preference.
func localeUser(t *testing.T, s *Server, locale string) string {
	t.Helper()
	ctx := context.Background()
	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no organisation to attach a fixture user to: %v", err)
	}

	var id string
	if err := s.db.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email, locale)
		VALUES ($1::uuid, sha256($2::bytea) || sha256($3::bytea), $4, $5)
		RETURNING id::text`,
		orgID, []byte(t.Name()+"a"), []byte(t.Name()+"b"),
		strings.ToLower(t.Name())+"@example.test", nullable(locale)).Scan(&id); err != nil {
		t.Fatalf("creating the fixture user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(),
			`DELETE FROM core.users WHERE id = $1::uuid`, id)
	})
	return id
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func TestANoticeUsesTheAccountHoldersLanguage(t *testing.T) {
	s, _ := localeServer(t)
	userID := localeUser(t, s, "ar")

	tr := s.notifierFor(context.Background(), userID)
	if tr.Lang() != "ar" {
		t.Fatalf("notice language is %q, want ar. The account holder's stored "+
			"preference decides this, because the person who triggered the "+
			"action may be the one the notice is warning about.", tr.Lang())
	}

	subject := tr.Text("mail.password.changed.subject")
	if subject == "" || subject == "mail.password.changed.subject" {
		t.Fatalf("the Arabic subject did not render: %q", subject)
	}
	// A crude but decisive check: the English string must not be what came back.
	english := s.pageSet().Bundle().For("en").Text("mail.password.changed.subject")
	if subject == english {
		t.Errorf("the Arabic notice rendered the English text: %q", subject)
	}
}

// No stored preference falls back to the deployment default, never to a request.
func TestANoticeWithoutAPreferenceUsesTheDefault(t *testing.T) {
	s, _ := localeServer(t)
	userID := localeUser(t, s, "")

	if got := s.notifierFor(context.Background(), userID).Lang(); got != i18n.Default {
		t.Fatalf("language is %q, want the default %q", got, i18n.Default)
	}
}

// A user that does not exist still yields a usable printer.
//
// This runs on the path that tells somebody their account was touched. Failing
// it over a missing row would be the wrong trade every time: a notice in the
// default language beats no notice.
func TestANoticeForAnUnknownUserStillRenders(t *testing.T) {
	s, _ := localeServer(t)
	tr := s.notifierFor(context.Background(), "00000000-0000-0000-0000-000000000000")
	if tr == nil {
		t.Fatal("no printer for an unknown user; the notice path would panic")
	}
	if tr.Text("mail.password.changed.subject") == "" {
		t.Error("the fallback printer renders nothing")
	}
}

// Text must not HTML-escape, or a plain-text email arrives mangled.
//
// `T` escapes every substituted value because its output goes into a page. Using
// it for mail puts `o&#39;brien@example.test` in front of somebody reading a
// security notice — which is exactly the signal people are taught to read as a
// forgery.
func TestTheTextRendererDoesNotEscapeForHTML(t *testing.T) {
	s, _ := localeServer(t)
	p := s.pageSet().Bundle().For("en")

	got := p.Text("mail.passkey.added.body", map[string]any{
		"Label":   "Ada's key & spare",
		"When":    "31 August 2026",
		"Support": "https://id.example.test",
	})
	for _, bad := range []string{"&#39;", "&amp;", "&#34;"} {
		if strings.Contains(got, bad) {
			t.Errorf("the plain-text body contains the HTML entity %q: %s", bad, got)
		}
	}
	if !strings.Contains(got, "Ada's key & spare") {
		t.Errorf("the label did not survive substitution: %s", got)
	}
}
