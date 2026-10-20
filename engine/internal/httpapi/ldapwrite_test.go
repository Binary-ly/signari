package httpapi

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"signari.dev/engine/internal/passwords"
)

// An LDAP Delete signs the person out of every application before the row
// goes, as the admin API's delete does. It ran the DELETE alone, which
// cascaded the sessions away and with them the list of applications to tell:
// they kept the person signed in under an account that no longer existed.
func TestAnLDAPDeleteSignsThePersonOutEverywhere(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	f.signInAndReturnCookie(t)
	var sid string
	if err := f.pool.QueryRow(ctx, `
		SELECT sid FROM core.sessions WHERE user_id = $1::uuid ORDER BY created_at DESC LIMIT 1`,
		f.userID).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.clients SET backchannel_logout_uri = 'https://rp.example.test/backchannel' WHERE client_id = $1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		sid, f.clientID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.outbox WHERE topic = 'backchannel_logout' AND payload->>'sub' = $1`, f.userID)
	})

	w := NewLDAPWriter(f.pool, nil, passwords.Policy{}, f.orgID, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := w.Remove(ctx, "cn=admin", f.email); err != nil {
		t.Fatal(err)
	}

	var users, notices int
	if err := f.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM core.users WHERE id::text = $1),
		       (SELECT count(*) FROM core.outbox WHERE topic = 'backchannel_logout'
		           AND payload->>'sub' = $1 AND payload->>'client_id' = $2
		           AND payload->>'reason' = 'user_deleted')`,
		f.userID, f.clientID).Scan(&users, &notices); err != nil {
		t.Fatal(err)
	}
	if users != 0 {
		t.Fatalf("the entry survives the Delete")
	}
	if notices != 1 {
		t.Errorf("%d back-channel logout notices queued for the application the deleted person "+
			"was signed in to, want 1", notices)
	}
}
