package httpapi

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// askForEverything subscribes the fixture's poll stream to what is advertised.
func (f *tokenFixture) askForEverything(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.ssf_streams SET events_requested = $2 WHERE client_id = $1`,
		f.clientID, ssf.SupportedEvents()); err != nil {
		t.Fatal(err)
	}
}

// inTx runs a change the way its callers do, committing it.
func (f *tokenFixture) inTx(t *testing.T, change func(pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := change(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// collected polls the stream and acknowledges what came, keyed by event type.
func (f *tokenFixture) collected(t *testing.T, secret string) map[string][]map[string]any {
	t.Helper()
	status, got := f.poll(t, secret, `{"returnImmediately":true,"maxEvents":100}`)
	if status != http.StatusOK {
		t.Fatalf("the poll answered %d", status)
	}
	out := map[string][]map[string]any{}
	var jtis []string
	for jti, jws := range got.Sets {
		jtis = append(jtis, `"`+jti+`"`)
		claims := setPayload(t, jws)
		for typ, event := range claims["events"].(map[string]any) {
			out[typ] = append(out[typ], event.(map[string]any))
		}
	}
	if len(jtis) > 0 {
		f.poll(t, secret, `{"returnImmediately":true,"ack":[`+strings.Join(jtis, ",")+`]}`)
	}
	return out
}

// Whatever a stream may subscribe to, something sends. A receiver was once left
// waiting on an advertised event nothing emitted, so this walks a person through
// each change and fails naming any advertised event that never arrived.
func TestEveryAdvertisedEventReachesAReceiver(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	ctx := context.Background()

	f.inTx(t, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, f.userID, "$argon2id$unused") })
	for _, status := range []string{"deactivated", "active"} {
		if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = $2 WHERE id = $1::uuid`, f.userID, status); err != nil {
			t.Fatal(err)
		}
	}
	f.inTx(t, func(tx pgx.Tx) error {
		_, err := store.TerminateSessions(ctx, tx, f.sid, "", store.ReasonAdminRevoke)
		return err
	})

	got := f.collected(t, secret)
	for _, event := range ssf.SupportedEvents() {
		if len(got[event]) != 1 {
			t.Errorf("%s arrived %d times, want once: %v", event, len(got[event]), got)
		}
	}
	for typ, events := range got {
		if !slices.Contains(ssf.SupportedEvents(), typ) {
			t.Errorf("%s arrived and is not advertised", typ)
		}
		subject, _ := events[0]["subject"].(map[string]any)
		if subject["sub"] != f.userID {
			t.Errorf("%s is about %v", typ, subject)
		}
		stamp, _ := events[0]["event_timestamp"].(float64)
		if at := time.Unix(int64(stamp), 0); time.Since(at) > time.Minute {
			t.Errorf("%s has event_timestamp %v", typ, at)
		}
	}
	change := got[ssf.EventCredentialChange][0]
	if change["credential_type"] != "password" || change["change_type"] != "update" ||
		change["initiating_entity"] != "user" {
		t.Errorf("the credential change says %v", change)
	}
}

// A stream hears of people its client has met, and of what it asked for.
func TestAStreamHearsOnlyOfThosePeopleItsClientHasMet(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	ctx := context.Background()

	// Sessions and the record of who they reached are gone: this client never met
	// the person as far as anything can show.
	if _, err := f.pool.Exec(ctx, `DELETE FROM core.session_clients WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	f.inTx(t, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, f.userID, "$argon2id$unused") })
	if got := f.collected(t, secret); len(got) != 0 {
		t.Errorf("a client that never met the person heard %v", got)
	}

	// A refresh family is meeting them too, with no session behind it.
	var family string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.refresh_token_families (org_id, client_id, user_id)
		VALUES ($1, $2, $3) RETURNING id::text`, f.orgID, f.clientID, f.userID).Scan(&family); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.refresh_token_families WHERE id = $1::uuid`, family)
	})
	f.inTx(t, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, f.userID, "$argon2id$unused") })
	if got := f.collected(t, secret); len(got[ssf.EventCredentialChange]) != 1 {
		t.Errorf("a client holding a refresh family heard %v", got)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE core.ssf_streams SET events_requested = $2 WHERE client_id = $1`,
		f.clientID, []string{ssf.EventSessionRevoked}); err != nil {
		t.Fatal(err)
	}
	f.inTx(t, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, f.userID, "$argon2id$unused") })
	if got := f.collected(t, secret); len(got) != 0 {
		t.Errorf("a stream that did not ask heard %v", got)
	}
}

// The change that ends a person's sessions is the one receivers most need, so a
// session already ended in the same transaction still counts as having met them.
func TestReceiversHearOfAChangeThatEndedTheSession(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	ctx := context.Background()
	f.inTx(t, func(tx pgx.Tx) error {
		if _, err := store.TerminateSessions(ctx, tx, "", f.userID, store.ReasonUserDeactivated); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID)
		return err
	})
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID)
	})
	if got := f.collected(t, secret); len(got[ssf.EventAccountDisabled]) != 1 {
		t.Errorf("the deactivation reached the receiver as %v", got)
	}
}

// The status is a fact of the row, so a write that does not change it says nothing,
// and an account waiting for approval was never disabled.
func TestOnlyAChangeOfStandingIsAnEvent(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	ctx := context.Background()
	for _, status := range []string{"active", "pending", "active"} {
		if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = $2 WHERE id = $1::uuid`, f.userID, status); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.collected(t, secret); len(got) != 0 {
		t.Errorf("no standing changed and the receiver heard %v", got)
	}
}

// Each way a credential changes says what it changed, with the word CAEP has for
// it, and an emailed code or a recovery code, which have no word, says nothing.
func TestEachCredentialChangeNamesItself(t *testing.T) {
	f := newTokenFixture(t)
	secret := f.makePollStream(t)
	f.askForEverything(t)
	ctx := context.Background()

	said := func(want string, change func(pgx.Tx) error) {
		t.Helper()
		f.inTx(t, change)
		got := f.collected(t, secret)[ssf.EventCredentialChange]
		var line []string
		for _, e := range got {
			line = append(line, e["credential_type"].(string)+" "+e["change_type"].(string)+" "+e["initiating_entity"].(string))
		}
		if strings.Join(line, ",") != want {
			t.Errorf("heard %q, want %q", strings.Join(line, ","), want)
		}
	}

	var rowID string
	said("fido2-platform create user", func(tx pgx.Tx) error {
		return store.SaveCredential(ctx, tx, f.userID, f.orgID, "rp.example", []byte("cred-"+f.userID), []byte("key"),
			make([]byte, 16), 0, true, true, true, []string{"internal"}, "none", "laptop")
	})
	said("fido2-roaming create user", func(tx pgx.Tx) error {
		if err := store.SaveCredential(ctx, tx, f.userID, f.orgID, "rp.example", []byte("cred2-"+f.userID), []byte("key"),
			make([]byte, 16), 0, true, false, false, []string{"usb"}, "none", "key"); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT id::text FROM core.webauthn_credentials
			WHERE user_id = $1::uuid AND 'usb' = ANY(transports)`, f.userID).Scan(&rowID)
	})
	said("fido2-roaming delete admin", func(tx pgx.Tx) error {
		_, err := store.RemoveFactor(ctx, tx, f.userID, "webauthn", rowID)
		return err
	})
	f.inTx(t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM core.webauthn_credentials WHERE user_id = $1::uuid`, f.userID).Scan(&rowID)
	})
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, 'x', 'argon2id') ON CONFLICT (user_id) DO NOTHING`, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	said("fido2-platform delete user", func(tx pgx.Tx) error { return store.DeleteCredential(ctx, tx, f.userID, rowID) })

	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	assign := func(tx pgx.Tx) error {
		_, err := store.AssignOTPToken(ctx, tx, f.userID, f.orgID, []byte("otp-secret"), "totp", "SHA1", 6, 30*time.Second, 0, root)
		return err
	}
	said("app create admin", assign)
	said("app update admin", assign)
	said("app delete user", func(tx pgx.Tx) error {
		_, err := store.RemoveOwnFactor(ctx, tx, f.userID, "totp")
		return err
	})
	said("app create admin", func(tx pgx.Tx) error { return store.EnrollDuo(ctx, tx, f.userID, f.orgID, "someone") })
	said("app delete admin", func(tx pgx.Tx) error {
		_, err := store.RemoveFactor(ctx, tx, f.userID, "duo", "")
		return err
	})
	said("", func(tx pgx.Tx) error {
		_, err := store.GenerateRecoveryCodes(ctx, tx, f.userID, f.orgID, 2)
		return err
	})
	said("", func(tx pgx.Tx) error {
		_, err := store.RemoveFactor(ctx, tx, f.userID, "recovery", "")
		return err
	})
}
