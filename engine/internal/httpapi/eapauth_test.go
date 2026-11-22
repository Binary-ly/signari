package httpapi

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/passwords"
)

// A write refused to an account outside the write group is audited by the
// account's subject, with the operation and without the username (3.33).
func TestARefusedLDAPWriteIsAuditedBySubject(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	name := fmt.Sprintf("ldap-refused-%d", time.Now().UnixNano())
	var id string
	if err := db.QueryRow(ctx, `
		INSERT INTO core.users (org_id, username, user_handle)
		VALUES ($1::uuid, $2, decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING id::text`, org, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id) })

	NewLDAPWriter(db, nil, passwords.Policy{}, org, slog.New(slog.NewTextHandler(io.Discard, nil))).
		Refused(ctx, name, "modify_dn")
	var detail string
	if err := db.QueryRow(ctx, `
		SELECT detail::text FROM core.audit_events
		WHERE event_type = 'ldap.write_refused' AND subject_id = $1::uuid AND actor_id = $1::uuid
		  AND detail->>'operation' = 'modify_dn'`, id).Scan(&detail); err != nil {
		t.Fatalf("no ldap.write_refused row for subject %s: %v", id, err)
	}
	if strings.Contains(detail, name) {
		t.Errorf("the audit row carries the username: %s", detail)
	}
}

// A certificate sign-in is audited by subject, succeeded or failed, and
// names the certificate by its serial (3.33). Nothing recorded one: the
// listener logged the username, and since that was taken out of the log
// (3.07) there was no record at all of who had joined the network.
func TestACertificateSignInIsAuditedBySubject(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var org string
	if err := db.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		t.Skipf("no organisation: %v", err)
	}
	stamp := time.Now().UnixNano()
	user := func(email, status string) string {
		t.Helper()
		var id string
		if err := db.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, status, user_handle)
			VALUES ($1::uuid, $2, $3, decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
			RETURNING id::text`, org, email, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, id) })
		return id
	}
	active := user(fmt.Sprintf("eap-on-%d@example.test", stamp), "active")
	gone := user(fmt.Sprintf("eap-off-%d@example.test", stamp), "deactivated")

	a := NewEAPCertAuthenticator(db, org, "email")
	for i, c := range []struct {
		email, event, subject, reason string
	}{
		{fmt.Sprintf("eap-on-%d@example.test", stamp), "login.succeeded", active, ""},
		{fmt.Sprintf("eap-off-%d@example.test", stamp), "login.failed", gone, "inactive"},
		{fmt.Sprintf("eap-nobody-%d@example.test", stamp), "login.failed", "", "unknown_user"},
	} {
		serial := big.NewInt(stamp + int64(i))
		_, err := a.AuthenticateCertificate(&x509.Certificate{SerialNumber: serial, EmailAddresses: []string{c.email}})
		if (err == nil) != (c.event == "login.succeeded") {
			t.Errorf("%s: err = %v", c.email, err)
		}
		if err != nil && strings.Contains(err.Error(), c.email) {
			t.Errorf("%s: the error quotes the certificate's address, and it is logged: %v", c.email, err)
		}
		var event, subject, reason string
		if err := db.QueryRow(ctx, `
			SELECT event_type, COALESCE(subject_id::text, ''), COALESCE(detail->>'reason', '')
			FROM core.audit_events
			WHERE detail->>'certificate_serial' = $1 AND detail->>'via' = 'eap-tls'`, serial.String()).
			Scan(&event, &subject, &reason); err != nil {
			t.Errorf("%s: no audit row for certificate %s: %v", c.email, serial, err)
			continue
		}
		if event != c.event || subject != c.subject || reason != c.reason {
			t.Errorf("%s: audited %s subject %q reason %q, want %s %q %q", c.email, event, subject, reason,
				c.event, c.subject, c.reason)
		}
	}
}
