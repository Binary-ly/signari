package kerberos

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// Verifying a password against the KDC.
//
// The second of the three ways a realm is used for authentication. SPNEGO
// covers a domain-joined browser; this covers everything else -- a mail client
// binding over LDAP, a VPN asking through RADIUS, a person on a machine that is
// not domain-joined typing the password they already have.
//
// # What it does and does not prove
//
// A successful AS-REQ proves the KDC accepted that password for that principal
// AT THIS MOMENT. It does not prove the account should have access here, and it
// does not create one: that stays the directory's job, exactly as with SPNEGO.
//
// # Why the KDC is asked rather than a hash compared
//
// There is no hash to compare. A realm does not publish password material, and
// the only way to check a password is to ask the KDC for a ticket with it. That
// also means every check is a live one: a password changed or an account
// disabled five seconds ago is refused here, which a cached hash could not do.

// KRB5ConfPath is where the realm configuration is read from.
//
// Read fresh on each verification rather than cached at startup: a realm whose
// KDCs move is a realm an operator fixes by editing this file, and requiring a
// restart to pick it up turns a five-second change into a maintenance window.
const KRB5ConfPath = "/etc/krb5.conf"

// PasswordVerifier checks passwords against a realm.
type PasswordVerifier struct {
	Realm string
	// ConfPath overrides /etc/krb5.conf.
	ConfPath string
	// Timeout bounds one exchange with the KDC.
	Timeout time.Duration
}

// ErrRefused is returned for any password the KDC did not accept.
//
// One error for every reason. The KDC distinguishes "no such principal" from
// "wrong password" and passing that on would make this a user-enumeration
// oracle for anyone who can reach whatever exposes it.
var ErrRefused = fmt.Errorf("the realm did not accept those credentials")

// Verify asks the KDC for a ticket.
func (v PasswordVerifier) Verify(ctx context.Context, username, password string) error {
	if v.Realm == "" {
		return fmt.Errorf("no Kerberos realm is configured")
	}
	if password == "" {
		// Refused without asking. An empty password against some KDC
		// configurations succeeds as an anonymous or pre-auth-less bind, and the
		// result is an authenticated session for a password nobody typed.
		return ErrRefused
	}
	// A principal with an instance component is a service or administrative
	// principal rather than a person, refused for the same reason SPNEGO
	// refuses it.
	if strings.Contains(username, "/") {
		return ErrRefused
	}
	// Strip a realm the caller may have included, so alice and alice@REALM
	// behave the same.
	if at := strings.LastIndex(username, "@"); at >= 0 {
		realm := username[at+1:]
		if !strings.EqualFold(realm, v.Realm) {
			// A principal naming another realm is not a user of this one.
			return ErrRefused
		}
		username = username[:at]
	}

	path := v.ConfPath
	if path == "" {
		path = KRB5ConfPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w. Kerberos password verification needs a "+
			"realm configuration naming the KDCs", path, err)
	}
	cfg, err := config.NewFromString(string(raw))
	if err != nil {
		return fmt.Errorf("%s did not parse as a krb5 configuration: %w", path, err)
	}

	cl := client.NewWithPassword(username, strings.ToUpper(v.Realm), password, cfg,
		client.DisablePAFXFAST(true))
	defer cl.Destroy()

	done := make(chan error, 1)
	go func() { done <- cl.Login() }()

	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	select {
	case err := <-done:
		if err != nil {
			return ErrRefused
		}
		return nil
	case <-time.After(timeout):
		// A KDC that does not answer is NOT a wrong password. Saying so would
		// send an office to reset passwords they typed correctly.
		return fmt.Errorf("the KDC did not answer within %s", timeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}
