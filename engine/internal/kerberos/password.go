package kerberos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
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
	// KeytabPath and ServicePrincipal are this service's, the same as SPNEGO's.
	// Required: see Verify.
	KeytabPath, ServicePrincipal string
	// KeytabData is the keytab itself, in place of KeytabPath, for a realm whose
	// keytab this deployment holds sealed.
	KeytabData []byte
}

// keytab is the service's key, wherever it was given.
func (v PasswordVerifier) keytab() (*keytab.Keytab, error) {
	if v.KeytabData != nil {
		return ParseKeytab(v.KeytabData, "the keytab of realm "+v.Realm)
	}
	return Config{KeytabPath: v.KeytabPath}.Keytab()
}

// ErrRefused is returned for any password the KDC did not accept.
//
// One error for every reason. The KDC distinguishes "no such principal" from
// "wrong password" and passing that on would make this a user-enumeration
// oracle for anyone who can reach whatever exposes it.
var ErrRefused = fmt.Errorf("the realm did not accept those credentials")

// ErrKDCUnproven is a KDC that took the password and could not show it is the
// realm's. Not a wrong password: somebody else's KDC, or a keytab out of date.
var ErrKDCUnproven = errors.New("the KDC could not prove it holds this service's key")

// Verify asks the KDC for a ticket, and then for a ticket to this service.
//
// # Why the first is not enough
//
// The AS exchange proves only that whoever answered knows the key the reply was
// encrypted with, and whoever answers on the network can choose that: send a
// reply encrypted with a password of its own and any password "works" for it.
// That is the KDC spoofing attack, and the way out is the one every PAM module
// came to. Ask for a ticket to a service whose key this side holds, and open it.
// Nobody but the real KDC has that key to encrypt with.
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
	if (v.KeytabPath == "" && v.KeytabData == nil) || v.ServicePrincipal == "" {
		return fmt.Errorf("a password cannot be checked against a realm without a keytab and a service " +
			"principal: nothing else tells the realm's KDC from one that says yes")
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
	kt, err := v.keytab()
	if err != nil {
		return err
	}
	spn, _, _ := strings.Cut(v.ServicePrincipal, "@")
	realm := strings.ToUpper(v.Realm)

	cl := client.NewWithPassword(username, realm, password, cfg, client.DisablePAFXFAST(true))
	defer cl.Destroy()

	done := make(chan error, 1)
	go func() {
		if err := cl.Login(); err != nil {
			done <- loginFailure(err)
			return
		}
		tkt, _, err := cl.GetServiceTicket(spn)
		if err != nil {
			done <- fmt.Errorf("%w: asking for a ticket to %s: %w", ErrKDCUnproven, spn, err)
			return
		}
		done <- checkServiceTicket(&tkt, kt, spn, username, realm, time.Now())
	}()

	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		// A KDC that does not answer is NOT a wrong password. Saying so would
		// send an office to reset passwords they typed correctly.
		return fmt.Errorf("the KDC did not answer within %s", timeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loginFailure says what a failed AS exchange means. A KDC that said no is
// ErrRefused, whatever it said no about. One that was never reached, or a realm this
// configuration does not name, has said nothing about the password, and calling that
// a wrong one sends an office to reset passwords they typed correctly.
func loginFailure(err error) error {
	var failed krberror.Krberror
	if errors.As(err, &failed) &&
		(failed.RootCause == krberror.NetworkingError || failed.RootCause == krberror.ConfigError) {
		return fmt.Errorf("the KDC could not be asked: %w", err)
	}
	return ErrRefused
}

// ticketSkew is the clock drift allowed against a ticket's times, the five
// minutes Kerberos deployments have always allowed.
const ticketSkew = 5 * time.Minute

// checkServiceTicket opens a ticket with this service's key and holds it to the
// person who asked. Opening it is the proof; the rest stops a real ticket for
// somebody else, or an old one, being replayed in its place.
func checkServiceTicket(tkt *messages.Ticket, kt *keytab.Keytab, spn, username, realm string, now time.Time) error {
	sname, _ := types.ParseSPNString(spn)
	if err := tkt.DecryptEncPart(kt, &sname); err != nil {
		return fmt.Errorf("%w: %w", ErrKDCUnproven, err)
	}
	enc := tkt.DecryptedEncPart
	if enc.CName.PrincipalNameString() != username || !strings.EqualFold(enc.CRealm, realm) {
		return fmt.Errorf("%w: the ticket is for %s@%s", ErrKDCUnproven, enc.CName.PrincipalNameString(), enc.CRealm)
	}
	start := enc.StartTime
	if start.IsZero() {
		start = enc.AuthTime
	}
	if now.Before(start.Add(-ticketSkew)) || now.After(enc.EndTime.Add(ticketSkew)) {
		return fmt.Errorf("%w: the ticket is not current", ErrKDCUnproven)
	}
	return nil
}
