// Package kerberos accepts SPNEGO logins from domain-joined machines.
//
// # What this is
//
// A user already signed in to a Windows domain or a FreeIPA realm has a
// Kerberos ticket. SPNEGO lets the browser present it, so signing in to Signari
// is no interaction at all — no password, no prompt.
//
// # Why this is not four weeks of work
//
// Because none of Kerberos is implemented here. gokrb5 handles keytabs, service
// ticket validation, encryption types, the replay cache and clock skew, and it
// has done so for years. Writing any of that again would be a project with a
// worse outcome.
//
// What is left is the part that is actually ours: mapping a principal to a
// person, refusing the mappings that are unsafe, and telling an operator why
// their keytab does not work BEFORE a user meets it.
//
// # The diagnosis is the feature
//
// Kerberos fails in ways the error never explains. A wrong service principal, a
// keytab exported at the wrong key version, a clock forty seconds out, an
// encryption type the KDC has disabled — every one of them surfaces to the user
// as the browser silently falling back to a password prompt, and to the
// operator as nothing at all.
//
// So Check exists, and it is worth more than the authentication itself.
package kerberos

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// Config is what a deployment needs to accept SPNEGO.
type Config struct {
	// KeytabPath is the service keytab, exported from the KDC.
	KeytabPath string
	// ServicePrincipal is the SPN this service answers as, e.g.
	// HTTP/auth.example.com@EXAMPLE.COM. Empty means accept anything in the
	// keytab, which is right when the keytab holds exactly one entry.
	ServicePrincipal string
	// Realm is the Kerberos realm, upper case by convention.
	Realm string
	// StripRealm removes @REALM when mapping a principal to a username.
	StripRealm bool
}

// Keytab loads and validates the keytab file.
func (c Config) Keytab() (*keytab.Keytab, error) {
	if c.KeytabPath == "" {
		return nil, fmt.Errorf("no keytab configured")
	}
	raw, err := os.ReadFile(c.KeytabPath)
	if err != nil {
		return nil, fmt.Errorf("reading the keytab: %w", err)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("%s is not a keytab: %w. Export it with `ktpass` on "+
			"Windows or `ipa-getkeytab` on FreeIPA -- a krb5.conf or a certificate "+
			"will produce exactly this error", c.KeytabPath, err)
	}
	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf("%s contains no entries. An empty keytab authenticates "+
			"nobody and looks identical to a working one until somebody tries",
			c.KeytabPath)
	}
	return kt, nil
}

// Entry describes one principal in a keytab, for reporting.
type Entry struct {
	Principal string
	KVNO      uint32
	EncType   int32
	Timestamp time.Time
}

// Entries lists what a keytab holds.
func Entries(kt *keytab.Keytab) []Entry {
	out := make([]Entry, 0, len(kt.Entries))
	for _, e := range kt.Entries {
		name := strings.Join(e.Principal.Components, "/")
		if e.Principal.Realm != "" {
			name += "@" + e.Principal.Realm
		}
		out = append(out, Entry{
			Principal: name,
			KVNO:      e.KVNO,
			EncType:   e.Key.KeyType,
			Timestamp: e.Timestamp,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal < out[j].Principal })
	return out
}

// EncTypeName renders an encryption type number.
//
// The numbers are how the KDC reports a mismatch, and nobody remembers them.
// A keytab holding only RC4 against a KDC that has disabled it fails with an
// error naming an integer.
func EncTypeName(t int32) string {
	switch t {
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 19:
		return "aes128-cts-hmac-sha256-128"
	case 20:
		return "aes256-cts-hmac-sha384-192"
	case 23:
		return "rc4-hmac (WEAK — disabled by default on current KDCs)"
	case 16:
		return "des3-cbc-sha1 (WEAK)"
	case 1, 2, 3:
		return "single-DES (BROKEN)"
	default:
		return fmt.Sprintf("enctype %d", t)
	}
}

// Weak reports whether an encryption type should not be relied on.
func Weak(t int32) bool {
	switch t {
	case 1, 2, 3, 16, 23:
		return true
	}
	return false
}

// UsernameFor maps a Kerberos principal to a local username.
//
// # The mapping is where the security is
//
// A principal is `alice@EXAMPLE.COM`. A local username is `alice` or
// `alice@example.com` depending on the deployment. Getting this wrong in the
// permissive direction — accepting a principal from a realm we do not trust, or
// letting a principal with an unexpected shape match a local account — is a
// full authentication bypass for anyone who can obtain a ticket from any realm
// the KDC will talk to.
//
// So the realm is checked explicitly rather than assumed, and a principal with
// instance components (`alice/admin@EXAMPLE.COM`) is refused: those are service
// and administrative principals, they are not people, and matching them to a
// user account of the same first component is how `alice/admin` becomes `alice`.
func (c Config) UsernameFor(principal string) (string, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return "", fmt.Errorf("empty principal")
	}

	name, realm, found := strings.Cut(principal, "@")
	if !found {
		return "", fmt.Errorf("principal %q carries no realm; refusing rather than "+
			"guessing which realm it came from", principal)
	}
	if c.Realm != "" && !strings.EqualFold(realm, c.Realm) {
		return "", fmt.Errorf("principal %q is from realm %q, not %q. A ticket from "+
			"another realm is not a user of this one, even where a trust exists",
			principal, realm, c.Realm)
	}
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("principal %q has an instance component. Those are "+
			"service and administrative principals rather than people, and matching "+
			"%q to a user account would let an administrative principal sign in as "+
			"the person who shares its first component", principal, name)
	}

	if c.StripRealm {
		return name, nil
	}
	// Lower-cased: realms are upper case by convention and email addresses are
	// not, so alice@EXAMPLE.COM must match alice@example.com.
	return name + "@" + strings.ToLower(realm), nil
}
