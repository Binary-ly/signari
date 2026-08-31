package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Reading users FROM an LDAP directory.
//
// The other direction from internal/ldapd, which lets applications bind to this
// engine. This is the inbound half: an organisation that already has OpenLDAP,
// Active Directory or FreeIPA can use this as its identity provider without
// re-entering everybody.
//
// # The immutable identifier is the whole design
//
// A DN is not stable: moving somebody between organisational units rewrites it,
// and so does a rename. An email is not stable either. Both are the obvious
// choice and both make a rename look like a departure plus an arrival --
// deactivating an account and creating a new one, which is how a directory sync
// locks somebody out of everything they own.
//
// So every flavour is read through its own immutable attribute:
//
//	OpenLDAP / FreeIPA   entryUUID   a UUID string
//	Active Directory     objectGUID  binary, hex-encoded here
//
// Getting this wrong is not a subtle bug: it is a mass lockout on the day
// somebody reorganises an OU tree.

// LDAPFlavour selects the attribute conventions.
type LDAPFlavour string

const (
	FlavourOpenLDAP LDAPFlavour = "openldap"
	FlavourAD       LDAPFlavour = "ad"
	FlavourFreeIPA  LDAPFlavour = "freeipa"
)

// LDAPSource reads users from a directory server.
type LDAPSource struct {
	// URL is ldap:// or ldaps://.
	URL      string
	BindDN   string
	Password string
	BaseDN   string
	// Filter is an LDAP filter. Empty gets a flavour-appropriate default.
	Filter  string
	Flavour LDAPFlavour

	// GroupAttribute names the attribute carrying a person's group memberships,
	// usually `memberOf`. EMPTY MEANS GROUPS ARE NOT FETCHED AT ALL, and that
	// distinction is load-bearing.
	//
	// A source that does not fetch groups reports every user with an empty group
	// list. Feeding that into BuildGroupPlan would read as "everybody is in no
	// groups" and propose removing every governed membership in the
	// organisation -- caught by the removal ceiling, but only after proposing a
	// change that was never real.
	//
	// So the sync only runs group reconciliation when this is set, and the
	// absence of the setting is what says "this source has nothing to say about
	// groups" rather than "this source says nobody is in any".
	GroupAttribute string

	// StartTLS upgrades a plaintext connection. Ignored for ldaps://.
	StartTLS bool
	// CAs verifies the server. nil uses the system roots.
	CAs *x509.CertPool
	// InsecureSkipVerify is deliberately absent. A directory sync carries every
	// employee's identity; an unverified server is a machine-in-the-middle
	// waiting to feed us a directory of its own choosing.

	// PageSize bounds each search page. Directories refuse unbounded searches
	// above a server-side limit, and hitting it silently truncates.
	PageSize uint32

	// Dial is overridden in tests.
	Dial func(context.Context, string) (ldapConn, error)
}

// ldapConn is the slice of go-ldap this package uses, so a test can supply its
// own without a server.
type ldapConn interface {
	Bind(username, password string) error
	// UnauthenticatedBind is how an anonymous bind is actually done. Bind("", "")
	// looks like the obvious way and is refused by the client library before it
	// reaches the wire -- see the comment in Fetch.
	UnauthenticatedBind(username string) error
	SearchWithPaging(req *ldap.SearchRequest, pageSize uint32) (*ldap.SearchResult, error)
	Close() error
}

func (s *LDAPSource) attributes() (uidAttr, mailAttr, nameAttr, idAttr, disabledAttr string) {
	switch s.Flavour {
	case FlavourAD:
		return "sAMAccountName", "mail", "displayName", "objectGUID", "userAccountControl"
	case FlavourFreeIPA:
		return "uid", "mail", "displayName", "ipaUniqueID", "nsAccountLock"
	default:
		return "uid", "mail", "cn", "entryUUID", ""
	}
}

func (s *LDAPSource) defaultFilter() string {
	switch s.Flavour {
	case FlavourAD:
		// Real people, not computers or service principals. Without the category
		// clause an AD sync imports every workstation as a user.
		return "(&(objectCategory=person)(objectClass=user))"
	case FlavourFreeIPA:
		return "(objectClass=posixaccount)"
	default:
		return "(objectClass=inetOrgPerson)"
	}
}

// Fetch reads every user under the base DN.
//
// A search that fails part-way is an ERROR, never a shorter list -- the same
// rule the Google and Entra adapters follow, and for the same reason: the
// reconciler downstream cannot tell a complete directory from a truncated one,
// and a truncated one looks exactly like a company where everybody left.
func (s *LDAPSource) Fetch(ctx context.Context) ([]RemoteUser, error) {
	if s.BaseDN == "" {
		return nil, fmt.Errorf("no base DN: without one the search has no scope and " +
			"most servers refuse it outright")
	}

	conn, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if s.BindDN != "" {
		if s.Password == "" {
			return nil, fmt.Errorf("bind DN %q has no password: on most servers that "+
				"is an UNAUTHENTICATED bind, which succeeds and leaves the connection "+
				"anonymous -- every later search would then read whatever the "+
				"directory publishes to strangers while appearing to be authorised",
				s.BindDN)
		}
		if err := conn.Bind(s.BindDN, s.Password); err != nil {
			return nil, fmt.Errorf("binding as %q: %w", s.BindDN, err)
		}
	} else {
		// An anonymous bind reads whatever the directory publishes to strangers,
		// which is usually far less than the operator expects and occasionally
		// nothing at all. Allowed, because some directories are configured that
		// way, but never silently.
		//
		// UnauthenticatedBind, not Bind("", ""). The client library refuses a
		// simple bind with an empty password before it reaches the wire, because
		// a DN with an empty password succeeds AS ANONYMOUS on most servers --
		// so an application that binds with a real DN and a blank password gets a
		// successful bind and none of the access it thinks it has. Guarding
		// against that also blocks the legitimately anonymous case, which needs
		// this separate call.
		//
		// The first version called Bind("", "") and could never connect to any
		// server at all. The test's fake connection accepted it, which is what a
		// fake does.
		if err := conn.UnauthenticatedBind(""); err != nil {
			return nil, fmt.Errorf("binding anonymously: %w (set a bind DN if this "+
				"directory does not allow anonymous search)", err)
		}
	}

	uidAttr, mailAttr, nameAttr, idAttr, disabledAttr := s.attributes()
	filter := s.Filter
	if filter == "" {
		filter = s.defaultFilter()
	}

	attrs := []string{uidAttr, mailAttr, nameAttr, idAttr}
	if disabledAttr != "" {
		attrs = append(attrs, disabledAttr)
	}
	// Only when asked for. Requesting the attribute unconditionally would make
	// every source look like it reports groups, and a source reporting none is
	// indistinguishable from one saying nobody is in any -- see GroupAttribute.
	if s.GroupAttribute != "" {
		attrs = append(attrs, s.GroupAttribute)
	}

	pageSize := s.PageSize
	if pageSize == 0 {
		pageSize = 500
	}

	req := ldap.NewSearchRequest(
		s.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil)

	// SearchWithPaging follows RFC 2696 to the end and returns an error if a page
	// fails. That is the behaviour this depends on: a plain Search stops at the
	// server's size limit and reports success, which is the silent truncation
	// this whole file is written to avoid.
	res, err := conn.SearchWithPaging(req, pageSize)
	if err != nil {
		return nil, fmt.Errorf("searching %q: %w", s.BaseDN, err)
	}

	out := make([]RemoteUser, 0, len(res.Entries))
	var missingID int
	for _, e := range res.Entries {
		id := s.immutableID(e, idAttr)
		if id == "" {
			// Cannot be tracked across a rename or a move. Counted and reported
			// rather than falling back to the DN, which is the mistake that
			// causes the mass lockout.
			missingID++
			continue
		}
		email := e.GetAttributeValue(mailAttr)
		if email == "" {
			// Some directories keep mail elsewhere or nowhere. The uid is not an
			// address, so it is used only as a last resort and the caller can see
			// what happened in the plan.
			email = e.GetAttributeValue(uidAttr)
		}
		var groups []string
		if s.GroupAttribute != "" {
			// Every value, not the first. A person is in several groups, and
			// GetAttributeValue returns one -- which would silently reduce
			// everybody to their alphabetically-first membership and propose
			// removing the rest.
			groups = e.GetAttributeValues(s.GroupAttribute)
		}

		out = append(out, RemoteUser{
			ID:        id,
			Email:     email,
			Name:      e.GetAttributeValue(nameAttr),
			Suspended: s.disabled(e, disabledAttr),
			Groups:    groups,
		})
	}

	if missingID > 0 && len(out) == 0 {
		return nil, fmt.Errorf("every one of the %d entries found lacks %q. This is "+
			"usually the wrong flavour: Active Directory uses objectGUID, OpenLDAP and "+
			"FreeIPA use entryUUID or ipaUniqueID", missingID, idAttr)
	}
	if missingID > 0 {
		return nil, fmt.Errorf("%d of %d entries lack %q and cannot be tracked across "+
			"a rename; refusing rather than importing them under an unstable key",
			missingID, missingID+len(out), idAttr)
	}
	return out, nil
}

// immutableID reads the flavour's stable identifier.
func (s *LDAPSource) immutableID(e *ldap.Entry, attr string) string {
	if s.Flavour == FlavourAD {
		// objectGUID is binary. Hex here rather than the Microsoft display form:
		// the value only has to be stable and comparable, and the display form
		// reorders bytes in a way that is easy to get subtly wrong.
		raw := e.GetRawAttributeValue(attr)
		if len(raw) == 0 {
			return ""
		}
		return hex.EncodeToString(raw)
	}
	return e.GetAttributeValue(attr)
}

// disabled reads whether the directory considers this account switched off.
func (s *LDAPSource) disabled(e *ldap.Entry, attr string) bool {
	if attr == "" {
		return false
	}
	v := e.GetAttributeValue(attr)
	switch s.Flavour {
	case FlavourAD:
		// userAccountControl is a bit field; 0x2 is ACCOUNTDISABLE. Parsed as an
		// integer rather than string-matched, because the other bits vary and a
		// substring test would be wrong for most accounts.
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return false
		}
		return n&0x2 != 0
	case FlavourFreeIPA:
		// nsAccountLock is the string "TRUE" when locked.
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

func (s *LDAPSource) connect(ctx context.Context) (ldapConn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, s.URL)
	}

	tlsCfg := &tls.Config{RootCAs: s.CAs, MinVersion: tls.VersionTLS12}

	conn, err := ldap.DialURL(s.URL, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("connecting to %q: %w", s.URL, err)
	}
	conn.SetTimeout(30 * time.Second)

	if s.StartTLS && strings.HasPrefix(s.URL, "ldap://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("StartTLS on %q: %w (a bind over plaintext sends "+
				"the bind password in the clear)", s.URL, err)
		}
	}
	return conn, nil
}
