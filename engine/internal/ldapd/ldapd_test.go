package ldapd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// The client here is go-ldap, a separate implementation by different authors.
// Testing our server with our own client would only prove we are
// self-consistent -- and self-consistency is exactly what a protocol bug looks
// like from the inside.

type fakeAuth struct{ calls int }

var fixtures = map[string]struct{ pw, email, name string }{
	"alice": {"correct-horse-battery", "alice@example.test", "Alice Example"},
	"bob":   {"hunter2hunter2", "bob@example.test", "Bob Example"},
}

func (f *fakeAuth) Authenticate(_ context.Context, u, p string) (*Identity, error) {
	f.calls++
	r, ok := fixtures[strings.ToLower(u)]
	if !ok || r.pw != p {
		return nil, errors.New("invalid credentials")
	}
	return &Identity{Username: strings.ToLower(u), Email: r.email, DisplayName: r.name, Active: true}, nil
}

func (f *fakeAuth) Lookup(_ context.Context, u string) (*Identity, error) {
	r, ok := fixtures[strings.ToLower(u)]
	if !ok {
		return nil, nil
	}
	return &Identity{Username: strings.ToLower(u), Email: r.email, DisplayName: r.name, Active: true}, nil
}

func (f *fakeAuth) List(_ context.Context, limit int) ([]*Identity, error) {
	var out []*Identity
	for u, r := range fixtures {
		out = append(out, &Identity{Username: u, Email: r.email, DisplayName: r.name, Active: true})
	}
	return out, nil
}

const baseDN = "dc=example,dc=test"

func startServer(t *testing.T, cfg Config) (addr string, auth *fakeAuth) {
	t.Helper()
	if cfg.BaseDN == "" {
		cfg.BaseDN = baseDN
	}
	auth = &fakeAuth{}
	s := New(cfg, auth, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return ln.Addr().String(), auth
}

func dial(t *testing.T, addr string) *ldapclient.Conn {
	t.Helper()
	c, err := ldapclient.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestEmptyPasswordBindIsRefused is CVE-2017-14623 and RFC 4513 §5.1.2.
//
// A simple bind with a DN and an empty password is an UNAUTHENTICATED bind. The
// person supplied a name; they proved nothing. Applications ask "did bind
// return an error" and read nil as "authenticated", so a server that answers
// success here hands every one of them a bypass.
//
// There is no configuration under which this passes.
func TestEmptyPasswordBindIsRefused(t *testing.T) {
	addr, auth := startServer(t, Config{})
	c := dial(t, addr)

	// UnauthenticatedBind, not Bind: go-ldap's own client refuses to SEND an
	// empty password (its fix for this same CVE), so an ordinary Bind never
	// reaches the server and the test would prove nothing about it.
	err := c.UnauthenticatedBind("uid=alice," + baseDN)
	if err == nil {
		t.Fatal("a bind with an EMPTY PASSWORD succeeded -- every application that " +
			"checks only the bind error now has an authentication bypass")
	}
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInvalidCredentials) {
		t.Errorf("error = %v, want invalidCredentials(49)", err)
	}
	// And it must not have reached the credential checker at all: the refusal is
	// structural, not a password comparison that happened to fail.
	if auth.calls != 0 {
		t.Errorf("the authenticator was called %d time(s) for an empty password", auth.calls)
	}
}

func TestCorrectBindSucceeds(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatalf("a valid bind was refused: %v", err)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "wrong"); err == nil {
		t.Fatal("a wrong password bound successfully")
	}
}

// TestUnknownUserAndWrongPasswordAreIndistinguishable.
//
// Different answers here make the port a user-enumeration oracle for anybody
// who can reach it -- and LDAP ports are routinely reachable from more of a
// network than their operators think.
func TestUnknownUserAndWrongPasswordAreIndistinguishable(t *testing.T) {
	addr, _ := startServer(t, Config{})

	c1 := dial(t, addr)
	errKnown := c1.Bind("uid=alice,"+baseDN, "wrong-password")
	c2 := dial(t, addr)
	errUnknown := c2.Bind("uid=nobody-at-all,"+baseDN, "wrong-password")

	if errKnown == nil || errUnknown == nil {
		t.Fatal("one of these binds succeeded")
	}
	if errKnown.Error() != errUnknown.Error() {
		t.Errorf("the answers differ, so existing users can be enumerated:\n"+
			"  existing user: %v\n  unknown user:  %v", errKnown, errUnknown)
	}
}

// TestBindDNMustBeUnderTheBase. A DN from another tree must not be resolved
// against ours by taking whatever the first RDN happens to say.
func TestBindDNMustBeUnderTheBase(t *testing.T) {
	addr, _ := startServer(t, Config{})
	for _, dn := range []string{
		"uid=alice,dc=somewhere,dc=else",
		"uid=alice",
		"cn=alice," + baseDN,       // wrong naming attribute
		"ou=x,uid=alice," + baseDN, // username buried, not the leading RDN
		"uid=,%s" + baseDN,         // empty value
	} {
		c := dial(t, addr)
		if err := c.Bind(dn, "correct-horse-battery"); err == nil {
			t.Errorf("bound successfully with DN %q", dn)
		}
	}
}

// TestFailedRebindDropsTheIdentity.
//
// A connection that stays bound as its previous identity after a failed re-bind
// lets a client authenticate once and then keep the session while claiming to
// be somebody else.
func TestFailedRebindDropsTheIdentity(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)

	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	// Now fail a re-bind as somebody else.
	if err := c.Bind("uid=bob,"+baseDN, "wrong"); err == nil {
		t.Fatal("the failed re-bind succeeded")
	}
	// The connection must no longer be authorised for anything.
	_, err := c.Search(ldapclient.NewSearchRequest(baseDN,
		ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
		"(objectClass=inetOrgPerson)", nil, nil))
	if err == nil {
		t.Fatal("a search succeeded after a FAILED re-bind: the connection kept the " +
			"identity from the earlier successful bind")
	}
}

// TestAnonymousSearchIsRefusedByDefault. An anonymous search endpoint is a user
// directory published to anyone who can reach the port.
func TestAnonymousSearchIsRefusedByDefault(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)

	_, err := c.Search(ldapclient.NewSearchRequest(baseDN,
		ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil))
	if err == nil {
		t.Fatal("an unbound connection searched the directory")
	}
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("error = %v, want insufficientAccessRights(50)", err)
	}
}

func TestBoundSearchReturnsEntries(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	res, err := c.Search(ldapclient.NewSearchRequest(baseDN,
		ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
		"(uid=alice)", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}
	e := res.Entries[0]
	if e.DN != "uid=alice,"+baseDN {
		t.Errorf("DN = %q", e.DN)
	}
	if e.GetAttributeValue("mail") != "alice@example.test" {
		t.Errorf("mail = %q", e.GetAttributeValue("mail"))
	}
}

// TestNoPasswordAttributeIsEverReturned.
//
// Some directories return a hash in userPassword; some return a placeholder.
// Both teach applications to compare credentials themselves, which is how a
// password ends up compared with == in somebody else's code.
func TestNoPasswordAttributeIsEverReturned(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	for _, attrs := range [][]string{nil, {"*"}, {"userPassword"}, {"userpassword", "mail"}} {
		res, err := c.Search(ldapclient.NewSearchRequest(baseDN,
			ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
			"(uid=alice)", attrs, nil))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range res.Entries {
			for _, a := range e.Attributes {
				if strings.EqualFold(a.Name, "userPassword") {
					t.Errorf("userPassword was returned for attrs=%v", attrs)
				}
			}
		}
	}
}

// TestAttributeSelectionIsHonoured. Returning attributes nobody asked for is a
// disclosure, not a convenience.
func TestAttributeSelectionIsHonoured(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	res, err := c.Search(ldapclient.NewSearchRequest(baseDN,
		ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
		"(uid=alice)", []string{"uid"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d", len(res.Entries))
	}
	for _, a := range res.Entries[0].Attributes {
		if !strings.EqualFold(a.Name, "uid") {
			t.Errorf("returned %q when only uid was requested", a.Name)
		}
	}
}

// TestWriteOperationsAreRefused. This is a read-only shim; a write that
// silently does nothing is worse than one that fails, because the caller
// believes the directory changed.
func TestWriteOperationsAreRefused(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	add := ldapclient.NewAddRequest("uid=intruder,"+baseDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	if err := c.Add(add); err == nil {
		t.Error("an add succeeded against a read-only directory")
	}

	mod := ldapclient.NewModifyRequest("uid=alice,"+baseDN, nil)
	mod.Replace("mail", []string{"attacker@evil.test"})
	if err := c.Modify(mod); err == nil {
		t.Error("a modify succeeded against a read-only directory")
	}

	if err := c.Del(ldapclient.NewDelRequest("uid=bob,"+baseDN, nil)); err == nil {
		t.Error("a delete succeeded against a read-only directory")
	}
}

// TestCompareIsRefused. Compare answers "does this attribute equal this value",
// which against a password attribute is a guessing oracle with no failed-login
// counter anywhere near it.
func TestCompareIsRefused(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Compare("uid=alice,"+baseDN, "userPassword", "correct-horse-battery"); err == nil {
		t.Error("compare succeeded; it is a credential-guessing oracle")
	}
}

// TestRootDSEIsReadableUnauthenticated -- clients probe it before binding, and
// it discloses nothing.
func TestRootDSEIsReadableUnauthenticated(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)

	res, err := c.Search(ldapclient.NewSearchRequest("",
		ldapclient.ScopeBaseObject, ldapclient.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil))
	if err != nil {
		t.Fatalf("the root DSE probe failed: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d", len(res.Entries))
	}
	if got := res.Entries[0].GetAttributeValue("namingContexts"); got != baseDN {
		t.Errorf("namingContexts = %q", got)
	}
	// StartTLS must not be advertised: a client that sees it will try it, be
	// refused, and may fall back to plaintext.
	for _, a := range res.Entries[0].Attributes {
		if strings.EqualFold(a.Name, "supportedExtension") {
			t.Error("an extension is advertised in the root DSE; StartTLS is refused")
		}
	}
}

// TestUnsupportedFilterMatchesNothing. Failing OPEN on a filter we do not
// understand answers it with the entire directory.
func TestUnsupportedFilterMatchesNothing(t *testing.T) {
	e := &entry{DN: "uid=alice", Attrs: map[string][]string{"uid": {"alice"}}}
	f := &filter{Kind: filterUnsupported}
	if f.Matches(e) {
		t.Error("an unsupported filter matched; a search we cannot parse would " +
			"return everything")
	}
}

func TestFilterEvaluation(t *testing.T) {
	e := &entry{DN: "uid=alice", Attrs: map[string][]string{
		"uid": {"alice"}, "mail": {"alice@example.test"},
		"objectClass": {"top", "inetOrgPerson"},
	}}
	cases := []struct {
		name string
		f    *filter
		want bool
	}{
		{"equality", &filter{Kind: filterEquality, Attr: "uid", Value: "alice"}, true},
		{"equality, wrong value", &filter{Kind: filterEquality, Attr: "uid", Value: "bob"}, false},
		{"attribute names are case-insensitive",
			&filter{Kind: filterEquality, Attr: "UID", Value: "alice"}, true},
		{"multi-valued attribute",
			&filter{Kind: filterEquality, Attr: "objectClass", Value: "inetOrgPerson"}, true},
		{"presence", &filter{Kind: filterPresent, Attr: "mail"}, true},
		{"presence of a missing attribute", &filter{Kind: filterPresent, Attr: "telephoneNumber"}, false},
		{"and", &filter{Kind: filterAnd, Children: []*filter{
			{Kind: filterEquality, Attr: "uid", Value: "alice"},
			{Kind: filterPresent, Attr: "mail"},
		}}, true},
		{"and, one false", &filter{Kind: filterAnd, Children: []*filter{
			{Kind: filterEquality, Attr: "uid", Value: "alice"},
			{Kind: filterPresent, Attr: "nope"},
		}}, false},
		{"or", &filter{Kind: filterOr, Children: []*filter{
			{Kind: filterEquality, Attr: "uid", Value: "bob"},
			{Kind: filterEquality, Attr: "uid", Value: "alice"},
		}}, true},
		{"not", &filter{Kind: filterNot, Children: []*filter{
			{Kind: filterEquality, Attr: "uid", Value: "bob"},
		}}, true},
		{"and containing an unsupported child fails closed",
			&filter{Kind: filterAnd, Children: []*filter{
				{Kind: filterEquality, Attr: "uid", Value: "alice"},
				{Kind: filterUnsupported},
			}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.Matches(e); got != c.want {
				t.Errorf("Matches = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAttrRequested(t *testing.T) {
	cases := []struct {
		name      string
		requested []string
		attr      string
		want      bool
	}{
		{"empty means all", nil, "mail", true},
		{"star means all", []string{"*"}, "mail", true},
		{"1.1 means none", []string{"1.1"}, "mail", false},
		{"explicit", []string{"mail"}, "mail", true},
		{"explicit, different attribute", []string{"uid"}, "mail", false},
		{"case-insensitive", []string{"MAIL"}, "mail", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := attrRequested(c.attr, c.requested); got != c.want {
				t.Errorf("attrRequested(%q, %v) = %v, want %v", c.attr, c.requested, got, c.want)
			}
		})
	}
}

func TestAnonymousSearchCanBeEnabledDeliberately(t *testing.T) {
	addr, _ := startServer(t, Config{AllowAnonymousSearch: true})
	c := dial(t, addr)
	res, err := c.Search(ldapclient.NewSearchRequest(baseDN,
		ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
		"(objectClass=inetOrgPerson)", nil, nil))
	if err != nil {
		t.Fatalf("anonymous search was refused despite being enabled: %v", err)
	}
	if len(res.Entries) == 0 {
		t.Error("no entries returned")
	}
}
