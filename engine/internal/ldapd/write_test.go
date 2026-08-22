package ldapd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// The write half, exercised through go-ldap -- a separate implementation by
// different authors, for the reason the read tests give: testing our server
// with our own client only proves we are self-consistent, and self-consistency
// is what a protocol bug looks like from the inside.
//
// Two properties dominate this file:
//
//   - Writes are OFF unless two separate things are configured, and the
//     off-state is byte-identical to what a read-only deployment answered
//     before writes existed.
//   - Every refusal carries the result code RFC 4511 assigns it, because a
//     directory client acts on the code and not on the message.

// writableDir is an in-memory directory that records what it was asked to do.
type writableDir struct {
	mu      sync.Mutex
	users   map[string]*Identity
	created []*NewEntry
	updates map[string]*Update
	removed []string
	renames [][2]string
	// fail, when set, is returned by every method -- for the error-mapping tests.
	fail error
}

func newWritableDir(members ...string) *writableDir {
	d := &writableDir{
		users:   map[string]*Identity{},
		updates: map[string]*Update{},
	}
	// One writer and one ordinary user, so "permitted" and "not permitted" are
	// both reachable without reconfiguring the server.
	d.users["admin"] = &Identity{
		Username: "admin", Email: "admin@example.test", DisplayName: "Ada Admin",
		Surname: "Admin", Active: true, Groups: members,
	}
	d.users["alice"] = &Identity{
		Username: "alice", Email: "alice@example.test", DisplayName: "Alice Example",
		Surname: "Example", GivenName: "Alice", Active: true,
	}
	return d
}

func (d *writableDir) Authenticate(_ context.Context, u, p string) (*Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.users[strings.ToLower(u)]
	if !ok || p != "correct-horse-battery" {
		return nil, ldapclient.NewError(49, io.EOF)
	}
	copied := *id
	return &copied, nil
}

func (d *writableDir) Lookup(_ context.Context, u string) (*Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.users[strings.ToLower(u)]
	if !ok {
		return nil, nil
	}
	copied := *id
	return &copied, nil
}

func (d *writableDir) List(_ context.Context, limit int) ([]*Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*Identity
	for _, id := range d.users {
		copied := *id
		out = append(out, &copied)
	}
	return out, nil
}

func (d *writableDir) Create(_ context.Context, actor string, e *NewEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return d.fail
	}
	if _, taken := d.users[strings.ToLower(e.Username)]; taken {
		return ErrEntryExists
	}
	d.created = append(d.created, e)
	d.users[strings.ToLower(e.Username)] = &Identity{
		Username: e.Username, Email: e.Email, DisplayName: e.CommonName,
		Surname: e.Surname, GivenName: e.GivenName, Active: true,
	}
	return nil
}

func (d *writableDir) Update(_ context.Context, actor, username string, u *Update) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return d.fail
	}
	if _, ok := d.users[strings.ToLower(username)]; !ok {
		return ErrNoSuchEntry
	}
	d.updates[strings.ToLower(username)] = u
	return nil
}

func (d *writableDir) Remove(_ context.Context, actor, username string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return d.fail
	}
	if _, ok := d.users[strings.ToLower(username)]; !ok {
		return ErrNoSuchEntry
	}
	delete(d.users, strings.ToLower(username))
	d.removed = append(d.removed, username)
	return nil
}

func (d *writableDir) Rename(_ context.Context, actor, from, to string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return d.fail
	}
	id, ok := d.users[strings.ToLower(from)]
	if !ok {
		return ErrNoSuchEntry
	}
	if _, taken := d.users[strings.ToLower(to)]; taken {
		return ErrEntryExists
	}
	delete(d.users, strings.ToLower(from))
	id.Username = to
	d.users[strings.ToLower(to)] = id
	d.renames = append(d.renames, [2]string{from, to})
	return nil
}

// startWritable brings up a server with the write half attached.
//
// writeGroup empty means the group is not configured, which is one of the two
// ways writes stay off.
func startWritable(t *testing.T, writeGroup string, d *writableDir, attachWriter bool) string {
	t.Helper()
	s := New(Config{BaseDN: baseDN, WriteGroup: writeGroup},
		d, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if attachWriter {
		s = s.WithWriter(d)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return ln.Addr().String()
}

// bound dials and binds as a user.
func bound(t *testing.T, addr, uid string) *ldapclient.Conn {
	t.Helper()
	c := dial(t, addr)
	if err := c.Bind("uid="+uid+","+baseDN, "correct-horse-battery"); err != nil {
		t.Fatalf("binding as %s: %v", uid, err)
	}
	return c
}

func addFor(uid string, attrs map[string][]string) *ldapclient.AddRequest {
	req := ldapclient.NewAddRequest("uid="+uid+","+baseDN, nil)
	for k, v := range attrs {
		req.Attribute(k, v)
	}
	return req
}

func goodAdd(uid string) *ldapclient.AddRequest {
	return addFor(uid, map[string][]string{
		"objectClass": {"inetOrgPerson"},
		"cn":          {"New Person"},
		"sn":          {"Person"},
		"mail":        {uid + "@example.test"},
	})
}

// codeOf pulls the LDAP result code out of a go-ldap error.
func codeOf(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error and got none")
	}
	var le *ldapclient.Error
	if !ldapclient.IsErrorAnyOf(err, ldapclient.LDAPResultSuccess) {
		// IsErrorAnyOf does not expose the code, so unwrap directly.
		if e, ok := err.(*ldapclient.Error); ok {
			le = e
		}
	}
	if le == nil {
		t.Fatalf("error is not an *ldap.Error: %T %v", err, err)
	}
	return le.ResultCode
}

// Writes are off unless BOTH a writer and a group are configured, and the
// off-state is exactly what a read-only deployment answered before.
func TestWritesAreRefusedUnlessConfigured(t *testing.T) {
	cases := []struct {
		name        string
		writeGroup  string
		withWriter  bool
		wantCode    uint16
		wantMessage string
	}{
		{
			name: "no writer at all", writeGroup: "directory-admins", withWriter: false,
			wantCode:    ldapclient.LDAPResultUnwillingToPerform,
			wantMessage: "read-only",
		},
		{
			// The half-configured case, and the one worth having a test for: a
			// Writer is attached and nobody is named. Reading the empty group as
			// "everybody" here would be a live grant produced by a configuration
			// somebody had not finished.
			name: "writer but no group", writeGroup: "", withWriter: true,
			wantCode:    ldapclient.LDAPResultUnwillingToPerform,
			wantMessage: "read-only",
		},
		{
			name:       "configured, bound identity outside the group",
			writeGroup: "directory-admins", withWriter: true,
			wantCode:    ldapclient.LDAPResultInsufficientAccessRights,
			wantMessage: "not permitted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newWritableDir() // admin is in NO groups
			addr := startWritable(t, tc.writeGroup, d, tc.withWriter)
			c := bound(t, addr, "admin")

			err := c.Add(goodAdd("newbie"))
			if got := codeOf(t, err); got != tc.wantCode {
				t.Fatalf("result code %d, want %d (%v)", got, tc.wantCode, err)
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Errorf("message %q does not mention %q", err, tc.wantMessage)
			}
			if len(d.created) != 0 {
				t.Error("the entry was created anyway")
			}
		})
	}
}

// An unbound connection cannot write, whatever the configuration.
func TestAnAnonymousConnectionCannotWrite(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := dial(t, addr)

	if err := c.Add(goodAdd("newbie")); codeOf(t, err) != ldapclient.LDAPResultInsufficientAccessRights {
		t.Fatalf("an anonymous add answered %v", err)
	}
	if len(d.created) != 0 {
		t.Error("an anonymous connection created an entry")
	}
}

// The whole journey: add, read back, modify, rename, delete.
func TestTheDirectoryCanBeWrittenAndReadBack(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")

	if err := c.Add(goodAdd("carol")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(d.created) != 1 || d.created[0].Surname != "Person" {
		t.Fatalf("the store received %+v", d.created)
	}

	// Read it back. The point of storing cn and sn is that they come back; a
	// directory that accepts an attribute and returns something else is the
	// failure this whole exercise is against.
	res, err := c.Search(ldapclient.NewSearchRequest(
		"uid=carol,"+baseDN, ldapclient.ScopeBaseObject, 0, 0, 0, false,
		"(objectClass=*)", []string{"cn", "sn", "mail", "uid"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("%d entries returned", len(res.Entries))
	}
	e := res.Entries[0]
	for attr, want := range map[string]string{
		"cn": "New Person", "sn": "Person", "mail": "carol@example.test", "uid": "carol",
	} {
		if got := e.GetAttributeValue(attr); got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}

	mod := ldapclient.NewModifyRequest("uid=carol,"+baseDN, nil)
	mod.Replace("mail", []string{"carol.new@example.test"})
	if err := c.Modify(mod); err != nil {
		t.Fatalf("modify: %v", err)
	}
	if u := d.updates["carol"]; u == nil || u.Email == nil || *u.Email != "carol.new@example.test" {
		t.Fatalf("the store received %+v", d.updates["carol"])
	}

	if err := c.ModifyDN(ldapclient.NewModifyDNRequest(
		"uid=carol,"+baseDN, "uid=caroline", true, "")); err != nil {
		t.Fatalf("modify dn: %v", err)
	}
	if len(d.renames) != 1 || d.renames[0] != [2]string{"carol", "caroline"} {
		t.Fatalf("renames = %v", d.renames)
	}

	if err := c.Del(ldapclient.NewDelRequest("uid=caroline,"+baseDN, nil)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(d.removed) != 1 || d.removed[0] != "caroline" {
		t.Fatalf("removed = %v", d.removed)
	}
}

// RFC 4511 §4.7 and RFC 4519's MUST attributes.
func TestAddEnforcesTheSchema(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")

	cases := []struct {
		name  string
		attrs map[string][]string
		dn    string
		want  uint16
	}{
		{
			name: "no sn", want: ldapclient.LDAPResultObjectClassViolation,
			attrs: map[string][]string{"objectClass": {"inetOrgPerson"}, "cn": {"X"}},
		},
		{
			name: "no cn", want: ldapclient.LDAPResultObjectClassViolation,
			attrs: map[string][]string{"objectClass": {"inetOrgPerson"}, "sn": {"X"}},
		},
		{
			name: "an object class this directory does not implement",
			want: ldapclient.LDAPResultObjectClassViolation,
			attrs: map[string][]string{
				"objectClass": {"posixAccount"}, "cn": {"X"}, "sn": {"X"}},
		},
		{
			name: "an attribute this directory does not define",
			want: ldapclient.LDAPResultUndefinedAttributeType,
			attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "cn": {"X"}, "sn": {"X"},
				"loginShell": {"/bin/sh"}},
		},
		{
			name: "a single-valued attribute given two values",
			want: ldapclient.LDAPResultConstraintViolation,
			attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "cn": {"X"}, "sn": {"A", "B"}},
		},
		{
			// §4.7 lets a client repeat the RDN attribute. Repeating it with a
			// DIFFERENT value is a request that says two things, and preferring
			// either one would store the entry under a name the client did not ask
			// for.
			name: "a uid attribute contradicting the DN",
			want: ldapclient.LDAPResultNamingViolation,
			attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "cn": {"X"}, "sn": {"X"},
				"uid": {"somebody-else"}},
		},
		{
			name: "memberOf, which this server maintains",
			want: ldapclient.LDAPResultConstraintViolation,
			attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "cn": {"X"}, "sn": {"X"},
				"memberOf": {"cn=admins,ou=groups," + baseDN}},
		},
		{
			name: "a DN outside the naming context", dn: "uid=x,dc=elsewhere,dc=test",
			want: ldapclient.LDAPResultNoSuchObject,
			attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "cn": {"X"}, "sn": {"X"}},
		},
		{
			name: "a DN named by something other than uid", dn: "cn=x," + baseDN,
			want: ldapclient.LDAPResultInvalidDNSyntax,
			attrs: map[string][]string{
				"objectClass": {"inetOrgPerson"}, "cn": {"X"}, "sn": {"X"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dn := tc.dn
			if dn == "" {
				dn = "uid=probe," + baseDN
			}
			req := ldapclient.NewAddRequest(dn, nil)
			for k, v := range tc.attrs {
				req.Attribute(k, v)
			}
			err := c.Add(req)
			if got := codeOf(t, err); got != tc.want {
				t.Fatalf("result code %d, want %d (%v)", got, tc.want, err)
			}
		})
	}

	// §4.7: the entry "MUST NOT exist for the AddRequest to succeed".
	t.Run("an entry that already exists", func(t *testing.T) {
		if err := c.Add(goodAdd("alice")); codeOf(t, err) != ldapclient.LDAPResultEntryAlreadyExists {
			t.Fatalf("adding an existing entry answered %v", err)
		}
	})
}

// RFC 4511 §4.6.
func TestModifyEnforcesTheSchema(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")
	dn := "uid=alice," + baseDN

	t.Run("the RDN attribute cannot be modified", func(t *testing.T) {
		// §4.6: "The Modify operation cannot be used to remove from an entry any
		// of its distinguished values... An attempt to do so will result in the
		// server returning the notAllowedOnRDN result code."
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Replace("uid", []string{"alice2"})
		err := c.Modify(m)
		if got := codeOf(t, err); got != ldapclient.LDAPResultNotAllowedOnRDN {
			t.Fatalf("result code %d, want notAllowedOnRDN(67) (%v)", got, err)
		}
		// And the message names the operation that would work, because that is
		// the whole reason this code exists rather than a generic refusal.
		if !strings.Contains(err.Error(), "modify DN") {
			t.Errorf("the refusal does not point at modify DN: %v", err)
		}
	})

	t.Run("the object class cannot be changed", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Replace("objectClass", []string{"posixAccount"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultObjectClassModsProhibited {
			t.Fatalf("result code %d, want objectClassModsProhibited(69)", got)
		}
	})

	t.Run("memberOf is maintained by the server", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Add("memberOf", []string{"cn=admins,ou=groups," + baseDN})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultConstraintViolation {
			t.Fatalf("result code %d, want constraintViolation(19)", got)
		}
	})

	t.Run("deleting a value that is not there", func(t *testing.T) {
		// §4.6's `delete` operates on the existing value set. Reporting success
		// for removing something that was never present tells the client its
		// change took effect.
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Delete("mail", []string{"someone.else@example.test"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultNoSuchAttribute {
			t.Fatalf("result code %d, want noSuchAttribute(16)", got)
		}
	})

	t.Run("adding a value that is already there", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Add("mail", []string{"alice@example.test"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultAttributeOrValueExists {
			t.Fatalf("result code %d, want attributeOrValueExists(20)", got)
		}
	})

	t.Run("deleting a MUST attribute", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Delete("sn", nil)
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultObjectClassViolation {
			t.Fatalf("result code %d, want objectClassViolation(65)", got)
		}
	})

	// §4.6: "the resulting entry AFTER the entire list of modifications is
	// performed MUST conform". So a request that removes a MUST attribute and
	// puts it back is legal, and a server that checked per-change would reject
	// it -- which is the ordinary way a client replaces a value.
	t.Run("deleting and re-adding a MUST attribute in one request", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Delete("sn", nil)
		m.Add("sn", []string{"Renamed"})
		if err := c.Modify(m); err != nil {
			t.Fatalf("a request whose FINAL state conforms was refused: %v", err)
		}
		if u := d.updates["alice"]; u == nil || u.Surname == nil || *u.Surname != "Renamed" {
			t.Fatalf("the store received %+v", d.updates["alice"])
		}
	})

	t.Run("an unknown attribute", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Replace("loginShell", []string{"/bin/sh"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultUndefinedAttributeType {
			t.Fatalf("result code %d, want undefinedAttributeType(17)", got)
		}
	})

	// The single-value rule, on both operations that can break it. Two tests,
	// because they are two branches: `add` appends to what is already there and
	// `replace` supplies the whole set, so a server can enforce one and not the
	// other -- and silently keeping the first value is how a client comes to
	// believe it stored something it did not.
	t.Run("adding a second value to a single-valued attribute", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Add("mail", []string{"alice.other@example.test"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultConstraintViolation {
			t.Fatalf("result code %d, want constraintViolation(19): mail is "+
				"single-valued and the entry already has one", got)
		}
	})

	t.Run("replacing a single-valued attribute with two values", func(t *testing.T) {
		m := ldapclient.NewModifyRequest(dn, nil)
		m.Replace("sn", []string{"One", "Two"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultConstraintViolation {
			t.Fatalf("result code %d, want constraintViolation(19)", got)
		}
	})

	t.Run("an entry that does not exist", func(t *testing.T) {
		m := ldapclient.NewModifyRequest("uid=ghost,"+baseDN, nil)
		m.Replace("mail", []string{"g@example.test"})
		if got := codeOf(t, c.Modify(m)); got != ldapclient.LDAPResultNoSuchObject {
			t.Fatalf("result code %d, want noSuchObject(32)", got)
		}
	})
}

// RFC 4511 §4.9.
func TestModifyDNRules(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")
	dn := "uid=alice," + baseDN

	t.Run("deleteoldrdn FALSE is refused rather than ignored", func(t *testing.T) {
		// §4.9: with FALSE "the attribute values forming the old RDN will be
		// retained as non-distinguished attribute values". uid is single-valued
		// here, so that cannot be represented -- and a server that accepted FALSE
		// and dropped the old value anyway would have done the one thing the flag
		// exists to prevent.
		err := c.ModifyDN(ldapclient.NewModifyDNRequest(dn, "uid=alice2", false, ""))
		if got := codeOf(t, err); got != ldapclient.LDAPResultConstraintViolation {
			t.Fatalf("result code %d, want constraintViolation(19) (%v)", got, err)
		}
		if len(d.renames) != 0 {
			t.Error("the entry was renamed despite the refusal")
		}
	})

	t.Run("a new RDN using another attribute", func(t *testing.T) {
		err := c.ModifyDN(ldapclient.NewModifyDNRequest(dn, "cn=Alice", true, ""))
		if got := codeOf(t, err); got != ldapclient.LDAPResultNamingViolation {
			t.Fatalf("result code %d, want namingViolation(64)", got)
		}
	})

	t.Run("a newSuperior that does not exist", func(t *testing.T) {
		err := c.ModifyDN(ldapclient.NewModifyDNRequest(dn, "uid=alice2", true,
			"ou=people,"+baseDN))
		if got := codeOf(t, err); got != ldapclient.LDAPResultNoSuchObject {
			t.Fatalf("result code %d, want noSuchObject(32)", got)
		}
	})

	t.Run("renaming onto an existing entry", func(t *testing.T) {
		err := c.ModifyDN(ldapclient.NewModifyDNRequest(dn, "uid=admin", true, ""))
		if got := codeOf(t, err); got != ldapclient.LDAPResultEntryAlreadyExists {
			t.Fatalf("result code %d, want entryAlreadyExists(68)", got)
		}
	})
}

// §4.8: "Only leaf entries (those with no subordinate entries) can be deleted."
func TestDeletingTheNamingContextIsRefused(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")

	err := c.Del(ldapclient.NewDelRequest(baseDN, nil))
	if got := codeOf(t, err); got != ldapclient.LDAPResultNotAllowedOnNonLeaf {
		t.Fatalf("result code %d, want notAllowedOnNonLeaf(66) (%v)", got, err)
	}
	if len(d.removed) != 0 {
		t.Error("something was deleted")
	}
}

// userPassword is write-only, in both directions.
func TestUserPasswordIsWriteOnly(t *testing.T) {
	d := newWritableDir("directory-admins")
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")

	req := goodAdd("dave")
	req.Attribute("userPassword", []string{"a-perfectly-fine-password"})
	if err := c.Add(req); err != nil {
		t.Fatalf("add with a password: %v", err)
	}
	if len(d.created) != 1 || d.created[0].Password != "a-perfectly-fine-password" {
		t.Fatal("the password did not reach the store")
	}

	// And it never comes back, at any value -- not a hash, not a placeholder.
	// Asked for BY NAME, which is the request a naive implementation answers.
	res, err := c.Search(ldapclient.NewSearchRequest(
		"uid=dave,"+baseDN, ldapclient.ScopeBaseObject, 0, 0, 0, false,
		"(objectClass=*)", []string{"userPassword", "*"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("%d entries", len(res.Entries))
	}
	for _, a := range res.Entries[0].Attributes {
		if strings.EqualFold(a.Name, "userPassword") {
			t.Fatalf("userPassword came back from a search: %v", a.Values)
		}
	}
}

// The store's own refusals reach the client as the codes RFC 4511 assigns.
func TestStoreErrorsBecomeTheRightResultCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want uint16
	}{
		{"a constraint the store enforces", ErrConstraint, ldapclient.LDAPResultConstraintViolation},
		{"an entry that exists", ErrEntryExists, ldapclient.LDAPResultEntryAlreadyExists},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newWritableDir("directory-admins")
			d.fail = tc.err
			addr := startWritable(t, "directory-admins", d, true)
			c := bound(t, addr, "admin")
			if got := codeOf(t, c.Add(goodAdd("newbie"))); got != tc.want {
				t.Fatalf("result code %d, want %d", got, tc.want)
			}
		})
	}
}

// A person entry always carries `sn`, including for accounts that predate the
// column -- because every entry here declares `person`, which makes it a MUST.
func TestEveryEntryCarriesTheMustAttributes(t *testing.T) {
	d := newWritableDir("directory-admins")
	// An account with no stored surname, which is every account created any way
	// but through this directory.
	d.users["legacy"] = &Identity{
		Username: "legacy", Email: "legacy@example.test",
		DisplayName: "Grace Hopper", Active: true,
	}
	addr := startWritable(t, "directory-admins", d, true)
	c := bound(t, addr, "admin")

	res, err := c.Search(ldapclient.NewSearchRequest(
		"uid=legacy,"+baseDN, ldapclient.ScopeBaseObject, 0, 0, 0, false,
		"(objectClass=*)", nil, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	e := res.Entries[0]
	if got := e.GetAttributeValue("sn"); got == "" {
		t.Error("an entry declaring `person` came back with no sn, which RFC 4519 " +
			"makes a MUST attribute of that class")
	} else if got != "Hopper" {
		t.Errorf("sn = %q; for a row with no stored surname it is derived from "+
			"the display name, which is a guess and should be the last word", got)
	}
	if got := e.GetAttributeValue("cn"); got != "Grace Hopper" {
		t.Errorf("cn = %q", got)
	}
}
