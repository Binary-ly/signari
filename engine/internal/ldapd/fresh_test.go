package ldapd

import (
	"fmt"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// What a connection may do is decided from the directory as it stands, not as
// it stood at bind (ADR-007). A client holds a connection open as long as it
// likes, and the search and write groups used to be read from the identity
// captured at bind, so someone removed from a group, or deactivated, kept
// listing or rewriting the directory until they chose to reconnect.

func (d *writableDir) change(uid string, groups []string, active bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[uid].Groups = groups
	d.users[uid].Active = active
}

func TestRemovalFromTheSearchGroupTakesEffectOnAnOpenConnection(t *testing.T) {
	d := newWritableDir("directory-readers")
	addr := startServerWith(t, Config{SearchGroup: "directory-readers"}, d)
	c := bound(t, addr, "admin")
	count := func() int {
		t.Helper()
		res, err := c.Search(ldapclient.NewSearchRequest(baseDN, ldapclient.ScopeWholeSubtree,
			ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"uid"}, nil))
		if err != nil {
			t.Fatal(err)
		}
		return len(res.Entries)
	}
	if got := count(); got != 2 {
		t.Fatalf("a member of the search group saw %d entries, want the directory's 2", got)
	}

	d.change("admin", nil, true)
	if got := count(); got != 1 {
		t.Errorf("after removal from the search group the same connection saw %d entries, "+
			"want only its own", got)
	}

	d.change("admin", []string{"directory-readers"}, false)
	if got := count(); got != 0 {
		t.Errorf("after deactivation the same connection saw %d entries, want none", got)
	}
}

// A write refused to a bound account outside the write group is handed to
// the writer to record, naming the account and the operation (3.33). It was a
// log line naming the account, and since 3.07 not even that.
func TestARefusedWriteIsHandedOnToBeRecorded(t *testing.T) {
	d := newWritableDir("directory-writers")
	addr := startWritable(t, "directory-writers", d, true)
	c := bound(t, addr, "alice")
	mod := ldapclient.NewModifyRequest("uid=admin,"+baseDN, nil)
	mod.Replace("mail", []string{"taken@example.test"})
	for _, try := range []func() error{
		func() error { return c.Add(goodAdd("mallory")) },
		func() error { return c.Modify(mod) },
		func() error { return c.Del(ldapclient.NewDelRequest("uid=admin,"+baseDN, nil)) },
		func() error {
			return c.ModifyDN(ldapclient.NewModifyDNRequest("uid=admin,"+baseDN, "uid=ada", true, ""))
		},
	} {
		if err := try(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
			t.Fatalf("a write by an account outside the write group gave %v", err)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	want := [][2]string{{"alice", "add"}, {"alice", "modify"}, {"alice", "delete"}, {"alice", "modify_dn"}}
	if fmt.Sprint(d.refused) != fmt.Sprint(want) {
		t.Errorf("the writer was handed %v, want %v", d.refused, want)
	}
}

func TestRemovalFromTheWriteGroupTakesEffectOnAnOpenConnection(t *testing.T) {
	d := newWritableDir("directory-writers")
	addr := startWritable(t, "directory-writers", d, true)
	c := bound(t, addr, "admin")
	if err := c.Add(goodAdd("first")); err != nil {
		t.Fatalf("a member of the write group could not add: %v", err)
	}

	d.change("admin", nil, true)
	err := c.Add(goodAdd("second"))
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("after removal from the write group the same connection's add gave %v, "+
			"want insufficientAccessRights", err)
	}

	d.change("admin", []string{"directory-writers"}, false)
	err = c.Add(goodAdd("third"))
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("after deactivation the same connection's add gave %v, "+
			"want insufficientAccessRights", err)
	}
}
