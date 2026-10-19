package ldapd

import (
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// A search returns the people its base and scope reach, which are the base
// DN's children and nobody else. The base was checked only for lying under the
// configured one, so a one-level or subtree search based at `ou=groups,…` or
// at a person returned every person (2.43), and a base written with a space
// after a comma was answered noSuchObject.
func TestASearchReachesOnlyWhatItsBaseAndScopeInclude(t *testing.T) {
	addr := startServerWith(t, Config{SearchGroup: "directory-readers"},
		&fakeAuth{groups: []string{"directory-readers"}})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	count := func(base string, scope int) int {
		t.Helper()
		res, err := c.Search(ldapclient.NewSearchRequest(base, scope,
			ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"uid"}, nil))
		if err != nil {
			t.Fatalf("search %s scope %d: %v", base, scope, err)
		}
		return len(res.Entries)
	}
	for _, c := range []struct {
		base  string
		scope int
		want  int
	}{
		{baseDN, ldapclient.ScopeWholeSubtree, len(fixtures)},
		{baseDN, ldapclient.ScopeSingleLevel, len(fixtures)},
		{"DC=Example, DC=Test", ldapclient.ScopeWholeSubtree, len(fixtures)},
		{"ou=groups," + baseDN, ldapclient.ScopeWholeSubtree, 0},
		{"ou=groups," + baseDN, ldapclient.ScopeSingleLevel, 0},
		{"uid=alice,ou=groups," + baseDN, ldapclient.ScopeBaseObject, 0},
		{"uid=alice," + baseDN, ldapclient.ScopeBaseObject, 1},
		{"uid=alice, " + baseDN, ldapclient.ScopeBaseObject, 1},
		{"uid=alice," + baseDN, ldapclient.ScopeWholeSubtree, 1},
		{"uid=alice," + baseDN, ldapclient.ScopeSingleLevel, 0},
	} {
		if got := count(c.base, c.scope); got != c.want {
			t.Errorf("base %q scope %d returned %d entries, want %d", c.base, c.scope, got, c.want)
		}
	}
}

// An ordinary user's own entry is held to the same rule.
func TestAnOrdinaryUsersOwnEntryRespectsTheScope(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Search(ldapclient.NewSearchRequest("ou=groups,"+baseDN, ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"uid"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 0 {
		t.Errorf("a search under ou=groups returned the user's own entry, which is not there")
	}
}

// RFC 4511 §4.1.11 (specs/rfc4511.txt:766-771): a critical control the server
// does not apply means the operation is not performed and the answer is
// unavailableCriticalExtension. A non-critical one is ignored.
func TestACriticalControlIsRefusedAndANonCriticalOneIgnored(t *testing.T) {
	addr, _ := startServer(t, Config{})
	c := dial(t, addr)
	if err := c.Bind("uid=alice,"+baseDN, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	// Server-side sorting's control type (RFC 2891), which this server does
	// not apply.
	sort := func(critical bool) []ldapclient.Control {
		return []ldapclient.Control{
			ldapclient.NewControlString(ldapclient.ControlTypeServerSideSorting, critical, ""),
		}
	}
	search := func(ctls []ldapclient.Control) (*ldapclient.SearchResult, error) {
		return c.Search(ldapclient.NewSearchRequest(baseDN, ldapclient.ScopeWholeSubtree,
			ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"uid"}, ctls))
	}

	if _, err := search(sort(true)); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailableCriticalExtension) {
		t.Errorf("a critical sort control answered %v, want unavailableCriticalExtension(12)", err)
	}
	if res, err := search(sort(false)); err != nil || len(res.Entries) != 1 {
		t.Errorf("a non-critical sort control answered %v with %d entries; it should be ignored", err, len(res.Entries))
	}
	// And the connection is still usable after the refusal.
	if res, err := search(nil); err != nil || len(res.Entries) != 1 {
		t.Errorf("a plain search after the refusal answered %v", err)
	}
}
