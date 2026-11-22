package httpapi

import (
	"context"
	"strconv"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"

	"signari.dev/engine/internal/ldapd"
)

func (f *directoryFixture) serveAccounts(t *testing.T) *ldapclient.Conn {
	t.Helper()
	return f.serveWith(t, ldapd.Config{BaseDN: "dc=example,dc=test", UserAttr: "uid", AllowAnonymousSearch: true,
		MaxResults: 100, POSIX: true, HomeTemplate: "/home/{username}", LoginShell: "/bin/sh"})
}

// A host asks by name, by number, for a group and for a person's groups, and each is
// one question of the database however many people there are.
func TestAHostFindsAnAccountThroughARealClient(t *testing.T) {
	f := newDirectoryFixture(t, 120)
	ctx := context.Background()
	var uid, gid int
	var group string
	if err := f.pool.QueryRow(ctx, `SELECT posix_uid FROM core.users WHERE org_id = $1::uuid AND username = 'p7'`,
		f.orgID).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, 'eng', 'Eng')
		RETURNING id::text, posix_gid`, f.orgID).Scan(&group, &gid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT $1::uuid, id, org_id FROM core.users WHERE org_id = $2::uuid AND username = 'p7'`, group, f.orgID); err != nil {
		t.Fatal(err)
	}
	if uid < 2000000000 {
		t.Fatalf("a person was allocated %d, in the range kept for numbers set by hand", uid)
	}
	c := f.serveAccounts(t)
	const usable = "(uid=*)(&(uidNumber=*)(!(uidNumber=0)))"
	const usableGroup = "(cn=*)(&(gidNumber=*)(!(gidNumber=0)))"
	for filter, want := range map[string]string{
		"(&(uid=p7)(objectClass=posixAccount)" + usable + ")":                                 "uid=p7,dc=example,dc=test",
		"(&(uidNumber=" + strconv.Itoa(uid) + ")(objectClass=posixAccount)" + usable + ")":    "uid=p7,dc=example,dc=test",
		"(&(cn=eng)(objectClass=posixGroup)" + usableGroup + ")":                              "cn=eng,ou=groups,dc=example,dc=test",
		"(&(gidNumber=" + strconv.Itoa(gid) + ")(objectClass=posixGroup)" + usableGroup + ")": "cn=eng,ou=groups,dc=example,dc=test",
		"(&(memberUid=p7)(objectClass=posixGroup)" + usableGroup + ")":                        "cn=eng,ou=groups,dc=example,dc=test",
	} {
		before := f.queries.n.Load()
		res, err := c.Search(ldapclient.NewSearchRequest("dc=example,dc=test", ldapclient.ScopeWholeSubtree,
			ldapclient.NeverDerefAliases, 0, 0, false, filter,
			[]string{"uid", "uidNumber", "gidNumber", "homeDirectory", "loginShell", "gecos", "memberUid", "cn"}, nil))
		if err != nil {
			t.Errorf("%s: %v", filter, err)
			continue
		}
		if len(res.Entries) != 1 || res.Entries[0].DN != want {
			t.Errorf("%s found %d entries, want %s", filter, len(res.Entries), want)
			continue
		}
		if spent := f.queries.n.Load() - before; spent != 1 {
			t.Errorf("%s took %d statements", filter, spent)
		}
	}

	res, err := c.Search(ldapclient.NewSearchRequest("dc=example,dc=test", ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(uid=p7)", []string{"*"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	e := res.Entries[0]
	if e.GetAttributeValue("uidNumber") != strconv.Itoa(uid) || e.GetAttributeValue("gidNumber") != strconv.Itoa(uid) ||
		e.GetAttributeValue("homeDirectory") != "/home/p7" || e.GetAttributeValue("loginShell") != "/bin/sh" {
		t.Errorf("the account reads %+v", e.Attributes)
	}

	g, err := c.Search(ldapclient.NewSearchRequest("dc=example,dc=test", ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=posixGroup)", []string{"memberUid", "gidNumber"}, nil))
	if err != nil || len(g.Entries) != 1 {
		t.Fatalf("%v %v", g, err)
	}
	if g.Entries[0].GetAttributeValue("memberUid") != "p7" || g.Entries[0].GetAttributeValue("gidNumber") != strconv.Itoa(gid) {
		t.Errorf("the group reads %+v", g.Entries[0].Attributes)
	}
}

// A range goes through Matches and is numeric: an operator's filter for the numbers
// allocated here must find them.
func TestARangeOfNumbersFindsAccounts(t *testing.T) {
	f := newDirectoryFixture(t, 3)
	c := f.serveAccounts(t)
	res, err := c.Search(ldapclient.NewSearchRequest("dc=example,dc=test", ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(&(objectClass=posixAccount)(uidNumber>=999999))", []string{"uid"}, nil))
	if err != nil || len(res.Entries) != 3 {
		t.Fatalf("%v, %v", res, err)
	}
}

// A number handed out twice gives a new employee an erased one's files, so nothing
// frees one: not a deletion, in this organisation or another.
func TestANumberIsNeverGivenTwice(t *testing.T) {
	f := newDirectoryFixture(t, 2)
	ctx := context.Background()
	numbers := func() map[string]int {
		rows, err := f.pool.Query(ctx, `SELECT username, posix_uid FROM core.users WHERE org_id = $1::uuid`, f.orgID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var name string
			var n int
			if err := rows.Scan(&name, &n); err != nil {
				t.Fatal(err)
			}
			out[name] = n
		}
		return out
	}
	before := numbers()
	if before["p1"] == before["p2"] {
		t.Fatalf("two people have %d", before["p1"])
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM core.users WHERE org_id = $1::uuid AND username = 'p2'`, f.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.users (org_id, user_handle, username, email, display_name)
		VALUES ($1::uuid, sha256(convert_to($1::text || 'again', 'UTF8')), 'p2', 'again@example.test', 'Again')`, f.orgID); err != nil {
		t.Fatal(err)
	}
	after := numbers()
	if after["p2"] <= before["p2"] || after["p1"] != before["p1"] {
		t.Errorf("before %v, after %v", before, after)
	}
}
