package ldapd

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// groupDir is a pagedDir with groups, which pages them the same way.
type groupDir struct {
	pagedDir
	groups []*Group
}

func (d *groupDir) Groups(_ context.Context, q Query) ([]*Group, error) {
	from := 0
	if q.After != "" {
		after, err := strconv.Atoi(q.After)
		if err != nil {
			return nil, ErrBadPosition
		}
		from = after + 1
	}
	var page []*Group
	for i := from; i < len(d.groups) && len(page) < q.Limit; i++ {
		g := *d.groups[i]
		g.Position = strconv.Itoa(i)
		page = append(page, &g)
	}
	return page, nil
}

func newGroupDir(people int, groups ...string) *groupDir {
	d := &groupDir{pagedDir: pagedDir{n: people}}
	for _, name := range groups {
		d.groups = append(d.groups, &Group{Name: name, Members: []string{"p0", "p1"}})
	}
	return d
}

func search(base string, scope int, filter string) *ldapclient.SearchRequest {
	return ldapclient.NewSearchRequest(base, scope, ldapclient.NeverDerefAliases, 0, 0, false, filter, nil, nil)
}

// A directory client lists groups and their members (7.02): `memberOf` on a
// person answers only the reverse. Each place a client looks for them.
func TestGroupsAreEntries(t *testing.T) {
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, newGroupDir(3, "eng", "ops")))
	groups := "ou=groups," + baseDN
	names := func(res *ldapclient.SearchResult) string {
		var got []string
		for _, e := range res.Entries {
			got = append(got, e.DN)
		}
		sort.Strings(got)
		return strings.Join(got, " ")
	}
	engDN, opsDN := "cn=eng,"+groups, "cn=ops,"+groups
	for name, tc := range map[string]struct {
		req  *ldapclient.SearchRequest
		want string
	}{
		"one level of the subtree": {search(groups, ldapclient.ScopeSingleLevel, "(objectClass=groupOfNames)"), engDN + " " + opsDN},
		"the subtree":              {search(groups, ldapclient.ScopeWholeSubtree, "(objectClass=*)"), engDN + " " + opsDN},
		"from the base":            {search(baseDN, ldapclient.ScopeWholeSubtree, "(objectClass=groupOfNames)"), engDN + " " + opsDN},
		"by name":                  {search(groups, ldapclient.ScopeWholeSubtree, "(cn=eng)"), engDN},
		"by a member":              {search(groups, ldapclient.ScopeWholeSubtree, "(member=uid=p1,"+baseDN+")"), engDN + " " + opsDN},
		"by nobody who is one":     {search(groups, ldapclient.ScopeWholeSubtree, "(member=uid=p2,"+baseDN+")"), ""},
		"one, by its DN":           {search(engDN, ldapclient.ScopeBaseObject, "(objectClass=*)"), engDN},
		"under one, nothing":       {search(engDN, ldapclient.ScopeSingleLevel, "(objectClass=*)"), ""},
		"one that is not there":    {search("cn=nope,"+groups, ldapclient.ScopeBaseObject, "(objectClass=*)"), ""},
		"the container":            {search(groups, ldapclient.ScopeBaseObject, "(objectClass=organizationalUnit)"), groups},
		"not as people":            {search(groups, ldapclient.ScopeWholeSubtree, "(objectClass=person)"), ""},
	} {
		res, err := c.Search(tc.req)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := names(res); got != tc.want {
			t.Errorf("%s found %q, want %q", name, got, tc.want)
		}
	}

	res, err := c.Search(search(engDN, ldapclient.ScopeBaseObject, "(objectClass=*)"))
	if err != nil {
		t.Fatal(err)
	}
	e := res.Entries[0]
	want := []string{"uid=p0," + baseDN, "uid=p1," + baseDN}
	if got := e.GetAttributeValues("member"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("member is %q, want the people's DNs %q", got, want)
	}
	if e.GetAttributeValue("cn") != "eng" {
		t.Errorf("cn is %q", e.GetAttributeValue("cn"))
	}
}

// memberOf and member are the same fact seen from two ends, so a client may
// follow one to the other.
func TestAMemberOfValueIsAGroupsDN(t *testing.T) {
	dir := newGroupDir(1, "everyone")
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))
	res, err := c.Search(search(baseDN, ldapclient.ScopeWholeSubtree, "(uid=p0)"))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("%v, %+v", err, res)
	}
	dn := res.Entries[0].GetAttributeValue("memberOf")
	group, err := c.Search(search(dn, ldapclient.ScopeBaseObject, "(objectClass=groupOfNames)"))
	if err != nil || len(group.Entries) != 1 {
		t.Errorf("%s, a person's memberOf, found %v, %+v", dn, err, group)
	}
}

// A subtree search of the base reaches people and then groups, and a page may
// end anywhere: past the last person, exactly on them, or among the groups.
// Everyone and every group is met once, at any page size.
func TestPagingCrossesFromPeopleToGroups(t *testing.T) {
	dir := newGroupDir(7, "a", "b", "c", "d")
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))
	for size := uint32(1); size <= 13; size++ {
		res, err := c.SearchWithPaging(search(baseDN, ldapclient.ScopeWholeSubtree, "(objectClass=*)"), size)
		if err != nil {
			t.Errorf("a page of %d: %v", size, err)
			continue
		}
		seen := map[string]int{}
		for _, e := range res.Entries {
			seen[e.DN]++
		}
		if len(res.Entries) != 11 || len(seen) != 11 {
			t.Errorf("a page of %d met %d entries, %d different, of 11", size, len(res.Entries), len(seen))
		}
	}
	// And without paging, a limit ending exactly at the last person still says
	// there is more.
	limited := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true, MaxResults: 7}, dir))
	if _, err := limited.Search(search(baseDN, ldapclient.ScopeWholeSubtree, "(objectClass=*)")); !ldapclient.IsErrorWithCode(err,
		ldapclient.LDAPResultAdminLimitExceeded) {
		t.Errorf("a limit of 7 with 4 groups past it answered %v", err)
	}
}

// Groups are the directory's, so they are for those who may read it. A person
// who may read only themselves has their groups on their own entry.
func TestAPersonWhoMayNotReadTheDirectorySeesNoGroups(t *testing.T) {
	dir := newGroupDir(3, "eng")
	dir.fakeAuth.groups = []string{"plain"}
	c := dial(t, startServerWith(t, Config{SearchGroup: "directory-readers"}, dir))
	if err := c.Bind("uid=alice,"+baseDN, fixtures["alice"].pw); err != nil {
		t.Fatal(err)
	}
	for _, req := range []*ldapclient.SearchRequest{
		search("ou=groups,"+baseDN, ldapclient.ScopeWholeSubtree, "(objectClass=*)"),
		search("cn=eng,ou=groups,"+baseDN, ldapclient.ScopeBaseObject, "(objectClass=*)"),
		search(baseDN, ldapclient.ScopeWholeSubtree, "(objectClass=groupOfNames)"),
	} {
		res, err := c.Search(req)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Entries) != 0 {
			t.Errorf("%s %s found %d entries", req.BaseDN, req.Filter, len(res.Entries))
		}
	}
}

func TestAGroupsFilterIsReducedToWhatTheDatabaseCanAnswer(t *testing.T) {
	s := New(Config{BaseDN: baseDN}, &fakeAuth{}, nil)
	for text, want := range map[string]string{
		"(cn=eng)":                      "&{Op:name Value:eng Of:[]}",
		"(objectClass=person)":          "&{Op:none Value: Of:[]}",
		"(objectClass=groupOfNames)":    "<nil>",
		"(member=uid=a," + baseDN + ")": "&{Op:member Value:a Of:[]}",
		"(member=cn=a,dc=other)":        "<nil>",
		// What no group holds cannot be TRUE of one.
		"(uid=x)":         "&{Op:none Value: Of:[]}",
		"(description=x)": "&{Op:none Value: Of:[]}",
		"(mail=*)":        "&{Op:none Value: Of:[]}",
		"(!(uid=x))":      "<nil>",
		"(uid:dn:=x)":     "<nil>",
		"(cn=e*)":         "<nil>",
	} {
		if got := fmt.Sprintf("%+v", s.narrowGroups(filterOf(t, text))); got != want {
			t.Errorf("%s reduced to %s, want %s", text, got, want)
		}
	}
}
