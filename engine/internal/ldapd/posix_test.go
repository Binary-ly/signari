package ldapd

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func posixServer(on bool) *Server {
	return New(Config{BaseDN: "dc=example,dc=test", UserAttr: "uid", POSIX: on, HomeTemplate: "/home/{username}",
		LoginShell: "/bin/bash"}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func present(attr string) *filter { return &filter{Kind: filterPresent, Attr: attr} }

func equal(attr, value string) *filter {
	return &filter{Kind: filterEquality, Attr: attr, Value: value}
}

func all(children ...*filter) *filter { return &filter{Kind: filterAnd, Children: children} }

func not(child *filter) *filter { return &filter{Kind: filterNot, Children: []*filter{child}} }

func TestAPersonIsAnAccountOnlyWhenAsked(t *testing.T) {
	id := &Identity{Username: "ada", DisplayName: "Ada L", UIDNumber: 2000000007}
	if a := posixServer(false).entryFor(id).Attrs; a["uidNumber"] != nil || contains(a["objectClass"], posixAccountClass) {
		t.Errorf("published unasked: %v", a)
	}
	a := posixServer(true).entryFor(id).Attrs
	for name, want := range map[string]string{"uidNumber": "2000000007", "gidNumber": "2000000007",
		"homeDirectory": "/home/ada", "loginShell": "/bin/bash", "gecos": "Ada L", "uid": "ada"} {
		if len(a[name]) != 1 || a[name][0] != want {
			t.Errorf("%s reads %v, want %s", name, a[name], want)
		}
	}
	if !contains(a["objectClass"], posixAccountClass) {
		t.Errorf("classes read %v", a["objectClass"])
	}
}

// A person with no number comes from a core that predates them, and a host reads an
// absent number as nothing but a zero as root.
func TestAPersonWithNoNumberIsNoAccount(t *testing.T) {
	a := posixServer(true).entryFor(&Identity{Username: "ada"}).Attrs
	if a["uidNumber"] != nil || contains(a["objectClass"], posixAccountClass) {
		t.Errorf("an account with no number: %v", a)
	}
}

func TestAHomeIsOnePathSegment(t *testing.T) {
	s := posixServer(true)
	for name, want := range map[string]string{"ada": "/home/ada", "..": "/home/_", ".": "/home/_",
		"../../etc": "/home/.._.._etc", "a/b": "/home/a_b", "ada@example.test": "/home/ada@example.test"} {
		if got := s.homeDirectory(name); got != want {
			t.Errorf("%q gets %q, want %q", name, got, want)
		}
	}
}

// As text 9 sorts after 10, so a range over a number finds the wrong people.
func TestARangeOverANumberIsNumeric(t *testing.T) {
	e := &entry{Attrs: map[string][]string{"uidNumber": {"9"}, "cn": {"9"}}}
	if !(&filter{Kind: filterLessOrEqual, Attr: "uidNumber", Value: "10"}).Matches(e) {
		t.Error("9 is not at most 10")
	}
	if (&filter{Kind: filterGreaterOrEqual, Attr: "uidnumber", Value: "10"}).Matches(e) {
		t.Error("9 is at least 10")
	}
	if (&filter{Kind: filterLessOrEqual, Attr: "cn", Value: "10"}).Matches(e) {
		t.Error("a name was compared as a number")
	}
}

func TestAGroupCarriesItsNumberAndMembers(t *testing.T) {
	g := &Group{Name: "staff", Members: []string{"ada", "bea"}, GIDNumber: 2000000011}
	a := posixServer(true).groupEntry(g).Attrs
	if strings.Join(a["memberUid"], ",") != "ada,bea" || a["gidNumber"][0] != "2000000011" ||
		!contains(a["objectClass"], posixGroupClass) || len(a["member"]) != 2 {
		t.Errorf("the group reads %v", a)
	}
	if a := posixServer(false).groupEntry(g).Attrs; a["gidNumber"] != nil || a["memberUid"] != nil ||
		contains(a["objectClass"], posixGroupClass) {
		t.Errorf("published unasked: %v", a)
	}
}

// The filters a host sends for a name, a number, a group and a person's groups. Each
// has to reach the database as a question about one thing, and each has to match.
func TestAHostsFiltersFindTheirEntry(t *testing.T) {
	s := posixServer(true)
	ada := s.entryFor(&Identity{Username: "ada", UIDNumber: 2000000007})
	staff := s.groupEntry(&Group{Name: "staff", Members: []string{"ada"}, GIDNumber: 2000000011})
	accounts := all(equal("objectClass", posixAccountClass), present("uid"), present("uidNumber"))
	groups := all(equal("objectClass", posixGroupClass), present("cn"), present("gidNumber"), not(equal("gidNumber", "0")))
	for name, tc := range map[string]struct {
		f       *filter
		e       *entry
		person  *Condition
		group   *Condition
		nothing bool
	}{
		"by name": {f: all(equal("uid", "ada"), accounts), e: ada,
			person: &Condition{Op: CondLogin, Value: "ada"}, group: &Condition{Op: CondNone}},
		"by number": {f: all(equal("uidNumber", "2000000007"), accounts), e: ada,
			person: &Condition{Op: CondNumber, Value: "2000000007"}, group: &Condition{Op: CondNone}},
		"a group by name": {f: all(equal("cn", "staff"), groups), e: staff,
			person: &Condition{Op: CondNone}, group: &Condition{Op: CondName, Value: "staff"}},
		"a group by number": {f: all(equal("gidNumber", "2000000011"), groups), e: staff,
			person: &Condition{Op: CondNone}, group: &Condition{Op: CondNumber, Value: "2000000011"}},
		"a person's groups": {f: all(equal("memberUid", "ada"), groups), e: staff,
			person: &Condition{Op: CondNone}, group: &Condition{Op: CondMember, Value: "ada"}},
	} {
		if !tc.f.Matches(tc.e) {
			t.Errorf("%s does not match its entry %v", name, tc.e.Attrs)
		}
		if got := s.narrow(tc.f); !sameCondition(got, tc.person) {
			t.Errorf("%s among people narrows to %+v, want %+v", name, got, tc.person)
		}
		if got := s.narrowGroups(tc.f); !sameCondition(got, tc.group) {
			t.Errorf("%s among groups narrows to %+v, want %+v", name, got, tc.group)
		}
	}
}

// The same filter on a directory that was not asked for accounts finds nobody.
func TestNoAccountsAreFoundUnasked(t *testing.T) {
	s := posixServer(false)
	f := equal("objectClass", posixAccountClass)
	if got := s.narrow(f); got == nil || got.Op != CondNone {
		t.Errorf("narrows to %+v", got)
	}
}

func sameCondition(a, b *Condition) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Op == b.Op && a.Value == b.Value
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
