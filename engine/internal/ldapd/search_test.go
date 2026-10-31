package ldapd

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// pagedDir is a directory of n people that pages as a database does.
type pagedDir struct {
	fakeAuth
	n int

	mu   sync.Mutex
	asks int
}

func (d *pagedDir) person(i int) *Identity {
	return &Identity{Username: fmt.Sprintf("p%d", i), Email: fmt.Sprintf("p%d@example.test", i),
		DisplayName: fmt.Sprintf("Person %d", i), Active: true, Position: strconv.Itoa(i),
		Groups: []string{"everyone"}}
}

func (d *pagedDir) List(_ context.Context, q Query) ([]*Identity, error) {
	d.mu.Lock()
	d.asks++
	d.mu.Unlock()
	from := 0
	if q.After != "" {
		after, err := strconv.Atoi(q.After)
		if err != nil {
			return nil, ErrBadPosition
		}
		from = after + 1
	}
	var page []*Identity
	for i := from; i < d.n && len(page) < q.Limit; i++ {
		page = append(page, d.person(i))
	}
	return page, nil
}

func (d *pagedDir) Lookup(_ context.Context, u string) (*Identity, error) {
	return nil, nil
}

func anonymousSearch(filter string, sizeLimit int) *ldapclient.SearchRequest {
	return ldapclient.NewSearchRequest(baseDN, ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases,
		sizeLimit, 0, false, filter, []string{"uid"}, nil)
}

// Somebody past the first page can be found (7.01). The directory read the
// first 500 people and filtered those, so nobody after them existed for any
// search at all.
func TestAPersonPastTheFirstPageIsFound(t *testing.T) {
	dir := &pagedDir{n: 2500}
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))
	res, err := c.Search(anonymousSearch("(uid=p2400)", 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("uid") != "p2400" {
		t.Fatalf("found %d entries for the person at 2,400", len(res.Entries))
	}
}

// A client walks the whole directory a page at a time with RFC 2696's control,
// through a real client's implementation of it, and meets everybody once.
func TestPagedResultsWalkTheWholeDirectory(t *testing.T) {
	dir := &pagedDir{n: 2500}
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))
	res, err := c.SearchWithPaging(anonymousSearch("(objectClass=person)", 0), 300)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range res.Entries {
		seen[e.GetAttributeValue("uid")]++
	}
	if len(res.Entries) != dir.n || len(seen) != dir.n {
		t.Errorf("met %d entries and %d people of %d", len(res.Entries), len(seen), dir.n)
	}

	root, err := c.Search(ldapclient.NewSearchRequest("", ldapclient.ScopeBaseObject, ldapclient.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := root.Entries[0].GetAttributeValue("supportedControl"); got != oidPagedResults {
		t.Errorf("the root DSE advertises %q", got)
	}
}

// A page of a search that a filter thins out still ends where the last entry
// returned was, not where the read stopped, so nobody is skipped between pages.
func TestAPageCarriesOnFromItsLastEntry(t *testing.T) {
	dir := &pagedDir{n: 1000}
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))
	res, err := c.SearchWithPaging(anonymousSearch("(|(uid=p7)(uid=p8)(uid=p9)(uid=p500)(uid=p999))", 0), 2)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.GetAttributeValue("uid"))
	}
	if want := []string{"p7", "p8", "p9", "p500", "p999"}; !reflect.DeepEqual(got, want) {
		t.Errorf("paged %v, want %v", got, want)
	}
}

// A list cut short says so (specs/rfc4511.txt:2780 and :2820). Success said a
// directory of 501 held 500, and an application reads the rest as not existing.
func TestAListCutShortSaysSo(t *testing.T) {
	addr := startServerWith(t, Config{AllowAnonymousSearch: true, MaxResults: 100}, &pagedDir{n: 101})
	c := dial(t, addr)
	res, err := c.Search(anonymousSearch("(objectClass=person)", 0))
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultAdminLimitExceeded) {
		t.Errorf("a search past the server's limit answered %v, want adminLimitExceeded", err)
	}
	if res == nil || len(res.Entries) != 100 {
		t.Errorf("the entries up to the limit were not returned: %+v", res)
	}
	res, err = c.Search(anonymousSearch("(objectClass=person)", 10))
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultSizeLimitExceeded) {
		t.Errorf("a search past the client's limit answered %v, want sizeLimitExceeded", err)
	}
	if res == nil || len(res.Entries) != 10 {
		t.Errorf("the entries up to the client's limit were not returned: %+v", res)
	}

	// Exactly the limit is a complete answer.
	exact := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true, MaxResults: 100}, &pagedDir{n: 100}))
	if res, err := exact.Search(anonymousSearch("(objectClass=person)", 0)); err != nil || len(res.Entries) != 100 {
		t.Errorf("a directory of exactly the limit answered %v with %d entries", err, len(res.Entries))
	}
}

// A cookie is the client's to return and not to make up, and giving up on a
// paged search ends it without another page.
func TestACookieIsNotTakenOnTrust(t *testing.T) {
	dir := &pagedDir{n: 50}
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))

	paged := ldapclient.NewControlPaging(10)
	paged.SetCookie([]byte("not a position"))
	req := anonymousSearch("(objectClass=person)", 0)
	req.Controls = []ldapclient.Control{paged}
	if _, err := c.Search(req); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultProtocolError) {
		t.Errorf("a made-up cookie answered %v, want protocolError", err)
	}

	abandon := ldapclient.NewControlPaging(0)
	abandon.SetCookie([]byte("12"))
	req = anonymousSearch("(objectClass=person)", 0)
	req.Controls = []ldapclient.Control{abandon}
	res, err := c.Search(req)
	if err != nil || len(res.Entries) != 0 {
		t.Errorf("giving up answered %v with %d entries", err, len(res.Entries))
	}
}

func filterOf(t *testing.T, text string) *filter {
	t.Helper()
	p, err := ldapclient.CompileFilter(text)
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	f, err := decodeFilter(p)
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return f
}

func TestAFilterIsReducedToWhatTheDatabaseCanAnswer(t *testing.T) {
	s := New(Config{BaseDN: baseDN}, &fakeAuth{}, nil)
	login := func(v string) *Condition { return &Condition{Op: CondLogin, Value: v} }
	mail := func(v string) *Condition { return &Condition{Op: CondMail, Value: v} }
	none := &Condition{Op: CondNone}
	for text, want := range map[string]*Condition{
		"(uid=a)":                        login("a"),
		"(UID=a)":                        login("a"),
		"(&(objectClass=person)(uid=a))": login("a"),
		"(|(uid=a)(mail=b))":             {Op: CondOr, Of: []*Condition{login("a"), mail("b")}},
		"(&(uid=a)(mail=b))":             {Op: CondAnd, Of: []*Condition{login("a"), mail("b")}},
		"(cn=A Person)":                  {Op: CondName, Value: "A Person"},
		"(memberOf=cn=eng,ou=groups," + baseDN + ")": {Op: CondGroup, Value: "eng"},
		// Left to Matches, each for its own reason.
		"(|(uid=a)(sn=b))":                nil, // this arm could be anybody
		"(!(uid=a))":                      nil, // the opposite of a superset is a subset
		"(sn=b)":                          nil,
		"(memberOf=cn=eng,ou=other,dc=x)": nil,
		"(objectClass=person)":            nil,
		// A superset: sn narrows nothing, and the AND only narrows further.
		"(&(uid=a)(sn=b))": login("a"),
		// Nobody, without asking.
		"(objectClass=device)":              none,
		"(&(uid=a)(objectClass=device))":    none,
		"(|(objectClass=device)(uid=a))":    login("a"),
		"(|(objectClass=a)(objectClass=b))": none,
	} {
		if got := s.narrow(filterOf(t, text)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s reduced to %+v, want %+v", text, got, want)
		}
	}
}

// holds reads a condition as the database would, loosely: it may say yes to
// anybody the database would, and that is what is being checked.
func holds(c *Condition, e *entry) bool {
	any := func(attr, value string) bool {
		for _, v := range attrValues(e, attr) {
			if strings.EqualFold(v, value) {
				return true
			}
		}
		return false
	}
	switch c.Op {
	case CondAnd:
		for _, child := range c.Of {
			if !holds(child, e) {
				return false
			}
		}
		return true
	case CondOr:
		for _, child := range c.Of {
			if holds(child, e) {
				return true
			}
		}
		return false
	case CondLogin:
		return any("uid", c.Value)
	case CondMail:
		return any("mail", c.Value)
	case CondName:
		return any("cn", c.Value)
	case CondGroup:
		return any("memberOf", fmt.Sprintf("cn=%s,ou=groups,%s", c.Value, baseDN))
	}
	return false
}

// The one way a reduction can go wrong is to hide somebody, since every entry
// it lets through is checked again. So: over random filters and people,
// anybody a filter matches, its reduction holds for.
func TestAReductionNeverHidesAnybody(t *testing.T) {
	s := New(Config{BaseDN: baseDN, UserAttr: "uid"}, &fakeAuth{}, nil)
	rng := rand.New(rand.NewSource(7))
	values := []string{"a", "b", "c"}
	attrs := []string{"uid", "mail", "cn", "sn", "givenName", "objectClass", "memberOf", "telephoneNumber"}
	pick := func(of []string) string { return of[rng.Intn(len(of))] }

	var random func(depth int) *filter
	random = func(depth int) *filter {
		if depth == 0 || rng.Intn(3) == 0 {
			attr := pick(attrs)
			switch {
			case rng.Intn(5) == 0:
				return &filter{Kind: filterPresent, Attr: attr}
			case attr == "objectClass":
				return &filter{Kind: filterEquality, Attr: attr, Value: pick([]string{"person", "device"})}
			case attr == "memberOf":
				return &filter{Kind: filterEquality, Attr: attr,
					Value: fmt.Sprintf("cn=%s,ou=groups,%s", pick(values), baseDN)}
			}
			return &filter{Kind: filterEquality, Attr: attr, Value: pick(values)}
		}
		kind := []filterKind{filterAnd, filterOr, filterNot}[rng.Intn(3)]
		if kind == filterNot {
			return &filter{Kind: kind, Children: []*filter{random(depth - 1)}}
		}
		f := &filter{Kind: kind}
		for i := 0; i < 1+rng.Intn(3); i++ {
			f.Children = append(f.Children, random(depth-1))
		}
		return f
	}

	matched := 0
	for i := 0; i < 20000; i++ {
		f := random(4)
		id := &Identity{Username: pick(values), Email: pick(values), DisplayName: pick(values),
			Surname: pick(values), GivenName: pick(values), Active: true}
		if rng.Intn(2) == 0 {
			id.Groups = []string{pick(values)}
		}
		e := s.entryFor(id)
		if !f.Matches(e) {
			continue
		}
		matched++
		if c := s.narrow(f); c != nil && (c.Op == CondNone || !holds(c, e)) {
			t.Fatalf("a filter matches %+v and its reduction %+v does not", id, c)
		}
	}
	if matched < 1000 {
		t.Fatalf("only %d filters matched anybody; this is testing nothing", matched)
	}
}
