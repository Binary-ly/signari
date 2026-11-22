package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func person(n int) *ldap.Entry {
	return entry(fmt.Sprintf("uid=p%d,dc=x", n), map[string][]string{
		"entryUUID": {fmt.Sprintf("id-%d", n)}, "mail": {fmt.Sprintf("p%d@example.test", n)}})
}

// sourceOn answers on the URLs given and cannot be reached on any other.
func sourceOn(f *fakeLDAP, url string, answering ...string) (*LDAPSource, *[]string) {
	var tried []string
	return &LDAPSource{URL: url, BaseDN: "dc=x", Flavour: FlavourOpenLDAP, BindDN: "cn=sync", Password: "p",
		Dial: func(_ context.Context, u string) (ldapConn, error) {
			tried = append(tried, u)
			for _, a := range answering {
				if a == u {
					return f, nil
				}
			}
			return nil, fmt.Errorf("connecting to %q: refused", u)
		}}, &tried
}

// A replica is tried when a server cannot be reached, in the order given.
func TestAnUnreachableServerIsPassedOver(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{person(1)}}
	s, tried := sourceOn(f, "ldaps://a.test  ldaps://b.test ldaps://c.test", "ldaps://b.test", "ldaps://c.test")
	got, err := s.Fetch(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("read %v, %v", got, err)
	}
	if strings.Join(*tried, " ") != "ldaps://a.test ldaps://b.test" {
		t.Errorf("tried %v", *tried)
	}

	// None answering says what each said, and is an error: an empty list would be
	// everybody having left.
	s, _ = sourceOn(f, "ldaps://a.test ldaps://b.test")
	_, err = s.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "a.test") || !strings.Contains(err.Error(), "b.test") {
		t.Errorf("answered %v", err)
	}
}

// One that answers and refuses has said something true: a replica would say it
// again, or be one that has fallen behind.
func TestAServerThatRefusesIsNotPassedOver(t *testing.T) {
	f := &fakeLDAP{bindErr: errors.New("invalid credentials")}
	s, tried := sourceOn(f, "ldaps://a.test ldaps://b.test", "ldaps://a.test", "ldaps://b.test")
	if _, err := s.Fetch(context.Background()); err == nil {
		t.Fatal("a refused bind answered nothing")
	}
	if len(*tried) != 1 {
		t.Errorf("tried %v", *tried)
	}
	f = &fakeLDAP{searchErr: errors.New("busy")}
	s, tried = sourceOn(f, "ldaps://a.test ldaps://b.test", "ldaps://a.test", "ldaps://b.test")
	if _, err := s.Fetch(context.Background()); err == nil {
		t.Fatal("a failed search answered nothing")
	}
	if len(*tried) != 1 {
		t.Errorf("tried %v", *tried)
	}
}

// Each stops where a sync would, says so, and reads no more than a test needs.
func TestAConnectionTestSaysWhereItStopped(t *testing.T) {
	ctx := context.Background()
	s, _ := sourceOn(&fakeLDAP{}, "ldaps://a.test ldaps://b.test")
	if r := s.Test(ctx); r.OK || r.Step != "connect" || !strings.Contains(r.Detail, "b.test") {
		t.Errorf("unreachable: %+v", r)
	}

	s, _ = sourceOn(&fakeLDAP{bindErr: errors.New("invalid credentials")}, "ldaps://a.test", "ldaps://a.test")
	if r := s.Test(ctx); r.OK || r.Step != "bind" || r.Server != "ldaps://a.test" {
		t.Errorf("refused: %+v", r)
	}

	s, _ = sourceOn(&fakeLDAP{searchErr: errors.New("no such object")}, "ldaps://a.test", "ldaps://a.test")
	if r := s.Test(ctx); r.OK || r.Step != "search" {
		t.Errorf("a bad base: %+v", r)
	}

	s, _ = sourceOn(&fakeLDAP{}, "ldaps://a.test", "ldaps://a.test")
	if r := s.Test(ctx); r.OK || r.Step != "search" || !strings.Contains(r.Detail, "everybody having left") {
		t.Errorf("nobody found: %+v", r)
	}

	// The wrong flavour, which a sync finds out by refusing every person.
	lacking := entry("uid=p,dc=x", map[string][]string{"objectGUID": {"x"}})
	s, _ = sourceOn(&fakeLDAP{entries: []*ldap.Entry{lacking}}, "ldaps://a.test", "ldaps://a.test")
	if r := s.Test(ctx); r.OK || r.Step != "identity" || !strings.Contains(r.Detail, "entryUUID") {
		t.Errorf("the wrong flavour: %+v", r)
	}

	// Past the limit it asked for is not a failure, and it read no more than that.
	f := &fakeLDAP{}
	for n := range testEntries + 3 {
		f.entries = append(f.entries, person(n))
	}
	s, _ = sourceOn(f, "ldaps://a.test ldaps://b.test", "ldaps://b.test")
	r := s.Test(ctx)
	if !r.OK || r.Server != "ldaps://b.test" || r.Found != testEntries {
		t.Errorf("a full directory: %+v", r)
	}
	if f.searched == nil || f.searched.SizeLimit != testEntries {
		t.Errorf("searched %+v", f.searched)
	}
	if f.pageSize != 0 {
		t.Error("the test paged through the directory")
	}
}

// Every URL is held to the rule, since a failover is when nobody is watching what
// the password would be sent to.
func TestEachURLIsHeldToTheRule(t *testing.T) {
	spec := func(url string, startTLS bool) *SourceSpec {
		return &SourceSpec{Kind: "ldap", Slug: "s", LDAPURL: url, LDAPBaseDN: "dc=x", LDAPFlavour: "openldap",
			LDAPStartTLS: startTLS, LDAPPassword: "p"}
	}
	if err := spec("ldaps://a.test ldaps://b.test", false).Validate(); err != nil {
		t.Errorf("two ldaps URLs: %v", err)
	}
	if err := spec("ldap://a.test ldap://b.test", true).Validate(); err != nil {
		t.Errorf("two with StartTLS: %v", err)
	}
	for _, url := range []string{"ldaps://a.test ldap://b.test", "ldaps://a.test http://b.test", "a.test"} {
		if err := spec(url, false).Validate(); !errors.Is(err, ErrSourceInvalid) {
			t.Errorf("%s answered %v", url, err)
		}
	}
}
