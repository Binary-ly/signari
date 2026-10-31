package ldapd

import (
	"context"
	"sync/atomic"
	"testing"

	ldapclient "github.com/go-ldap/ldap/v3"
)

// goesDown is an authenticator whose lookups stop answering after a given number.
type goesDown struct {
	*fakeAuth
	answers atomic.Int64
}

func (g *goesDown) Lookup(ctx context.Context, u string) (*Identity, error) {
	if g.answers.Add(-1) < 0 {
		return nil, ErrUnavailable
	}
	return g.fakeAuth.Lookup(ctx, u)
}

// A search that could not be answered says so. An empty result is a statement that
// nobody is there, and a service reading this directory is entitled to act on it, so
// neither search that reads a person may turn an outage into one, whichever lookup the
// outage arrives at.
func TestASearchThatCouldNotBeAnsweredIsNotAnEmptyOne(t *testing.T) {
	for _, c := range []struct {
		name    string
		groups  []string
		answers int64
	}{
		// The check of who is asking is the first lookup, and each goes on from there.
		{"somebody who may read the directory", []string{"readers"}, 1},
		{"somebody who may read only their own entry", nil, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			auth := &goesDown{fakeAuth: &fakeAuth{groups: c.groups}}
			auth.answers.Store(1 << 20)
			conn := dial(t, startServerWith(t, Config{SearchGroup: "readers"}, auth))
			if err := conn.Bind("uid=alice,"+baseDN, fixtures["alice"].pw); err != nil {
				t.Fatal(err)
			}
			search := func() (*ldapclient.SearchResult, error) {
				return conn.Search(ldapclient.NewSearchRequest("uid=alice,"+baseDN, ldapclient.ScopeBaseObject,
					ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"uid"}, nil))
			}
			if got, err := search(); err != nil || len(got.Entries) != 1 {
				t.Fatalf("with everything up: %v, %v", got, err)
			}
			auth.answers.Store(c.answers)
			if got, err := search(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailable) {
				t.Errorf("after %d lookups the search gave %v, %v; want unavailable", c.answers, got, err)
			}
		})
	}
}
