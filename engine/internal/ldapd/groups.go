package ldapd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Group entries (7.02). An application that reads groups from a directory lists
// them and their members; `memberOf` on a person answers only the reverse.
//
// They sit at cn=<name>,ou=groups,<base>, which is where memberOf has always
// pointed. A group with nobody in it is not published: groupOfNames MUST have a
// member, and the alternatives are an entry that breaks the class it claims or a
// member that is not one.

// Group is what the directory exposes about a group.
type Group struct {
	Name string `json:"name"`
	// Members are the login names of those in it, as dnFor names them.
	Members []string `json:"members"`
	// GIDNumber is its POSIX number, 0 from a core that predates them.
	GIDNumber int `json:"gid_number,omitempty"`
	// Position is where Groups found it, as Identity's is.
	Position string `json:"position,omitempty"`
}

// GroupLister is an Authenticator that can read groups. A directory behind one
// that cannot holds only people.
type GroupLister interface {
	// Groups answers a page of the groups a search could reach, those with
	// members, in an order that does not change between pages. As List does, it
	// answers ErrBadPosition for a position it did not issue.
	Groups(ctx context.Context, q Query) ([]*Group, error)
}

var groupClasses = []string{"top", "groupOfNames"}

// groupsCookie marks a position as being among the groups, for a search that
// reaches people and then groups.
const groupsCookie = "g:"

func (s *Server) groupsDN() string { return "ou=groups," + s.cfg.BaseDN }

func (s *Server) groupDN(name string) string {
	return fmt.Sprintf("cn=%s,%s", name, s.groupsDN())
}

func (s *Server) groupEntry(g *Group) *entry {
	members := make([]string, len(g.Members))
	for i, m := range g.Members {
		members[i] = s.dnFor(m)
	}
	attrs := map[string][]string{
		"objectClass": groupClasses,
		"cn":          {g.Name},
		"member":      members,
	}
	if s.cfg.POSIX && g.GIDNumber > 0 {
		attrs["objectClass"] = s.groupClasses()
		attrs["gidNumber"] = []string{strconv.Itoa(g.GIDNumber)}
		attrs["memberUid"] = g.Members
	}
	return &entry{DN: s.groupDN(g.Name), Attrs: attrs}
}

func (s *Server) walkGroups(ctx context.Context, req *searchRequest, after string, want int) (
	[]*entry, string, bool, error) {

	lister, ok := s.auth.(GroupLister)
	if !ok {
		return nil, "", false, nil
	}
	return walk(req, Query{Narrow: s.narrowGroups(req.Filter), After: after}, want, func(q Query) ([]listed, error) {
		groups, err := lister.Groups(ctx, q)
		if err != nil {
			return nil, err
		}
		out := make([]listed, len(groups))
		for i, g := range groups {
			out[i] = listed{entry: s.groupEntry(g), position: g.Position}
		}
		return out, nil
	})
}

// groupSearch answers a search based in the group subtree, reporting whether it
// was one.
func (s *Server) groupSearch(ctx context.Context, req *searchRequest, after string, limit int) (
	found []*entry, position string, more, handled bool, err error) {

	base, groups := normalDN(req.BaseDN), normalDN(s.groupsDN())
	switch {
	case base == groups && req.Scope == scopeBaseObject:
		e := &entry{DN: s.groupsDN(), Attrs: map[string][]string{
			"objectClass": {"top", "organizationalUnit"}, "ou": {"groups"}}}
		if req.Filter.Matches(e) {
			found = []*entry{e}
		}
		return found, "", false, true, nil
	case base == groups:
		found, position, more, err = s.walkGroups(ctx, req, strings.TrimPrefix(after, groupsCookie), limit)
		return found, groupsCookie + position, more, true, err
	case strings.HasSuffix(base, ","+groups):
		if req.Scope == scopeSingleLevel {
			return nil, "", false, true, nil // a group has no children
		}
		// One group, and only the one its DN names.
		name, ok := s.groupOfDN(req.BaseDN)
		if !ok {
			return nil, "", false, true, nil
		}
		one := *req
		one.Filter = &filter{Kind: filterAnd, Children: []*filter{req.Filter,
			{Kind: filterEquality, Attr: "cn", Value: name}}}
		found, _, _, err = s.walkGroups(ctx, &one, "", 1)
		return found, "", false, true, err
	}
	return nil, "", false, false, nil
}

// walkAll reads a subtree of the base: people and then groups, the cookie saying
// which it has reached.
func (s *Server) walkAll(ctx context.Context, req *searchRequest, after string, limit int) (
	[]*entry, string, bool, error) {

	var people []*entry
	if !strings.HasPrefix(after, groupsCookie) {
		var last string
		var more bool
		var err error
		people, last, more, err = s.walkPeople(ctx, req, after, limit)
		if err != nil || more {
			return people, last, more, err
		}
		after = groupsCookie
	}
	groups, last, more, err := s.walkGroups(ctx, req, strings.TrimPrefix(after, groupsCookie), limit-len(people))
	return append(people, groups...), groupsCookie + last, more, err
}
