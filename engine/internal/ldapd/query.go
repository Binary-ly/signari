package ldapd

import (
	"context"
	"errors"
	"strings"
)

// Query asks for a page of the people a subtree search could reach (7.01). The
// directory used to read the first 500 people and filter those in memory, so
// nobody past them could be found by any filter.
//
// It crosses a process boundary, as an outpost's request to the core, so it is
// data and says nothing of how it is answered.
type Query struct {
	// Narrow is what the search's filter says about who could match; nil is
	// anybody. See narrow for why it is only ever a superset.
	Narrow *Condition `json:"narrow,omitempty"`
	// After is the Position of the last person of the page before.
	After string `json:"after,omitempty"`
	// Limit is the most to answer. Fewer than this means there are no more.
	Limit int `json:"limit"`
}

// Ops a Condition may be. Each of the leaves compares without regard to case.
const (
	CondAnd = "and"
	CondOr  = "or"
	// CondLogin is the name a person signs in with.
	CondLogin = "login"
	CondMail  = "mail"
	// CondName is the entry's common name.
	CondName = "name"
	// CondGroup is membership of the group named by Value.
	CondGroup = "group"
	// CondLoginPrefix and CondMailPrefix are a name or an address beginning
	// with Value.
	CondLoginPrefix = "login_prefix"
	CondMailPrefix  = "mail_prefix"
	// CondMember is a group that holds the person who signs in as Value.
	CondMember = "member"
	// CondNumber is a person's or group's POSIX number.
	CondNumber = "number"
	// CondNone is nobody at all.
	CondNone = "none"
)

// Condition is a filter reduced to what a person's stored fields can answer.
type Condition struct {
	Op    string       `json:"op"`
	Value string       `json:"value,omitempty"`
	Of    []*Condition `json:"of,omitempty"`
}

// MaxConditions bounds a filter's reduction. Past it a search reads everybody
// and filters here, which is slower and still right; a client does not get to
// write an arbitrarily long statement for the database.
const MaxConditions = 256

// ErrBadPosition is a paging cookie this directory did not issue.
var ErrBadPosition = errors.New("ldapd: that is not a position in the directory")

// narrow reduces a filter to a Condition that every entry the filter matches
// satisfies. nil means it says nothing about who, and the search reads
// everybody.
//
// A superset and nothing tighter, because Matches still decides every entry
// and is the only thing that does: all a Condition can do wrong is hide
// somebody, so anything uncertain is left out. That is why `!` narrows
// nothing: the opposite of a superset is a subset. So a NOT of an address is
// not answered by the database, whose lower() folds more than equalFold here
// does and would drop an entry Matches keeps.
func (s *Server) narrow(f *filter) *Condition {
	return reduced(f, s.personLeaf)
}

// narrowGroups is narrow for a search of the groups.
func (s *Server) narrowGroups(f *filter) *Condition {
	return reduced(f, s.groupLeaf)
}

func reduced(f *filter, leaf func(*filter) *Condition) *Condition {
	spent := 0
	c := reduce(f, &spent, leaf)
	if spent > MaxConditions {
		return nil
	}
	return c
}

func reduce(f *filter, spent *int, leaf func(*filter) *Condition) *Condition {
	*spent++
	if f == nil || *spent > MaxConditions {
		return nil
	}
	switch f.Kind {
	case filterAnd:
		var of []*Condition
		for _, child := range f.Children {
			c := reduce(child, spent, leaf)
			if c == nil {
				continue // a superset of the AND: it only ever narrows further
			}
			if c.Op == CondNone {
				return c
			}
			of = append(of, c)
		}
		return joined(CondAnd, of)

	case filterOr:
		var of []*Condition
		for _, child := range f.Children {
			c := reduce(child, spent, leaf)
			if c == nil {
				return nil // this arm could match anybody, so the OR could
			}
			if c.Op != CondNone {
				of = append(of, c)
			}
		}
		if len(of) == 0 && len(f.Children) > 0 {
			return &Condition{Op: CondNone}
		}
		return joined(CondOr, of)
	}
	return leaf(f)
}

// personLeaf is what one assertion says about who could match among people.
func (s *Server) personLeaf(f *filter) *Condition {
	switch f.Kind {
	case filterSubstring:
		switch {
		case f.Initial == "":
		case equalFold(f.Attr, "cn"):
		case equalFold(f.Attr, s.cfg.UserAttr):
			return &Condition{Op: CondLoginPrefix, Value: f.Initial}
		case equalFold(f.Attr, "mail"):
			return &Condition{Op: CondMailPrefix, Value: f.Initial}
		}

	case filterEquality, filterApprox:
		switch {
		case equalFold(f.Attr, "objectClass"):
			for _, class := range s.personClasses() {
				if equalFold(class, f.Value) {
					return nil
				}
			}
			return &Condition{Op: CondNone}
		case s.cfg.POSIX && isIntegerAttr(f.Attr):
			// A person's gidNumber is their own number.
			return numberCondition(CondNumber, f.Value)
		case s.cfg.POSIX && equalFold(f.Attr, "uid"):
			return &Condition{Op: CondLogin, Value: f.Value}
		case equalFold(f.Attr, "cn"):
			// Before the naming attribute: entryFor writes cn over it when the
			// two are the same attribute.
			return &Condition{Op: CondName, Value: f.Value}
		case equalFold(f.Attr, s.cfg.UserAttr):
			return &Condition{Op: CondLogin, Value: f.Value}
		case equalFold(f.Attr, "mail"):
			return &Condition{Op: CondMail, Value: f.Value}
		case equalFold(f.Attr, "memberOf"):
			if name, ok := s.groupOfDN(f.Value); ok {
				return &Condition{Op: CondGroup, Value: name}
			}
		}
	}
	return nil
}

// groupLeaf is personLeaf for groups, of which an organisation has few: only
// what a client actually asks by, and that an assertion about an attribute no
// group holds cannot be TRUE of one, so `(uid=x)` from the base asks one
// question and not two.
func (s *Server) groupLeaf(f *filter) *Condition {
	exact := f.Kind == filterEquality || f.Kind == filterApprox
	switch {
	case f.Attr == "" || (f.Kind == filterExtensible && f.DNAttributes):
		return nil
	case equalFold(f.Attr, "objectClass"):
		if exact {
			for _, class := range s.groupClasses() {
				if equalFold(class, f.Value) {
					return nil
				}
			}
			return &Condition{Op: CondNone}
		}
	case equalFold(f.Attr, "cn"):
		if exact {
			return &Condition{Op: CondName, Value: f.Value}
		}
	case equalFold(f.Attr, "member"):
		if exact {
			if login, err := s.usernameFromDN(f.Value); err == nil {
				return &Condition{Op: CondMember, Value: login}
			}
		}
	case s.cfg.POSIX && equalFold(f.Attr, "gidNumber"):
		if exact {
			return numberCondition(CondNumber, f.Value)
		}
	case s.cfg.POSIX && equalFold(f.Attr, "memberUid"):
		if exact {
			return &Condition{Op: CondMember, Value: f.Value}
		}
	default:
		return &Condition{Op: CondNone}
	}
	return nil
}

func joined(op string, of []*Condition) *Condition {
	switch len(of) {
	case 0:
		return nil
	case 1:
		return of[0]
	}
	return &Condition{Op: op, Of: of}
}

// groupOfDN reads the group a memberOf value names, as entryFor writes one.
// Anything else is left to Matches.
func (s *Server) groupOfDN(dn string) (string, bool) {
	const prefix = "cn="
	suffix := ",ou=groups," + s.cfg.BaseDN
	if len(dn) <= len(prefix)+len(suffix) || !equalFold(dn[:len(prefix)], prefix) ||
		!equalFold(dn[len(dn)-len(suffix):], suffix) {
		return "", false
	}
	name := dn[len(prefix) : len(dn)-len(suffix)]
	if strings.ContainsAny(name, ",=") {
		return "", false
	}
	return name, true
}

// listed is one entry a backend answered, and where it was.
type listed struct {
	entry    *entry
	position string
}

// walk reads entries in order until it has want that match or there are no
// more. more says another match exists past the last one returned, and last is
// that entry's position.
func walk(req *searchRequest, q Query, want int, read func(Query) ([]listed, error)) (
	found []*entry, last string, more bool, err error) {

	q.Limit = walkPage(want)
	if q.Narrow != nil && q.Narrow.Op == CondNone {
		return nil, "", false, nil
	}
	for {
		page, err := read(q)
		if err != nil {
			return nil, "", false, err
		}
		for _, l := range page {
			if !req.Filter.Matches(l.entry) {
				continue
			}
			if len(found) == want {
				return found, last, true, nil
			}
			found = append(found, l.entry)
			last = l.position
		}
		// Short, or a backend that gave no position to go on from.
		if len(page) < q.Limit || page[len(page)-1].position == "" {
			return found, last, false, nil
		}
		q.After = page[len(page)-1].position
	}
}

func (s *Server) walkPeople(ctx context.Context, req *searchRequest, after string, want int) (
	[]*entry, string, bool, error) {
	return walk(req, Query{Narrow: s.narrow(req.Filter), After: after}, want, func(q Query) ([]listed, error) {
		people, err := s.auth.List(ctx, q)
		if err != nil {
			return nil, err
		}
		out := make([]listed, len(people))
		for i, id := range people {
			out[i] = listed{entry: s.entryFor(id), position: id.Position}
		}
		return out, nil
	})
}

// walkPage is how many people to ask for at once. One past what is wanted, so
// that a further match is seen; at least a hundred, since a filter the database
// could not narrow is filtered here and most of a page may not match.
func walkPage(want int) int {
	const least, most = 100, 1000
	switch {
	case want+1 < least:
		return least
	case want+1 > most:
		return most
	}
	return want + 1
}
