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
	spent := 0
	c := s.reduce(f, &spent)
	if spent > MaxConditions {
		return nil
	}
	return c
}

func (s *Server) reduce(f *filter, spent *int) *Condition {
	*spent++
	if f == nil || *spent > MaxConditions {
		return nil
	}
	switch f.Kind {
	case filterAnd:
		var of []*Condition
		for _, child := range f.Children {
			c := s.reduce(child, spent)
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
			c := s.reduce(child, spent)
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

	case filterEquality:
		switch {
		case equalFold(f.Attr, "objectClass"):
			for _, class := range objectClasses {
				if equalFold(class, f.Value) {
					return nil
				}
			}
			return &Condition{Op: CondNone}
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

// walk reads people in order, past after, until it has want who match or there
// are no more. more says another match exists past the last one returned, and
// last is that entry's position.
func (s *Server) walk(ctx context.Context, req *searchRequest, after string, want int) (
	found []*entry, last string, more bool, err error) {

	q := Query{Narrow: s.narrow(req.Filter), After: after, Limit: walkPage(want)}
	if q.Narrow != nil && q.Narrow.Op == CondNone {
		return nil, "", false, nil
	}
	for {
		page, err := s.auth.List(ctx, q)
		if err != nil {
			return nil, "", false, err
		}
		for _, id := range page {
			e := s.entryFor(id)
			if !req.Filter.Matches(e) {
				continue
			}
			if len(found) == want {
				return found, last, true, nil
			}
			found = append(found, e)
			last = id.Position
		}
		// Short, or a backend that gave no position to go on from.
		if len(page) < q.Limit || page[len(page)-1].Position == "" {
			return found, last, false, nil
		}
		q.After = page[len(page)-1].Position
	}
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
