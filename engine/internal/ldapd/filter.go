package ldapd

import (
	"cmp"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// filter is a search filter (RFC 4511 §4.5.1.7), held as the parts its BER
// carried and evaluated on those. It is never turned back into a filter string
// to be parsed again: a value's own `*` or `)` would become syntax there, which
// is how another directory loses its escaping.
type filter struct {
	Kind  filterKind
	Attr  string
	Value string
	// Initial, Any and Final are the parts of a substrings filter. An empty
	// Initial or Final is one that was not given.
	Initial string
	Any     []string
	Final   string
	// Rule and DNAttributes are an extensibleMatch's. Rule empty is the
	// attribute's equality.
	Rule         string
	DNAttributes bool
	Children     []*filter
}

type filterKind int

const (
	filterAnd filterKind = iota
	filterOr
	filterNot
	filterEquality
	filterPresent
	filterSubstring
	filterGreaterOrEqual
	filterLessOrEqual
	filterApprox
	filterExtensible
	// filterUnsupported is Undefined whatever it is asked of, rather than an
	// error: specs/rfc4511.txt:1312 "Servers MUST NOT return errors if attribute
	// descriptions or matching rule ids are not recognized, assertion values
	// are invalid, or the assertion syntax is not supported."
	filterUnsupported
)

// Filter tags (RFC 4511 §4.5.1.7).
const (
	filterTagAnd            = 0
	filterTagOr             = 1
	filterTagNot            = 2
	filterTagEquality       = 3
	filterTagSubstring      = 4
	filterTagGreaterOrEqual = 5
	filterTagLessOrEqual    = 6
	filterTagPresent        = 7
	filterTagApprox         = 8
	filterTagExtensible     = 9
)

// maxSubstrings caps a substrings filter's parts: each is a scan of every value
// of every entry a search reads. A filter past it is Undefined, as one this
// directory cannot evaluate is.
const maxSubstrings = 8

func decodeFilter(p *ber.Packet) (*filter, error) {
	switch p.Tag {
	case filterTagAnd, filterTagOr:
		kind := filterAnd
		if p.Tag == filterTagOr {
			kind = filterOr
		}
		f := &filter{Kind: kind}
		for _, c := range p.Children {
			child, err := decodeFilter(c)
			if err != nil {
				return nil, err
			}
			f.Children = append(f.Children, child)
		}
		return f, nil

	case filterTagNot:
		if len(p.Children) != 1 {
			return &filter{Kind: filterUnsupported}, nil
		}
		child, err := decodeFilter(p.Children[0])
		if err != nil {
			return nil, err
		}
		return &filter{Kind: filterNot, Children: []*filter{child}}, nil

	case filterTagEquality, filterTagGreaterOrEqual, filterTagLessOrEqual, filterTagApprox:
		if len(p.Children) != 2 {
			return &filter{Kind: filterUnsupported}, nil
		}
		kind := map[ber.Tag]filterKind{filterTagEquality: filterEquality, filterTagGreaterOrEqual: filterGreaterOrEqual,
			filterTagLessOrEqual: filterLessOrEqual, filterTagApprox: filterApprox}[p.Tag]
		return &filter{Kind: kind, Attr: string(p.Children[0].Data.Bytes()),
			Value: string(p.Children[1].Data.Bytes())}, nil

	case filterTagPresent:
		return &filter{Kind: filterPresent, Attr: string(p.Data.Bytes())}, nil

	case filterTagSubstring:
		return decodeSubstrings(p), nil

	case filterTagExtensible:
		return decodeExtensible(p), nil

	default:
		return &filter{Kind: filterUnsupported}, nil
	}
}

// decodeSubstrings reads a SubstringFilter. specs/rfc4511.txt:1326: at most one
// initial, which is first, and at most one final, which is last.
func decodeSubstrings(p *ber.Packet) *filter {
	unsupported := &filter{Kind: filterUnsupported}
	if len(p.Children) != 2 {
		return unsupported
	}
	parts := p.Children[1].Children
	if len(parts) == 0 || len(parts) > maxSubstrings {
		return unsupported
	}
	f := &filter{Kind: filterSubstring, Attr: string(p.Children[0].Data.Bytes())}
	for i, part := range parts {
		value := string(part.Data.Bytes())
		if value == "" {
			return unsupported
		}
		switch part.Tag {
		case 0:
			if i != 0 {
				return unsupported
			}
			f.Initial = value
		case 1:
			f.Any = append(f.Any, value)
		case 2:
			if i != len(parts)-1 {
				return unsupported
			}
			f.Final = value
		default:
			return unsupported
		}
	}
	return f
}

// decodeExtensible reads a MatchingRuleAssertion: [1] rule, [2] type, [3] value
// and [4] dnAttributes (specs/rfc4511.txt:1144). With no rule the type has to be
// there (:1388).
func decodeExtensible(p *ber.Packet) *filter {
	f := &filter{Kind: filterExtensible}
	hasValue := false
	for _, part := range p.Children {
		switch part.Tag {
		case 1:
			f.Rule = string(part.Data.Bytes())
		case 2:
			f.Attr = string(part.Data.Bytes())
		case 3:
			f.Value, hasValue = string(part.Data.Bytes()), true
		case 4:
			raw := part.Data.Bytes()
			f.DNAttributes = len(raw) == 1 && raw[0] != 0
		}
	}
	if !hasValue || (f.Rule == "" && f.Attr == "") {
		return &filter{Kind: filterUnsupported}
	}
	return f
}

// entry is one directory entry we return.
type entry struct {
	DN    string
	Attrs map[string][]string
}

// truth is what a filter says of an entry: specs/rfc4511.txt:1268, "TRUE",
// "FALSE", or "Undefined".
type truth int

const (
	isFalse truth = iota
	isTrue
	undefined
)

// Matches evaluates a filter against an entry. Only TRUE returns it.
//
// Attribute names are compared case-insensitively, because LDAP attribute
// descriptions are case-insensitive and clients send every variation of `uid`,
// `uID` and `UID` that you can imagine.
func (f *filter) Matches(e *entry) bool {
	return f == nil || f.eval(e) == isTrue
}

// order compares a value with the assertion's.
func (f *filter) order(v string) int {
	if isIntegerAttr(f.Attr) {
		a, aerr := strconv.Atoi(v)
		b, berr := strconv.Atoi(f.Value)
		if aerr == nil && berr == nil {
			return cmp.Compare(a, b)
		}
	}
	return cmp.Compare(foldASCII(v), foldASCII(f.Value))
}

// eval is the filter's value. Three of them, because two fail open: an
// assertion this directory cannot evaluate was FALSE, so the NOT of it was
// TRUE, and `(!(shoeSize=12))` returned everybody. Undefined stays Undefined
// through a NOT (specs/rfc4511.txt:1278).
func (f *filter) eval(e *entry) truth {
	switch f.Kind {
	case filterAnd:
		out := isTrue
		for _, c := range f.Children {
			switch c.eval(e) {
			case isFalse:
				return isFalse
			case undefined:
				out = undefined
			}
		}
		return out
	case filterOr:
		out := isFalse
		for _, c := range f.Children {
			switch c.eval(e) {
			case isTrue:
				return isTrue
			case undefined:
				out = undefined
			}
		}
		return out
	case filterNot:
		if len(f.Children) != 1 {
			return undefined
		}
		switch f.Children[0].eval(e) {
		case isTrue:
			return isFalse
		case isFalse:
			return isTrue
		}
		return undefined
	case filterEquality, filterApprox:
		// :1380, "If approximate matching is not supported for the attribute,
		// this filter item should be treated as an equalityMatch."
		return assertion(e, f.Attr, func(v string) bool { return equalFold(v, f.Value) })
	case filterPresent:
		return assertion(e, f.Attr, func(string) bool { return true })
	case filterGreaterOrEqual:
		return assertion(e, f.Attr, func(v string) bool { return f.order(v) >= 0 })
	case filterLessOrEqual:
		return assertion(e, f.Attr, func(v string) bool { return f.order(v) <= 0 })
	case filterSubstring:
		return assertion(e, f.Attr, f.substringsOf)
	case filterExtensible:
		return f.evalExtensible(e)
	}
	return undefined
}

// assertion asks whether a value of an attribute passes. Undefined for an
// attribute this directory does not recognise, specs/rfc4511.txt:1295; FALSE for
// one it does and this entry has no value of, or none that passes.
func assertion(e *entry, attr string, passes func(string) bool) truth {
	values := attrValues(e, attr)
	if len(values) == 0 {
		if _, known := lookupAttr(attr); !known {
			return undefined
		}
		return isFalse
	}
	for _, v := range values {
		if passes(v) {
			return isTrue
		}
	}
	return isFalse
}

// substringsOf is the filter's parts, in order and without overlapping.
func (f *filter) substringsOf(value string) bool {
	v := foldASCII(value)
	at := 0
	if f.Initial != "" {
		start := foldASCII(f.Initial)
		if !strings.HasPrefix(v, start) {
			return false
		}
		at = len(start)
	}
	for _, part := range f.Any {
		part = foldASCII(part)
		i := strings.Index(v[at:], part)
		if i < 0 {
			return false
		}
		at += i + len(part)
	}
	if f.Final != "" {
		end := foldASCII(f.Final)
		return len(v)-len(end) >= at && strings.HasSuffix(v, end)
	}
	return true
}

// evalExtensible follows specs/rfc4511.txt:1386. Undefined for a rule it does
// not recognise (:1419), among them every rule it would have to take an OID for
// on no authority; `(cn:caseExactMatch:=Ada)` names them.
func (f *filter) evalExtensible(e *entry) truth {
	same, known := matchingRule(f.Rule)
	if !known {
		return undefined
	}
	test := func(v string) bool { return same(v, f.Value) }

	out := isFalse
	if f.Attr != "" {
		out = assertion(e, f.Attr, test)
	} else {
		for _, values := range e.Attrs {
			for _, v := range values {
				if test(v) {
					return isTrue
				}
			}
		}
	}
	if out == isTrue || !f.DNAttributes {
		return out
	}
	for _, rdn := range strings.Split(e.DN, ",") {
		attr, value, ok := strings.Cut(rdn, "=")
		if !ok {
			continue
		}
		if (f.Attr == "" || equalFold(strings.TrimSpace(attr), f.Attr)) && test(strings.TrimSpace(value)) {
			return isTrue
		}
	}
	return out
}

// matchingRule is a rule by name, as OpenLDAP's schema names them, or the
// attribute's equality for none.
func matchingRule(name string) (func(a, b string) bool, bool) {
	switch foldASCII(name) {
	case "", "caseignorematch", "caseignoreia5match":
		return equalFold, true
	case "caseexactmatch", "caseexactia5match":
		return func(a, b string) bool { return a == b }, true
	}
	return nil, false
}

// foldASCII folds as equalFold compares.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		b[i] = lower(c)
	}
	return string(b)
}
