// Package ldapd is an LDAP front end for applications that can only
// authenticate by binding to a directory.
//
// # What this is, and what it deliberately is not
//
// It is a COMPATIBILITY SHIM. It answers bind and search, read-only, so that
// software written against a directory can authenticate people who live in
// Signari. It is not a directory: there is no write path, no schema, no
// replication, no modify, no add, no delete. Those are refused rather than
// stubbed, because a half-implemented directory is one somebody eventually
// depends on.
//
// # The rule the CVE record points at
//
// CVE-2017-14623, against go-ldap: "an attacker may be able to login with an
// empty password... if [the application] relies only on the return error of the
// Bind function and it is used with an LDAP server allowing unauthenticated
// bind."
//
// RFC 4513 §5.1.2 names that case: a simple bind carrying a DN and an EMPTY
// password is an *unauthenticated* bind, not an authentication. Servers that
// answer success to it hand every such application a bypass, because the
// application asked "did the bind succeed" and the honest answer to "is this
// person who they say they are" was never given.
//
// So: an empty password is refused here, always, with invalidCredentials. There
// is no configuration option to allow it.
package ldapd

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP application tags (RFC 4511 §4).
const (
	appBindRequest       = 0
	appBindResponse      = 1
	appUnbindRequest     = 2
	appSearchRequest     = 3
	appSearchResultEntry = 4
	appSearchResultDone  = 5
	appModifyRequest     = 6
	appAddRequest        = 8
	appDelRequest        = 10
	appModifyDNRequest   = 12
	appCompareRequest    = 14
	appAbandonRequest    = 16
	appExtendedRequest   = 23
	appExtendedResponse  = 24
)

// Result codes (RFC 4511 §4.1.9 / Appendix A).
const (
	resultSuccess                = 0
	resultProtocolError          = 2
	resultAuthMethodNotSupported = 7
	resultNoSuchObject           = 32
	resultInvalidCredentials     = 49
	resultInsufficientAccess     = 50
	resultUnwillingToPerform     = 53
	resultOther                  = 80
)

// Search scopes.
const (
	scopeBaseObject   = 0
	scopeSingleLevel  = 1
	scopeWholeSubtree = 2
)

// maxMessageSize bounds a single LDAP message.
//
// The protocol carries its own length, so a caller can announce a request of any
// size and a server that believes it allocates that much before reading a byte
// of it. One connection, one integer, gigabytes of memory.
const maxMessageSize = 1 << 20

// bindRequest is a decoded simple bind.
type bindRequest struct {
	Version  int
	DN       string
	Password string
	// Simple is false for SASL, which is refused: implementing SASL badly is
	// worse than not implementing it, and the applications this shim exists for
	// use simple bind over TLS.
	Simple bool
}

// searchRequest is the subset of a search we act on.
type searchRequest struct {
	BaseDN    string
	Scope     int
	SizeLimit int
	Filter    *filter
	Attrs     []string
}

// decodeBind reads a BindRequest.
func decodeBind(op *ber.Packet) (*bindRequest, error) {
	if len(op.Children) < 3 {
		return nil, fmt.Errorf("bind request has %d fields, expected 3", len(op.Children))
	}
	ver, ok := op.Children[0].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("bind version is not an integer")
	}
	dn, ok := op.Children[1].Value.(string)
	if !ok {
		return nil, fmt.Errorf("bind DN is not a string")
	}

	auth := op.Children[2]
	req := &bindRequest{Version: int(ver), DN: dn}

	// Tag 0 is simple authentication; tag 3 is SASL.
	if auth.Tag != 0 {
		return req, nil // Simple stays false: the caller refuses it.
	}
	req.Simple = true
	// The password is the raw octet string. Taken from Data, not Value: BER
	// parsers may decode a context-tagged octet string as a string only
	// sometimes, and a password read as an empty string when it was not empty
	// would be a very bad failure in exactly this function.
	req.Password = string(auth.Data.Bytes())
	return req, nil
}

// decodeSearch reads a SearchRequest.
func decodeSearch(op *ber.Packet) (*searchRequest, error) {
	if len(op.Children) < 8 {
		return nil, fmt.Errorf("search request has %d fields, expected at least 8",
			len(op.Children))
	}
	base, _ := op.Children[0].Value.(string)
	scope, _ := op.Children[1].Value.(int64)
	sizeLimit, _ := op.Children[3].Value.(int64)

	f, err := decodeFilter(op.Children[6])
	if err != nil {
		return nil, err
	}

	var attrs []string
	for _, a := range op.Children[7].Children {
		if s, ok := a.Value.(string); ok {
			attrs = append(attrs, s)
		}
	}
	return &searchRequest{
		BaseDN: base, Scope: int(scope), SizeLimit: int(sizeLimit),
		Filter: f, Attrs: attrs,
	}, nil
}

// filter is the subset of LDAP filters this shim understands.
//
// Deliberately small. The full grammar includes substring matching, extensible
// matches and approximate matches, and each is a way to ask the server to do
// work on behalf of an unauthenticated stranger. What applications actually
// send when authenticating is an equality match on a login attribute, and
// occasionally an AND of that with an objectClass.
type filter struct {
	Kind     filterKind
	Attr     string
	Value    string
	Children []*filter
}

type filterKind int

const (
	filterAnd filterKind = iota
	filterOr
	filterNot
	filterEquality
	filterPresent
	// filterUnsupported is returned rather than an error so a search carrying a
	// construct we do not implement can be answered with an empty result set
	// instead of a protocol error. Applications probe with odd filters, and a
	// protocol error tends to abort the whole connection.
	filterUnsupported
)

// Filter tags (RFC 4511 §4.5.1.7).
const (
	filterTagAnd       = 0
	filterTagOr        = 1
	filterTagNot       = 2
	filterTagEquality  = 3
	filterTagSubstring = 4
	filterTagPresent   = 7
)

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

	case filterTagEquality:
		if len(p.Children) != 2 {
			return &filter{Kind: filterUnsupported}, nil
		}
		attr := string(p.Children[0].Data.Bytes())
		val := string(p.Children[1].Data.Bytes())
		return &filter{Kind: filterEquality, Attr: attr, Value: val}, nil

	case filterTagPresent:
		return &filter{Kind: filterPresent, Attr: string(p.Data.Bytes())}, nil

	default:
		return &filter{Kind: filterUnsupported}, nil
	}
}

// entry is one directory entry we return.
type entry struct {
	DN    string
	Attrs map[string][]string
}

// Matches evaluates a filter against an entry.
//
// Attribute names are compared case-insensitively, because LDAP attribute
// descriptions are case-insensitive and clients send every variation of `uid`,
// `uID` and `UID` that you can imagine.
func (f *filter) Matches(e *entry) bool {
	if f == nil {
		return true
	}
	switch f.Kind {
	case filterAnd:
		for _, c := range f.Children {
			if !c.Matches(e) {
				return false
			}
		}
		return true
	case filterOr:
		for _, c := range f.Children {
			if c.Matches(e) {
				return true
			}
		}
		return false
	case filterNot:
		return len(f.Children) == 1 && !f.Children[0].Matches(e)
	case filterEquality:
		for _, v := range attrValues(e, f.Attr) {
			if equalFold(v, f.Value) {
				return true
			}
		}
		return false
	case filterPresent:
		return len(attrValues(e, f.Attr)) > 0
	default:
		// An unsupported construct matches nothing, so the search returns an
		// empty result rather than everything. Failing open here would answer a
		// filter we did not understand with the entire directory.
		return false
	}
}

func attrValues(e *entry, attr string) []string {
	for k, v := range e.Attrs {
		if equalFold(k, attr) {
			return v
		}
	}
	return nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// --- encoding ---------------------------------------------------------------

func newMessage(messageID int64, op *ber.Packet) *ber.Packet {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	m.AppendChild(op)
	return m
}

// newResult builds an LDAPResult-bearing response.
//
// The diagnostic message is chosen by the caller and is deliberately vague on
// authentication failures -- see the note on bind handling. Anywhere else it is
// as specific as possible, because an operator debugging a client that will not
// connect has nothing else to go on.
func newResult(app ber.Tag, code int64, matchedDN, diagnostic string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, matchedDN, "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))
	return p
}

// newSearchEntry builds a SearchResultEntry.
func newSearchEntry(e *entry, requested []string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultEntry, nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, values := range e.Attrs {
		if !attrRequested(name, requested) {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range values {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		}
		a.AppendChild(vals)
		attrs.AppendChild(a)
	}
	p.AppendChild(attrs)
	return p
}

// attrRequested implements the attribute selection rules.
//
// An empty list means "all user attributes"; "*" means the same; "1.1" means
// none. Getting this wrong in the permissive direction returns attributes a
// client never asked for, which for a directory is a disclosure rather than a
// convenience.
func attrRequested(name string, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, r := range requested {
		switch {
		case r == "1.1":
			return false
		case r == "*":
			return true
		case equalFold(r, name):
			return true
		}
	}
	return false
}
