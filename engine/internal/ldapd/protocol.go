// Package ldapd is an LDAP front end for applications that can only
// authenticate by binding to a directory.
//
// # What this is, and what it deliberately is not
//
// It is a COMPATIBILITY SHIM that answers bind and search, so that software
// written against a directory can authenticate people who live in Signari.
//
// Since August 2026 it can also be WRITTEN to: Add, Modify, Delete and Modify
// DN (RFC 4511 §4.6–§4.9), against an explicit schema in schema.go. That is off
// by default and needs two decisions to turn on -- a Writer, and a group naming
// who may use it -- because a directory that can be written to is a much larger
// surface than one that cannot, and because the LDAP outpost has no write path
// back to the engine at all. See write.go.
//
// It is still not a directory. There is no replication, no DIT structure rules,
// no aliases, no subordinate entries: the tree is flat
// and holds `person` entries. Everything outside that is refused rather than
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
//
// The write codes are as specific as the specification allows, because a
// directory client acts on them. `entryAlreadyExists` tells a provisioning run
// to move on; `constraintViolation` tells it to fix the data; `notAllowedOnRDN`
// tells it to use Modify DN instead. Collapsing all of them to
// unwillingToPerform -- which is what a shim reaching for one code does -- turns
// every one of those into "something went wrong, try again forever".
const (
	resultSuccess                = 0
	resultProtocolError          = 2
	resultTimeLimitExceeded      = 3
	resultSizeLimitExceeded      = 4
	resultAuthMethodNotSupported = 7
	resultAdminLimitExceeded     = 11
	// A critical control this server does not apply. RFC 4511 §4.1.11,
	// specs/rfc4511.txt:766-771: such an operation MUST NOT be performed.
	resultUnavailableCriticalExtension = 12
	resultNoSuchAttribute              = 16
	resultUndefinedAttributeType       = 17
	resultConstraintViolation          = 19
	resultAttributeOrValueExists       = 20
	resultNoSuchObject                 = 32
	resultInvalidDNSyntax              = 34
	resultInvalidCredentials           = 49
	resultInsufficientAccess           = 50
	// "Indicates that the server is too busy to service the operation."
	// RFC 4511 s4.1.9, specs/rfc4511.txt:2904.
	resultBusy                      = 51
	resultUnwillingToPerform        = 53
	resultNamingViolation           = 64
	resultObjectClassViolation      = 65
	resultNotAllowedOnNonLeaf       = 66
	resultNotAllowedOnRDN           = 67
	resultEntryAlreadyExists        = 68
	resultObjectClassModsProhibited = 69
	resultOther                     = 80
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

	// TimeLimit is §4.5.1.5: "A time limit that restricts the maximum time (in
	// seconds) allowed for a Search. A value of zero in this field indicates
	// that no client-requested time limit restrictions are in effect."
	TimeLimit int

	// TypesOnly is §4.5.1.6: "Setting this field to TRUE causes only attribute
	// descriptions (and not values) to be returned."
	//
	// Read rather than ignored because ignoring it means answering with values
	// the client explicitly asked not to receive -- every name and mail address
	// this shim exposes, sent to a caller that wanted the schema. For a directory
	// whose whole posture is to return less than it could, silently returning
	// more than was asked for is the wrong way round.
	TypesOnly bool
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
	timeLimit, _ := op.Children[4].Value.(int64)
	typesOnly, _ := op.Children[5].Value.(bool)

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
		TimeLimit: int(timeLimit), TypesOnly: typesOnly,
		Filter: f, Attrs: attrs,
	}, nil
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

// oidPagedResults is RFC 2696's control. Its value is a BER SEQUENCE of a size
// and an opaque cookie, in both directions.
const oidPagedResults = "1.2.840.113556.1.4.319"

// pagedResults is that control on a request.
type pagedResults struct {
	size   int
	cookie string
}

// pagedResultsOf finds the control among an LDAPMessage's controls.
func pagedResultsOf(controls *ber.Packet) (*pagedResults, error) {
	if controls == nil {
		return nil, nil
	}
	for _, ctl := range controls.Children {
		if len(ctl.Children) == 0 || ber.DecodeString(ctl.Children[0].Data.Bytes()) != oidPagedResults {
			continue
		}
		// The value is the last child: the criticality before it is optional.
		value := ctl.Children[len(ctl.Children)-1]
		if len(ctl.Children) < 2 || value.Tag != ber.TagOctetString {
			return nil, fmt.Errorf("the paged results control has no value")
		}
		seq, err := ber.DecodePacketErr(value.Data.Bytes())
		if err != nil {
			return nil, err
		}
		if len(seq.Children) != 2 {
			return nil, fmt.Errorf("the paged results value has %d fields, expected 2", len(seq.Children))
		}
		size, ok := seq.Children[0].Value.(int64)
		if !ok || size < 0 {
			return nil, fmt.Errorf("the paged results size is not a size")
		}
		return &pagedResults{size: int(size), cookie: string(seq.Children[1].Data.Bytes())}, nil
	}
	return nil, nil
}

// pagedDone is a SearchResultDone carrying the control back: the cookie to send
// for the next page, empty when there is none. The estimate of the total stays
// zero, which means it is not known; counting would read everybody.
func pagedDone(messageID, code int64, cookie string) *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "size"))
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, "cookie"))
	value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "controlValue")
	value.Data.Write(seq.Bytes())

	ctl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	ctl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oidPagedResults, "controlType"))
	ctl.AppendChild(value)
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	controls.AppendChild(ctl)

	m := newMessage(messageID, newResult(appSearchResultDone, code, "", ""))
	m.AppendChild(controls)
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
func newSearchEntry(e *entry, requested []string, typesOnly bool) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultEntry, nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, values := range e.Attrs {
		if !attrRequested(name, requested) {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		// §4.5.1.6: TRUE yields descriptions and no values. The attribute is still
		// present -- the client asked which attributes exist, and an entry with
		// the attribute omitted answers a different question -- but its value set
		// is empty.
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		if !typesOnly {
			for _, v := range values {
				vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
			}
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
