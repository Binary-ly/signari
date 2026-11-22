package store

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"signari.dev/engine/internal/scim"
)

// A SCIM list filter as a condition on the link tables, in SQL so that a page
// and its totalResults are of what matched. Filtering a page in memory would
// report the collection's size for a page of matches.
//
// # What can be asked about
//
// What /Schemas publishes and the two resources return, each named here. RFC 7644
// Table 9 (specs/rfc7644.txt:3821) has invalidFilter for "the specified attribute
// and filter comparison combination is not supported", and that is the answer to
// anything else: an unknown attribute read as absent would make
// `not (nickName eq "x")` match everybody, and an upstream that reads a page to
// decide whether to create somebody acts on the answer.
//
// # Every condition is true or false, never NULL
//
// The one nullable attribute is the address. A NULL would make `not (...)` drop
// the person with no address, who is exactly who it describes, so a comparison
// with an absent value is settled here: not equal, and matching nothing else.

// ErrSCIMFilter is a well-formed filter this server cannot answer.
var ErrSCIMFilter = errors.New("scim filter")

type scimAttrKind int

const (
	// scimFolded compares without regard to case: caseExact false in /Schemas.
	scimFolded scimAttrKind = iota
	// scimExact compares as stored: an upstream's identifiers are opaque.
	scimExact
	// scimFoldColumn is scimFolded over a column that holds the fold already,
	// which the people table does so that a lookup can use an index under row
	// security (migration 0199).
	scimFoldColumn
	scimBoolean
	scimDateTime
	scimResourceID
	// scimComplex is a multi-valued attribute named whole, which RFC 7644 says
	// only `pr` can ask about (specs/rfc7644.txt:1197, a sub-attribute MUST be
	// specified). sql says whether it has a value.
	scimComplex
	// scimMemberValue is a member's resource id, one of many: eq asks whether any
	// member is this one, the rule for a multi-valued attribute. sql is the
	// members, and is continued with a condition.
	scimMemberValue
)

type scimAttr struct {
	sql      string
	kind     scimAttrKind
	nullable bool
	// person says sql reads core.users, which only then joins the page.
	person bool
}

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:user"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:group"

	scimGroupMembers = `SELECT 1 FROM core.group_members gm
		JOIN core.scim_source_links m ON m.source_id = l.source_id AND m.user_id = gm.user_id
		WHERE gm.group_id = l.group_id`
)

var scimUserAttrs = map[string]scimAttr{
	"id":                {sql: "l.resource_id", kind: scimResourceID},
	"externalid":        {sql: "l.external_id", kind: scimExact},
	"username":          {sql: "l.user_name", kind: scimFolded},
	"displayname":       {sql: "l.display_name", kind: scimFolded},
	"active":            {sql: "u.status = 'active'", kind: scimBoolean, person: true},
	"emails":            {sql: "COALESCE(u.email_fold, '') <> ''", kind: scimComplex, person: true},
	"emails.value":      {sql: "u.email_fold", kind: scimFoldColumn, nullable: true, person: true},
	"meta.created":      {sql: "l.created_at", kind: scimDateTime},
	"meta.lastmodified": {sql: "l.updated_at", kind: scimDateTime},
}

var scimGroupAttrs = map[string]scimAttr{
	"id":                {sql: "l.resource_id", kind: scimResourceID},
	"externalid":        {sql: "l.external_id", kind: scimExact},
	"displayname":       {sql: "l.display_name", kind: scimFolded},
	"members":           {sql: "EXISTS (" + scimGroupMembers + ")", kind: scimComplex},
	"members.value":     {sql: scimGroupMembers, kind: scimMemberValue},
	"meta.created":      {sql: "l.created_at", kind: scimDateTime},
	"meta.lastmodified": {sql: "l.updated_at", kind: scimDateTime},
}

// scimCondition is what a filter became: where over the alias l, its arguments
// numbered from the first it was given, and whether it needs core.users as u.
type scimCondition struct {
	where  string
	args   []any
	person bool
}

func scimFilterSQL(f *scim.Filter, attrs map[string]scimAttr, schema string, first int) (scimCondition, error) {
	if f == nil {
		return scimCondition{where: "TRUE"}, nil
	}
	b := &scimFilterBuilder{attrs: attrs, schema: schema + ":", first: first}
	where, err := b.condition(f)
	if err != nil {
		return scimCondition{}, fmt.Errorf("%w: %w", ErrSCIMFilter, err)
	}
	return scimCondition{where: where, args: b.args, person: b.person}, nil
}

type scimFilterBuilder struct {
	attrs  map[string]scimAttr
	schema string
	first  int
	args   []any
	person bool
}

func (b *scimFilterBuilder) arg(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(b.first+len(b.args)-1)
}

func (b *scimFilterBuilder) condition(f *scim.Filter) (string, error) {
	switch f.Op {
	case "and", "or":
		left, err := b.condition(f.Left)
		if err != nil {
			return "", err
		}
		right, err := b.condition(f.Right)
		if err != nil {
			return "", err
		}
		return "(" + left + " " + strings.ToUpper(f.Op) + " " + right + ")", nil
	case "not":
		inner, err := b.condition(f.Left)
		if err != nil {
			return "", err
		}
		return "NOT (" + inner + ")", nil
	}

	// An attribute may be written with its schema (Figure 1's attrPath).
	name := strings.TrimPrefix(f.Attr, b.schema)
	a, ok := b.attrs[name]
	if !ok {
		return "", fmt.Errorf("%q cannot be filtered on", f.Attr)
	}
	b.person = b.person || a.person

	switch {
	case f.Op == "pr":
		return a.present(), nil
	case f.Value == nil && f.Op == "eq":
		return "NOT (" + a.present() + ")", nil
	case f.Value == nil && f.Op == "ne":
		return a.present(), nil
	}
	switch a.kind {
	case scimFolded, scimExact, scimFoldColumn:
		return b.text(a, f)
	case scimBoolean:
		return b.boolean(a, f)
	case scimDateTime:
		return b.dateTime(a, f)
	case scimResourceID:
		return b.resourceID(a, f)
	case scimMemberValue:
		return b.member(a, f)
	}
	return "", fmt.Errorf("%q can only be asked `pr`: name a sub-attribute to compare", f.Attr)
}

// present is `pr`: "a non-empty or non-null value" (specs/rfc7644.txt:987).
func (a scimAttr) present() string {
	switch a.kind {
	case scimFolded, scimExact, scimFoldColumn:
		return "COALESCE(" + a.sql + ", '') <> ''"
	case scimComplex:
		return a.sql
	case scimMemberValue:
		return "EXISTS (" + a.sql + ")"
	}
	return "TRUE"
}

func (b *scimFilterBuilder) text(a scimAttr, f *scim.Filter) (string, error) {
	want, ok := f.Value.(string)
	if !ok {
		return "", fmt.Errorf("%q is a string, compared with %v", f.Attr, f.Value)
	}
	lhs, rhs := a.sql, b.arg(want)+"::text"
	switch a.kind {
	case scimFolded:
		lhs, rhs = "lower("+lhs+")", "lower("+rhs+")"
	case scimFoldColumn:
		rhs = "lower(" + rhs + ")"
	}
	// strpos and starts_with, not LIKE: a value's `%` is a percent sign.
	// "C" for the order, which is "a lexicographical comparison" (Table 3) and
	// not whatever the database's locale makes of one.
	var cmp string
	switch f.Op {
	case "eq":
		cmp = lhs + " = " + rhs
	case "ne":
		cmp = lhs + " <> " + rhs
	case "co":
		cmp = "strpos(" + lhs + ", " + rhs + ") > 0"
	case "sw":
		cmp = "starts_with(" + lhs + ", " + rhs + ")"
	case "ew":
		cmp = "right(" + lhs + ", char_length(" + rhs + ")) = " + rhs
	case "gt":
		cmp = lhs + ` COLLATE "C" > ` + rhs
	case "ge":
		cmp = lhs + ` COLLATE "C" >= ` + rhs
	case "lt":
		cmp = lhs + ` COLLATE "C" < ` + rhs
	case "le":
		cmp = lhs + ` COLLATE "C" <= ` + rhs
	default:
		return "", fmt.Errorf("the operator %q is not supported", f.Op)
	}
	switch {
	case !a.nullable:
		return cmp, nil
	case f.Op == "ne":
		return "COALESCE(" + cmp + ", TRUE)", nil
	}
	return "COALESCE(" + cmp + ", FALSE)", nil
}

// boolean takes eq and ne. Table 3 has gt and its kin refused for a Boolean, and
// nothing else in it can mean anything for one.
func (b *scimFilterBuilder) boolean(a scimAttr, f *scim.Filter) (string, error) {
	want, ok := f.Value.(bool)
	if !ok {
		return "", fmt.Errorf("%q is a boolean, compared with %v", f.Attr, f.Value)
	}
	switch f.Op {
	case "eq":
		return "(" + a.sql + ") = " + b.arg(want) + "::boolean", nil
	case "ne":
		return "(" + a.sql + ") <> " + b.arg(want) + "::boolean", nil
	}
	return "", fmt.Errorf("%q is a boolean, and %s cannot compare one", f.Attr, f.Op)
}

// dateTime compares to the second, which is what a resource's meta shows: a
// client handed 12:00:05 by `meta.lastModified` would otherwise find that
// `eq "...12:00:05Z"` matches nothing, the column holding microseconds.
func (b *scimFilterBuilder) dateTime(a scimAttr, f *scim.Filter) (string, error) {
	s, ok := f.Value.(string)
	if !ok {
		return "", fmt.Errorf("%q is a time, compared with %v", f.Attr, f.Value)
	}
	want, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("%q is not a time as RFC 3339 writes one", s)
	}
	op, ok := map[string]string{"eq": "=", "ne": "<>", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[f.Op]
	if !ok {
		return "", fmt.Errorf("%q is a time, and %s cannot compare one", f.Attr, f.Op)
	}
	return "date_trunc('second', " + a.sql + ") " + op + " " + b.arg(want) + "::timestamptz", nil
}

// resourceID compares ids this server issued. One that is not a uuid is an id of
// nothing, which is an answer rather than a mistake: an upstream may hold ids
// from somewhere else, and asked is told none match.
func (b *scimFilterBuilder) resourceID(a scimAttr, f *scim.Filter) (string, error) {
	s, ok := f.Value.(string)
	if !ok {
		return "", fmt.Errorf("%q is a string, compared with %v", f.Attr, f.Value)
	}
	id, err := uuid.Parse(s)
	switch f.Op {
	case "eq":
		if err != nil {
			return "FALSE", nil
		}
		return a.sql + " = " + b.arg(id.String()) + "::uuid", nil
	case "ne":
		if err != nil {
			return "TRUE", nil
		}
		return a.sql + " <> " + b.arg(id.String()) + "::uuid", nil
	}
	return "", fmt.Errorf("%q is an id, and %s cannot compare one", f.Attr, f.Op)
}

func (b *scimFilterBuilder) member(a scimAttr, f *scim.Filter) (string, error) {
	s, ok := f.Value.(string)
	if !ok || f.Op != "eq" {
		return "", fmt.Errorf("%q can be asked `eq` with an id, or `pr`", f.Attr)
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return "FALSE", nil
	}
	return "EXISTS (" + a.sql + " AND m.resource_id = " + b.arg(id.String()) + "::uuid)", nil
}
