// Package rar implements RFC 9396, OAuth 2.0 Rich Authorization Requests.
//
// # What it is for
//
// `scope` is a list of bare strings, so everything an API needs to say about a
// permission has to be encoded into one of them. That works until a permission
// has structure — "move £500 from this account to that one", "sign this
// document", "issue this credential" — at which point deployments invent
// `payment:500:GB123:GB456` and every party has to agree on how to split it.
//
// `authorization_details` gives the permission a shape: a JSON array of typed
// objects, each naming what may be done, where, and to what.
//
// # The rule that makes this different from every other parser here
//
// §5 requires the authorization server to REFUSE an object "of known type but
// containing unknown fields". That is the opposite of the forward-compatibility
// rule this codebase follows elsewhere — AuthZEN §10.1.1 makes ignoring unknown
// fields a MUST, and internal/authzen does exactly that.
//
// The difference is what the fields MEAN. An unknown field in an authorization
// query is a hint the decision did not need. An unknown field in an
// authorization DETAIL is a permission: ignoring it either grants access the
// resource owner never saw on the consent screen, or withholds one the client
// believes it obtained. Neither failure is visible to anybody at the time.
//
// So: unknown type, unknown field, wrong field type, missing required field —
// each is `invalid_authorization_details`, and each aborts the request.
package rar

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"signari.dev/engine/internal/jsonstrict"
)

// Param is the request and response parameter name.
const Param = "authorization_details"

// ErrorCode is the error §5 requires for every rejection here.
const ErrorCode = "invalid_authorization_details"

// Common data fields, §2.2. A deployment declares which of these a type uses;
// anything outside the declared set is an unknown field and is refused.
const (
	FieldLocations  = "locations"
	FieldActions    = "actions"
	FieldDatatypes  = "datatypes"
	FieldIdentifier = "identifier"
	FieldPrivileges = "privileges"
)

// arrayFields are the common fields whose value is an array of strings.
// `identifier` is the one scalar, which is why it is listed separately rather
// than being special-cased at each use.
var arrayFields = map[string]bool{
	FieldLocations: true, FieldActions: true, FieldDatatypes: true, FieldPrivileges: true,
}

func knownField(name string) bool {
	return arrayFields[name] || name == FieldIdentifier
}

// Detail is one authorization details object.
type Detail struct {
	// Type is §2's `type`, the only REQUIRED field. "The value of the type field
	// determines the allowable contents of the object that contains it."
	Type string `json:"type"`

	Locations  []string `json:"locations,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Datatypes  []string `json:"datatypes,omitempty"`
	Identifier string   `json:"identifier,omitempty"`
	Privileges []string `json:"privileges,omitempty"`
}

// TypeSpec is what a deployment has registered about one authorization details
// type: which of the common data fields it uses, and which of those are
// required.
//
// §10 says "The registration of authorization details types with the AS is
// outside the scope of this specification", so this is our shape for it. It is
// deliberately a declaration of FIELDS rather than a schema: the values are
// "determined by the API being protected" (§2.2), which is not something this
// server can check, and pretending otherwise would be a validation that looks
// stricter than it is.
type TypeSpec struct {
	Type string
	// Fields are the common data fields this type permits.
	Fields []string
	// Required are the fields that must be present. A subset of Fields.
	Required []string
}

func (s TypeSpec) permits(field string) bool {
	for _, f := range s.Fields {
		if f == field {
			return true
		}
	}
	return false
}

// Registry maps a type identifier to what the deployment registered for it.
type Registry map[string]TypeSpec

// Types returns the registered type identifiers, sorted.
//
// Sorted because this feeds `authorization_details_types_supported` in the
// discovery document, and a metadata document whose array reorders between
// requests is one that breaks any client comparing it against a cached copy.
func (r Registry) Types() []string {
	out := make([]string, 0, len(r))
	for t := range r {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Error is a rejection carrying §5's error code.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

func fail(format string, args ...any) *Error {
	return &Error{Reason: fmt.Sprintf(format, args...)}
}

// Parse reads the `authorization_details` parameter.
//
// Returns the parsed details and the raw objects, because §5's unknown-field
// rule cannot be enforced after unmarshalling into a struct: the unknown field
// is exactly the one the struct discards.
func Parse(raw string) ([]Detail, []map[string]json.RawMessage, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil, nil
	}
	// Duplicate members first, for the reason internal/jsonstrict documents: a
	// document whose meaning depends on the parser cannot be authorized, and
	// these objects are permissions.
	if err := jsonstrict.NoDuplicateKeys([]byte(raw)); err != nil {
		return nil, nil, fail("authorization_details: %v", err)
	}

	var objs []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &objs); err != nil {
		// §2: the parameter is a JSON ARRAY. A single object is the common
		// mistake and is worth naming, because "invalid JSON" sends the caller
		// looking for a syntax error that is not there.
		var single map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &single) == nil {
			return nil, nil, fail("authorization_details must be a JSON array of " +
				"objects, and this is a single object; wrap it in [ ]")
		}
		return nil, nil, fail("authorization_details is not a JSON array: %v", err)
	}
	if len(objs) == 0 {
		// An empty array is a request for no rich permissions, which is
		// indistinguishable from omitting the parameter -- and treating it as
		// "grant nothing" silently would let a client believe it asked for
		// something.
		return nil, nil, fail("authorization_details is an empty array; omit the " +
			"parameter entirely if no rich permissions are being requested")
	}

	details := make([]Detail, 0, len(objs))
	for i, obj := range objs {
		d, err := decodeDetail(obj)
		if err != nil {
			return nil, nil, fail("authorization_details[%d]: %v", i, err)
		}
		details = append(details, d)
	}
	return details, objs, nil
}

// decodeDetail reads one object field by field, LENIENTLY.
//
// A field whose JSON type is wrong is left at its zero value rather than
// aborting the decode, because §5 wants that reported as
// `invalid_authorization_details` naming the field — and a whole-struct
// unmarshal fails with Go's own message instead, which says "cannot unmarshal
// array into Go struct field Detail.identifier of type string" to somebody
// debugging a payment API.
//
// Validate re-reads the same raw objects and produces the proper error, so
// nothing is accepted that this leniency skipped past; the leniency only decides
// WHICH layer reports it.
func decodeDetail(obj map[string]json.RawMessage) (Detail, error) {
	var d Detail
	if raw, ok := obj["type"]; ok {
		// The type is decoded strictly: everything downstream keys off it, and a
		// non-string type cannot be looked up in the registry at all.
		if err := json.Unmarshal(raw, &d.Type); err != nil {
			return d, fmt.Errorf("type must be a string")
		}
	}
	_ = json.Unmarshal(obj[FieldLocations], &d.Locations)
	_ = json.Unmarshal(obj[FieldActions], &d.Actions)
	_ = json.Unmarshal(obj[FieldDatatypes], &d.Datatypes)
	_ = json.Unmarshal(obj[FieldPrivileges], &d.Privileges)
	_ = json.Unmarshal(obj[FieldIdentifier], &d.Identifier)
	return d, nil
}

// Validate applies §5 against the registered types.
//
// Every one of §5's five conditions, in the order the specification lists them,
// because an implementation that checks four of them refuses four kinds of bad
// request and grants the fifth.
func Validate(details []Detail, objs []map[string]json.RawMessage, reg Registry) error {
	for i := range details {
		d, obj := details[i], objs[i]

		// §2: "This field is REQUIRED."
		if strings.TrimSpace(d.Type) == "" {
			return fail("authorization_details[%d] has no type", i)
		}
		// §5: "contains an unknown authorization details type value"
		spec, known := reg[d.Type]
		if !known {
			return fail("authorization_details[%d] has type %q, which this server "+
				"does not know; registered types are %s",
				i, d.Type, strings.Join(reg.Types(), ", "))
		}

		for _, name := range sortedNames(obj) {
			if name == "type" {
				continue
			}
			// §5: "is an object of known type but containing unknown fields"
			//
			// Both halves: a field this server has never heard of, and a field it
			// knows about that this TYPE did not register. The second is the one
			// that matters -- `actions` on a type that grants by `privileges` is a
			// permission nobody will read.
			if !knownField(name) {
				return fail("authorization_details[%d] of type %q contains the "+
					"unknown field %q", i, d.Type, name)
			}
			if !spec.permits(name) {
				return fail("authorization_details[%d] of type %q contains the field "+
					"%q, which that type does not use; it would be carried and never "+
					"read", i, d.Type, name)
			}
			// §5: "contains fields of the wrong type"
			if err := checkFieldType(name, obj[name]); err != nil {
				return fail("authorization_details[%d] of type %q: %v", i, d.Type, err)
			}
		}

		// §5: "is missing required fields for the authorization details type"
		for _, req := range spec.Required {
			if !present(obj, req) {
				return fail("authorization_details[%d] of type %q is missing the "+
					"required field %q", i, d.Type, req)
			}
		}

		// §5: "contains fields with invalid values". What is checkable without
		// knowing the API is emptiness: an empty string in an actions array is
		// not an action, and an empty identifier identifies nothing.
		if err := checkValues(d); err != nil {
			return fail("authorization_details[%d] of type %q: %v", i, d.Type, err)
		}
	}
	return nil
}

func present(obj map[string]json.RawMessage, field string) bool {
	raw, ok := obj[field]
	return ok && len(raw) > 0 && string(raw) != "null"
}

func checkFieldType(name string, raw json.RawMessage) error {
	if arrayFields[name] {
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("%s must be an array of strings", name)
		}
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("%s must be a string", name)
	}
	return nil
}

func checkValues(d Detail) error {
	for _, pair := range []struct {
		name string
		vals []string
	}{
		{FieldLocations, d.Locations}, {FieldActions, d.Actions},
		{FieldDatatypes, d.Datatypes}, {FieldPrivileges, d.Privileges},
	} {
		for _, v := range pair.vals {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("%s contains an empty value", pair.name)
			}
		}
	}
	return nil
}

func sortedNames(obj map[string]json.RawMessage) []string {
	out := make([]string, 0, len(obj))
	for k := range obj {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Narrow applies §6: a token request may ask for LESS than was granted.
//
//	"The AS checks whether the underlying grant ... allows the issuance of an
//	access token with the requested authorization details. Otherwise, the AS
//	refuses the request with the error code invalid_authorization_details."
//
// §6.1 is explicit that there is no standard comparison — "the semantics of the
// fields in the authorization_details will be implementation specific" and "an
// AS should not rely on simple object comparison in most cases".
//
// So this implements the one comparison that is safe without knowing the API:
// **subset**. A requested detail is allowed when a granted detail of the same
// type contains every one of its values, field by field. That can only ever
// narrow, never widen, which is the property §6 is protecting. Anything
// cleverer would be this server guessing at semantics it was told it does not
// have.
func Narrow(granted, requested []Detail) ([]Detail, error) {
	if len(requested) == 0 {
		return granted, nil
	}
	out := make([]Detail, 0, len(requested))
	for i, want := range requested {
		ok := false
		for _, have := range granted {
			if have.Type != want.Type {
				continue
			}
			if covers(have, want) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fail("authorization_details[%d] of type %q asks for more "+
				"than this grant authorized", i, want.Type)
		}
		out = append(out, want)
	}
	return out, nil
}

// covers reports whether `have` permits everything `want` asks for.
func covers(have, want Detail) bool {
	if want.Identifier != "" && want.Identifier != have.Identifier {
		return false
	}
	return subset(want.Locations, have.Locations) &&
		subset(want.Actions, have.Actions) &&
		subset(want.Datatypes, have.Datatypes) &&
		subset(want.Privileges, have.Privileges)
}

func subset(want, have []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// FilterByAudience implements §9.1's "filtered to the specific audience".
//
// §2.2 defines `locations` as "the location of the resource server", so it is
// the only field that can answer "does this permission concern the RS this
// token is for?" without knowing the API.
//
// Two rules, and the second is the one that matters:
//
//  1. A detail whose `locations` names one of the audiences is included.
//  2. A detail with NO `locations` is included for every audience.
//
// Rule 2 is not a convenience. §2.2 makes `locations` OPTIONAL, so its absence
// means "unspecified", not "applies nowhere". Treating an absent location as an
// empty one would silently drop the constraint from the token — and an RS that
// receives no details where it expected some has no way to tell "this grant was
// unconstrained" from "the constraint was filtered out on the way here". The
// failure would look like a widened permission and read like a missing field.
//
// Filtering is RECOMMENDED rather than required, and it exists to stop one
// resource server learning the details of a permission granted for another.
func FilterByAudience(details []Detail, audience []string) []Detail {
	if len(details) == 0 {
		return nil
	}
	aud := make(map[string]bool, len(audience))
	for _, a := range audience {
		aud[a] = true
	}
	out := make([]Detail, 0, len(details))
	for _, d := range details {
		if len(d.Locations) == 0 {
			out = append(out, d)
			continue
		}
		for _, loc := range d.Locations {
			if aud[loc] {
				out = append(out, d)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
