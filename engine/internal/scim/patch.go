package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PATCH, which is where every SCIM implementation goes wrong.
//
// RFC 7644 §3.5.2 defines a small operation language, and the two upstreams
// that matter emit different dialects of it. An implementation that handles
// only the dialect it was tested against silently ignores the other one --
// silently, because a PATCH that changes nothing still returns 200 and the
// upstream records a successful sync.
//
// The differences that bite, all seen in the wild:
//
//	{"op":"replace","path":"active","value":false}          the tidy form
//	{"op":"replace","value":{"active":false}}               Entra, no path
//	{"op":"Replace",...}                                    Entra, capitalised
//	{"op":"replace","path":"active","value":"False"}        Entra, STRING
//	{"op":"replace","path":"name.givenName","value":"Al"}   a sub-attribute
//	{"op":"replace","path":"emails[type eq \"work\"].value"} a filtered path
//
// The string "False" is the one that causes real damage. Parsed with the
// ordinary rules of most languages, a non-empty string is true, so a
// deactivation arrives and is applied as an ACTIVATION: the person who just
// left the company keeps their account, and the upstream shows a green tick.

// PatchOp is one operation in a PATCH request.
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// PatchRequest is the body of a SCIM PATCH.
type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

// UserPatch is the subset of changes this engine acts on.
//
// Pointers so "not mentioned" and "set to the zero value" stay distinct. A
// PATCH that only changes a display name must not clear the address, and a
// struct of plain values cannot express the difference.
type UserPatch struct {
	Active      *bool
	UserName    *string
	DisplayName *string
	Email       *string
	// Unsupported lists paths that were understood as paths but are not acted
	// on, so a caller can report them rather than pretend.
	Unsupported []string
}

// ApplyUserPatch reads a PATCH body into the changes it implies.
//
// Unknown operations are an ERROR, not a no-op. A silently ignored PATCH is
// reported to the upstream as success, and the upstream then believes a
// deactivation took effect.
func ApplyUserPatch(req PatchRequest) (*UserPatch, error) {
	if len(req.Operations) == 0 {
		return nil, fmt.Errorf("PATCH with no operations")
	}

	out := &UserPatch{}
	for i, op := range req.Operations {
		// Case-insensitive: Entra capitalises. The RFC says these are the three
		// values; it does not say they are case sensitive, and being strict here
		// achieves nothing except breaking a real client.
		switch strings.ToLower(strings.TrimSpace(op.Op)) {
		case "replace", "add":
			if err := applyAssign(out, op); err != nil {
				return nil, fmt.Errorf("operation %d: %w", i, err)
			}
		case "remove":
			if err := applyRemove(out, op); err != nil {
				return nil, fmt.Errorf("operation %d: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("operation %d: unknown op %q", i, op.Op)
		}
	}
	return out, nil
}

// applyAssign handles replace and add, which differ only for multi-valued
// attributes this engine does not store.
func applyAssign(out *UserPatch, op PatchOp) error {
	path := normalisePath(op.Path)

	// No path: the value is an object of attributes to merge. Entra's usual
	// shape, and the one an implementation written from the RFC's examples
	// alone tends to miss.
	if path == "" {
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &attrs); err != nil {
			return fmt.Errorf("a pathless operation needs an object value: %w", err)
		}
		for k, v := range attrs {
			if err := assignOne(out, normalisePath(k), v); err != nil {
				return err
			}
		}
		return nil
	}
	return assignOne(out, path, op.Value)
}

func assignOne(out *UserPatch, path string, raw json.RawMessage) error {
	switch path {
	case "active":
		b, err := parseSCIMBool(raw)
		if err != nil {
			return err
		}
		out.Active = &b

	case "username":
		s, err := parseSCIMString(raw)
		if err != nil {
			return err
		}
		out.UserName = &s

	case "displayname":
		s, err := parseSCIMString(raw)
		if err != nil {
			return err
		}
		out.DisplayName = &s

	case "name.formatted":
		s, err := parseSCIMString(raw)
		if err != nil {
			return err
		}
		// Only if displayName was not also given: displayName is the more
		// specific statement of the two.
		if out.DisplayName == nil {
			out.DisplayName = &s
		}

	case "emails", "emails.value":
		s, err := parseEmailValue(raw)
		if err != nil {
			return err
		}
		out.Email = &s

	default:
		return assignFiltered(out, path, raw)
	}
	return nil
}

func assignFiltered(out *UserPatch, path string, raw json.RawMessage) error {
	p, err := ParsePath(path)
	if err != nil {
		// An unparseable path is NOT recorded as unsupported. We cannot say what
		// it asked for, so we cannot say it was irrelevant either.
		return fmt.Errorf("path %q: %w", path, err)
	}
	if p.Filter == nil || p.Attr != "emails" {
		// A path we simply do not store — `phoneNumbers`, `addresses`, an
		// extension attribute. Recorded rather than refused: the same operation
		// may have changed something we DID apply, and failing the whole request
		// would block a sync over an attribute nobody here uses.
		out.Unsupported = append(out.Unsupported, path)
		return nil
	}

	// One email is stored, and it is the primary one. A filter selecting the
	// primary or work address is therefore addressing the value we keep.
	if p.Sub != "" && p.Sub != "value" {
		out.Unsupported = append(out.Unsupported, path)
		return nil
	}
	if !selectsStoredEmail(p.Filter) {
		// The filter names an address we do not keep — `type eq "home"` when the
		// stored value is the primary. Refused rather than recorded, because
		// applying it would overwrite the primary with a home address and
		// recording it would drop a change the upstream believes it made.
		// Neither is silent; this one at least gets retried.
		return fmt.Errorf("path %q selects an email address this server does not "+
			"store separately: only the primary address is kept, so a change to "+
			"another one cannot be represented", path)
	}
	s, err := parseEmailValue(raw)
	if err != nil {
		return err
	}
	out.Email = &s
	return nil
}

// selectsStoredEmail reports whether a filter picks the address we keep.
//
// Evaluated by running the filter against the record we would store, rather than
// by pattern-matching the filter's text. A filter is a predicate; asking it
// about the actual value is what it is for, and it makes `primary eq true and
// type eq "work"` work without enumerating the combinations.
func selectsStoredEmail(f *Filter) bool {
	stored := map[string]any{"primary": true, "type": "work"}
	return f.Matches(stored)
}

func applyRemove(out *UserPatch, op PatchOp) error {
	path := normalisePath(op.Path)
	if path == "" {
		return fmt.Errorf("remove without a path is not valid")
	}
	switch path {
	case "active":
		// Removing "active" means returning it to its default, which SCIM says
		// is true. Rare, and refusing it would be worse than being explicit.
		t := true
		out.Active = &t
	default:
		out.Unsupported = append(out.Unsupported, path)
	}
	return nil
}

// normalisePath lowercases and strips the schema URN prefix.
//
// Entra sends fully qualified paths for core attributes as often as not:
//
//	urn:ietf:params:scim:schemas:core:2.0:User:active
func normalisePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if i := strings.LastIndex(p, ":"); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

// parseSCIMBool reads a boolean that may have been sent as a string.
//
// THE most important twenty lines in this file. Entra sends
// {"value":"False"} -- a JSON string -- and the ordinary reading of a non-empty
// string is true. An implementation that takes that reading applies a
// deactivation as an activation: somebody who has left keeps their access, and
// the upstream reports success.
func parseSCIMBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, fmt.Errorf("%s is not a boolean", string(raw))
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	// Not guessed. A value we cannot read is refused, because the two possible
	// guesses are "keep their access" and "remove it", and picking the wrong one
	// silently is how this goes wrong.
	return false, fmt.Errorf("%q is neither true nor false", s)
}

func parseSCIMString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s is not a string", string(raw))
	}
	return strings.TrimSpace(s), nil
}

// parseEmailValue reads an address from any of the shapes SCIM allows.
func parseEmailValue(raw json.RawMessage) (string, error) {
	// A bare string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s), nil
	}
	// A single object, or an array of them.
	var one Email
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return strings.TrimSpace(one.Value), nil
	}
	var many []Email
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		for _, e := range many {
			if e.Primary {
				return strings.TrimSpace(e.Value), nil
			}
		}
		return strings.TrimSpace(many[0].Value), nil
	}
	return "", fmt.Errorf("%s is not an email value", string(raw))
}

func ParseUserNameFilter(filter string) (string, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", nil
	}
	lower := strings.ToLower(filter)
	if !strings.HasPrefix(lower, "username eq ") {
		return "", fmt.Errorf("only `userName eq \"...\"` is supported as a filter, "+
			"got %q. Returning everything for an unrecognised filter would let a "+
			"caller match the wrong person", filter)
	}
	v := strings.TrimSpace(filter[len("username eq "):])
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"') {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return "", fmt.Errorf("the filter has no value")
	}
	// Unescape the one escape SCIM filters use.
	return strings.ReplaceAll(v, `\"`, `"`), nil
}
