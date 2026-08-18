package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)


// GroupPatch is the set of changes a PATCH implies.
type GroupPatch struct {
	// DisplayName is set when the operation renames the group.
	DisplayName *string
	// AddMembers and RemoveMembers are SCIM resource ids of users.
	AddMembers    []string
	RemoveMembers []string
	// ReplaceMembers is non-nil when the operation replaces the whole member
	// list, which is different from adding to it: everybody not named is
	// removed. Distinguished by a pointer because replacing with an EMPTY list
	// -- "this group now has nobody in it" -- is a real and legitimate
	// operation, and a plain nil slice cannot say it.
	ReplaceMembers *[]string
	// Unsupported lists paths understood as paths but not acted on.
	Unsupported []string
}

func memberIDFromPath(path string) (string, error) {
	p, err := ParsePath(path)
	if err != nil {
		return "", err
	}
	if p.Attr != "members" || p.Filter == nil {
		return "", nil
	}
	if p.Sub != "" && p.Sub != "value" {
		return "", fmt.Errorf("a member filter may only be followed by .value, got %q", p.Sub)
	}
	// The filter is a predicate, so it is asked about a candidate rather than
	// pattern-matched. A member element carries `value`, and a filter that
	// selects on anything else identifies nobody this server can look up.
	id := memberValueSelectedBy(p.Filter)
	if id == "" {
		return "", fmt.Errorf("cannot tell which member %q names; only a filter on "+
			"`value` identifies one", path)
	}
	return id, nil
}

// memberValueSelectedBy extracts the id an equality filter on `value` selects.
//
// Only `value eq "…"` identifies a member. Anything else — a filter on
// `display`, a range, a negation — describes a set this server cannot enumerate,
// and guessing would remove the wrong person.
func memberValueSelectedBy(f *Filter) string {
	if f == nil || f.Op != "eq" || f.Attr != "value" {
		if f != nil && f.Op == "and" {
			// `value eq "x" and type eq "User"` is a conjunction Entra sends.
			if id := memberValueSelectedBy(f.Left); id != "" {
				return id
			}
			return memberValueSelectedBy(f.Right)
		}
		return ""
	}
	s, _ := f.Value.(string)
	return s
}

// ApplyGroupPatch reads a PATCH body into the changes it implies.
func ApplyGroupPatch(req PatchRequest) (*GroupPatch, error) {
	if len(req.Operations) == 0 {
		return nil, fmt.Errorf("PATCH with no operations")
	}
	out := &GroupPatch{}
	for i, op := range req.Operations {
		verb := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)

		switch verb {
		case "add", "replace":
			if err := groupAssign(out, verb, path, op.Value); err != nil {
				return nil, fmt.Errorf("operation %d: %w", i, err)
			}
		case "remove":
			if err := groupRemove(out, path, op.Value); err != nil {
				return nil, fmt.Errorf("operation %d: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("operation %d: unknown op %q", i, op.Op)
		}
	}
	return out, nil
}

func groupAssign(out *GroupPatch, verb, path string, raw json.RawMessage) error {
	// The no-path form: the value is an object whose members ARE the paths.
	// Entra sends this, and reading it as a member list would add a group named
	// after a field name.
	if path == "" {
		var body map[string]json.RawMessage
		if err := json.Unmarshal(raw, &body); err != nil {
			return fmt.Errorf("%s with no path needs an object value: %w", verb, err)
		}
		for key, v := range body {
			if err := groupAssign(out, verb, key, v); err != nil {
				return err
			}
		}
		return nil
	}

	switch strings.ToLower(stripSchemaPrefix(path)) {
	case "displayname":
		var name string
		if err := json.Unmarshal(raw, &name); err != nil {
			return fmt.Errorf("displayName must be a string: %w", err)
		}
		out.DisplayName = &name
		return nil

	case "members":
		ids, err := memberIDs(raw)
		if err != nil {
			return err
		}
		if verb == "replace" {
			// "replace" on the whole member list means the list IS this, so
			// anybody absent is removed. Treating it as "add" leaves departed
			// members in the group with the upstream reporting success.
			cp := append([]string{}, ids...)
			out.ReplaceMembers = &cp
			return nil
		}
		out.AddMembers = append(out.AddMembers, ids...)
		return nil
	}

	// A filtered member path on add/replace. Rare, but Entra emits
	// `replace` with `members[value eq "x"]` when re-asserting one membership.
	if id, perr := memberIDFromPath(path); perr != nil {
		return perr
	} else if id != "" {
		out.AddMembers = append(out.AddMembers, id)
		return nil
	}

	out.Unsupported = append(out.Unsupported, path)
	return nil
}

func groupRemove(out *GroupPatch, path string, raw json.RawMessage) error {
	if path == "" {
		return fmt.Errorf("remove with no path: there is nothing to remove")
	}

	id, perr := memberIDFromPath(path)
	if perr != nil {
		return perr
	}
	if id != "" {
		out.RemoveMembers = append(out.RemoveMembers, id)
		return nil
	}

	if strings.EqualFold(stripSchemaPrefix(path), "members") {
		// Entra's form: the path is the collection and the value names members.
		if len(raw) > 0 && string(raw) != "null" {
			ids, err := memberIDs(raw)
			if err != nil {
				return err
			}
			out.RemoveMembers = append(out.RemoveMembers, ids...)
			return nil
		}
		// `remove` on the whole collection with no value empties the group.
		empty := []string{}
		out.ReplaceMembers = &empty
		return nil
	}

	// Anything else naming members that we could not read is an error rather
	// than an unsupported path. Recording it as unsupported would answer 200.
	if strings.HasPrefix(strings.ToLower(path), "members") {
		return fmt.Errorf("cannot read which member %q removes; refusing rather "+
			"than answering success to a removal that would not happen", path)
	}

	out.Unsupported = append(out.Unsupported, path)
	return nil
}

// memberIDs reads a member list in either of the shapes upstreams send.
func memberIDs(raw json.RawMessage) ([]string, error) {
	// The ordinary shape: an array of objects with a `value`.
	var objs []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &objs); err == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if o.Value != "" {
				out = append(out, o.Value)
			}
		}
		if len(out) > 0 || len(objs) > 0 {
			return out, nil
		}
	}
	// A single object rather than an array.
	var one struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return []string{one.Value}, nil
	}
	// A bare array of id strings.
	var strs []string
	if err := json.Unmarshal(raw, &strs); err == nil {
		return strs, nil
	}
	return nil, fmt.Errorf("cannot read a member list from %s", string(raw))
}

// stripSchemaPrefix removes a `urn:...:` schema qualifier from a path.
//
// RFC 7644 §3.5.2 permits a fully qualified attribute path, and Entra sends one
// for extension attributes. Without this, `urn:...:2.0:Group:members` is not
// recognised as `members` and a membership change becomes an unsupported path --
// answered 200 and never retried.
func stripSchemaPrefix(path string) string {
	if !strings.HasPrefix(strings.ToLower(path), "urn:") {
		return path
	}
	if i := strings.LastIndex(path, ":"); i >= 0 && i+1 < len(path) {
		return path[i+1:]
	}
	return path
}

func GroupNameFrom(displayName string) (string, error) {
	var b strings.Builder
	lastDash := false
	for _, r := range displayName {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			// Runs of anything else collapse to ONE separator, so
			// "Finance & Legal" becomes finance-legal rather than finance---legal.
			if !lastDash && b.Len() > 0 {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > 64 {
		name = strings.Trim(name[:64], "-")
	}
	if name == "" {
		return "", fmt.Errorf("the display name %q contains no characters usable "+
			"in a group name, which must match [a-zA-Z0-9._-]", displayName)
	}
	return name, nil
}

func ParseDisplayNameFilter(filter string) (string, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", nil
	}
	lower := strings.ToLower(filter)
	if !strings.HasPrefix(lower, "displayname eq ") {
		return "", fmt.Errorf("only `displayName eq \"...\"` is supported as a "+
			"filter on /Groups, got %q. Returning everything for an unrecognised "+
			"filter would let a caller match the wrong group", filter)
	}
	v := strings.TrimSpace(filter[len("displayname eq "):])
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return "", fmt.Errorf("the filter has no value")
	}
	return strings.ReplaceAll(v, `\"`, `"`), nil
}
