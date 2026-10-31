package scim

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// What a target needs that the protocol does not say it should.
//
// Named for what they do and not for who needs them: which products need which is
// a fact about their current version, and an operator who finds that a target
// answers PATCH with a 405 knows what to set from that alone. A target can need
// several, which one vendor's name per target could not say.

const (
	// CompatNoPatch is a target that refuses PATCH. A change is made by reading the
	// resource and putting it back whole, changed only where it had to be, which
	// is not the same as the PUT SetActive refuses: that replaces what a target
	// holds with what we know, and this sends back everything it answered. Another
	// writer's change between the two is lost, which no PUT can avoid.
	CompatNoPatch = "no-patch"
	// CompatNoFilter is a target that refuses a filter on a list. Finding somebody
	// walks the list, which costs a page per hundred accounts and is only ever
	// asked for after a 409.
	CompatNoFilter = "no-filter"
	// CompatTypedMembers is a target that refuses a member with no type.
	CompatTypedMembers = "typed-members"
)

// Compatibilities are what can be asked for, as the column's CHECK has them.
var Compatibilities = []string{CompatNoPatch, CompatNoFilter, CompatTypedMembers}

// CheckCompatibility refuses a name this does not know, which would otherwise be
// a setting that quietly changes nothing.
func CheckCompatibility(names []string) error {
	for _, name := range names {
		if !slices.Contains(Compatibilities, name) {
			return fmt.Errorf("compatibility is one of %s, not %q", strings.Join(Compatibilities, ", "), name)
		}
	}
	return nil
}

func (t Target) needs(name string) bool { return slices.Contains(t.Compatibility, name) }

// replaceResource reads a resource and puts it back with one change, whatever
// else it holds going back as it came. A map, so that an attribute this has no
// field for is not an attribute it erases.
func (c *Client) replaceResource(ctx context.Context, path string, change func(map[string]any)) error {
	var resource map[string]any
	if err := c.do(ctx, http.MethodGet, path, nil, &resource); err != nil {
		return err
	}
	change(resource)
	return c.do(ctx, http.MethodPut, path, resource, nil)
}

// memberValue reads a member out of a group as a target answered it.
func memberValue(m any) string {
	if object, ok := m.(map[string]any); ok {
		s, _ := object["value"].(string)
		return s
	}
	return ""
}

// replaceMembers changes exactly the members named, as patchMembers does, and
// leaves the rest as the target has them, a member added by hand there included.
func (c *Client) replaceMembers(ctx context.Context, path, op string, memberIDs []string) error {
	return c.replaceResource(ctx, path, func(group map[string]any) {
		members, _ := group["members"].([]any)
		kept := make([]any, 0, len(members)+len(memberIDs))
		for _, m := range members {
			if op != "remove" || !slices.Contains(memberIDs, memberValue(m)) {
				kept = append(kept, m)
			}
		}
		if op == "add" {
			for _, id := range memberIDs {
				if !slices.ContainsFunc(kept, func(m any) bool { return memberValue(m) == id }) {
					kept = append(kept, c.member(id))
				}
			}
		}
		group["members"] = kept
	})
}

// member is one member as this target wants it.
func (c *Client) member(id string) Member {
	m := Member{Value: id}
	if c.target.needs(CompatTypedMembers) {
		m.Type = "user"
	}
	return m
}
