package config

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// applyNestings makes each group the file gives a member_of inside exactly those
// groups (11.09), once every group the file declares exists. Every nesting taken
// away goes first and every one made after, so a file that turns two groups the
// other way up -- a inside b becoming b inside a -- does not meet its own old
// nesting as a loop half way through.
func applyNestings(ctx context.Context, tx pgx.Tx, orgID string, f *File,
	planned func(kind, name string) (Change, bool)) error {

	type edge struct{ group, parent string }
	var add []edge
	ids := map[string]string{}
	id := func(name string) (string, error) {
		if v, ok := ids[name]; ok {
			return v, nil
		}
		v, err := store.GroupIDNamed(ctx, tx, orgID, name)
		if err == nil && v == "" {
			err = fmt.Errorf("no group named %q in the organisation", name)
		}
		ids[name] = v
		return v, err
	}
	for _, g := range f.Groups {
		c, ok := planned("group", g.Name)
		if !ok || c.Action == "delete" || g.MemberOf == nil {
			continue
		}
		groupID, err := id(g.Name)
		if err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
		have, err := store.ParentsOf(ctx, tx, groupID)
		if err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
		want := map[string]bool{}
		for _, p := range g.memberOf() {
			want[p] = true
		}
		for _, n := range have {
			if want[n.Parent] {
				delete(want, n.Parent)
				continue
			}
			if _, err := store.UnnestGroup(ctx, tx, orgID, groupID, n.ParentID); err != nil {
				return fmt.Errorf("group %q: taking it out of %q: %w", g.Name, n.Parent, err)
			}
		}
		for _, p := range sortedCopy(namesIn(want)) {
			add = append(add, edge{g.Name, p})
		}
	}
	for _, e := range add {
		groupID, err := id(e.group)
		if err != nil {
			return fmt.Errorf("group %q: %w", e.group, err)
		}
		parentID, err := id(e.parent)
		if err != nil {
			return fmt.Errorf("group %q: member_of: %w", e.group, err)
		}
		if _, err := store.NestGroup(ctx, tx, orgID, groupID, parentID, ""); err != nil {
			if errors.Is(err, store.ErrNestingLoop) {
				return refuse("group %s: putting it inside %s would make a loop with the organisation's "+
					"existing nestings: %v", e.group, e.parent, err)
			}
			return fmt.Errorf("group %q: putting it inside %q: %w", e.group, e.parent, err)
		}
	}
	return nil
}

func namesIn(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
