package scim

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Provisioning groups, and their membership, to a target.
//
// # Why membership is PATCHed and never PUT
//
// The same reasoning `SetActive` records for users, and it matters more here. A
// PUT replaces the whole resource, so pushing a group with our membership list
// erases anything the target holds that we did not send — accounts a local
// administrator added there by hand, service accounts, everything.
//
// A group is an access control list at the target. Replacing one wholesale, on
// a schedule, is a way to remove somebody's access at 3am for a reason nobody
// can reconstruct. So membership changes are add and remove operations naming
// exactly the members that moved.
//
// # A group we do not manage is never touched
//
// Reconciliation only ever acts on groups this deployment created, tracked by
// the remote id it was told at creation. A group matched by NAME could be one
// the target's own administrators maintain — and the first sync would then take
// it over and start removing their members.

const (
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

// Group is the subset of the SCIM group schema this sends.
//
// Deliberately small, for the same reason User is: every attribute sent is one
// a target with a stricter idea of its schema can reject.
type Group struct {
	Schemas     []string `json:"schemas"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`

	// ID is assigned BY THE TARGET and only ever read, never sent.
	ID string `json:"id,omitempty"`
}

// Member is one member reference inside a group.
type Member struct {
	// Value is the target's own user id, not ours. A membership expressed with
	// our identifier would be a membership the target cannot resolve.
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// CreateGroup creates a group at the target and returns its remote id.
func (c *Client) CreateGroup(ctx context.Context, g Group) (string, error) {
	if c.target.DryRun {
		return "", nil
	}
	g.Schemas = []string{schemaGroup}
	var created Group
	if err := c.do(ctx, http.MethodPost, "/Groups", g, &created); err != nil {
		return "", err
	}
	if created.ID == "" {
		// Same rule as CreateUser: without an id this group cannot be found
		// again, so every later reconciliation would create a duplicate.
		return "", fmt.Errorf("the target created the group but returned no id, so " +
			"it could not be reconciled later")
	}
	return created.ID, nil
}

// GetGroup reads one group by its remote id.
func (c *Client) GetGroup(ctx context.Context, remoteID string) (*Group, error) {
	var g Group
	if err := c.do(ctx, http.MethodGet, "/Groups/"+url.PathEscape(remoteID), nil, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// DeleteGroup removes a group from the target.
func (c *Client) DeleteGroup(ctx context.Context, remoteID string) error {
	if c.target.DryRun {
		return nil
	}
	return c.do(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(remoteID), nil, nil)
}

// AddMembers adds members without disturbing the ones already there.
func (c *Client) AddMembers(ctx context.Context, remoteID string, memberIDs []string) error {
	return c.patchMembers(ctx, remoteID, "add", memberIDs)
}

// RemoveMembers removes exactly the members named.
func (c *Client) RemoveMembers(ctx context.Context, remoteID string, memberIDs []string) error {
	return c.patchMembers(ctx, remoteID, "remove", memberIDs)
}

// patchMembers issues one PATCH naming only the members that moved.
//
// The removal path filters BY VALUE rather than replacing the members
// attribute, which is the difference between "take these three people out" and
// "these are now the only members" — and the second, sent with a list that was
// short because a query failed, empties the group.
func (c *Client) patchMembers(ctx context.Context, remoteID, op string, memberIDs []string) error {
	if len(memberIDs) == 0 || c.target.DryRun {
		return nil
	}

	type operation struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value,omitempty"`
	}
	body := struct {
		Schemas    []string    `json:"schemas"`
		Operations []operation `json:"Operations"`
	}{Schemas: []string{schemaPatch}}

	for _, id := range memberIDs {
		switch op {
		case "add":
			body.Operations = append(body.Operations, operation{
				Op: "add", Path: "members", Value: []Member{{Value: id}},
			})
		case "remove":
			// A filtered path, so the target removes this member and leaves the
			// rest. `path: "members"` with no filter is a request to replace the
			// whole attribute at several implementations.
			//
			// The id is quoted and escaped: a member id is data, and a filter is
			// a query language. An unescaped quote in one would change which
			// members the filter matches.
			body.Operations = append(body.Operations, operation{
				Op:   "remove",
				Path: fmt.Sprintf("members[value eq %s]", quoteFilterValue(id)),
			})
		default:
			return fmt.Errorf("unknown membership operation %q", op)
		}
	}

	return c.do(ctx, http.MethodPatch, "/Groups/"+url.PathEscape(remoteID), body, nil)
}

// quoteFilterValue renders a value for a SCIM filter expression.
//
// SCIM filters are a query language (RFC 7644 §3.4.2.2) and a member id is data
// that arrives from a target we do not control. Interpolating one unescaped
// lets a crafted id change which members the filter matches -- so a removal
// aimed at one account could remove several, or none.
func quoteFilterValue(v string) string {
	var out []byte
	out = append(out, '"')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '"', '\\':
			out = append(out, '\\', v[i])
		default:
			out = append(out, v[i])
		}
	}
	return string(append(out, '"'))
}
