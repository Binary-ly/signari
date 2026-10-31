package provision

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/scim"
)

// Group provisioning (7.09). The reconciliation in admin.go is the same for every
// kind of target: a group this deployment created, its members compared with who
// here has an account there. What differs is the wire, and that is this interface.

// Group is a group as a target is asked to hold it. Name is the short name here, for
// a target that makes an address from it.
type Group struct{ Name, DisplayName, ExternalID string }

// GroupProvisioner is a target that holds groups. Members are the identifiers a
// target gave its accounts, the ones the link table holds.
type GroupProvisioner interface {
	CreateGroup(ctx context.Context, g Group) (string, error)
	DeleteGroup(ctx context.Context, remoteID string) error
	GroupMembers(ctx context.Context, remoteID string) ([]string, error)
	AddGroupMembers(ctx context.Context, remoteID string, members []string) error
	RemoveGroupMembers(ctx context.Context, remoteID string, members []string) error
}

// groupsAt is the target's groups. Google's are asked for through a token that may
// hold them; see forGroups.
func groupsAt(t scim.Target, hc *http.Client) (GroupProvisioner, error) {
	p, err := ForTarget(t, hc)
	if err != nil {
		return nil, err
	}
	if g, ok := p.(*Google); ok {
		return g.forGroups(), nil
	}
	return p.(GroupProvisioner), nil
}

// groupNickname is a name a target will take in an address: letters, digits and
// these three, of what is here. Entra's mailNickname and the left of a Google address
// both refuse most of what a group's display name may hold.
func groupNickname(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = strings.TrimRight(out[:64], "-.")
	}
	return out
}

// SCIM.

func (s SCIM) CreateGroup(ctx context.Context, g Group) (string, error) {
	return s.Client.CreateGroup(ctx, scim.Group{DisplayName: g.DisplayName, ExternalID: g.ExternalID})
}

func (s SCIM) DeleteGroup(ctx context.Context, remoteID string) error {
	return s.Client.DeleteGroup(ctx, remoteID)
}

func (s SCIM) GroupMembers(ctx context.Context, remoteID string) ([]string, error) {
	g, err := s.Client.GetGroup(ctx, remoteID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		out = append(out, m.Value)
	}
	return out, nil
}

func (s SCIM) AddGroupMembers(ctx context.Context, remoteID string, members []string) error {
	return s.Client.AddMembers(ctx, remoteID, members)
}

func (s SCIM) RemoveGroupMembers(ctx context.Context, remoteID string, members []string) error {
	return s.Client.RemoveMembers(ctx, remoteID, members)
}

// Entra. A security group, which needs Group.ReadWrite.All on the application
// registration. Graph has no external identifier for a group, so the description
// says which of them this deployment owns.

func (e *Entra) CreateGroup(ctx context.Context, g Group) (string, error) {
	nickname := groupNickname(g.Name)
	if nickname == "" {
		return "", fmt.Errorf("the group %q has no characters a mail nickname may hold", g.Name)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := e.call(ctx, http.MethodPost, "/groups", map[string]any{"displayName": g.DisplayName,
		"mailNickname": nickname, "mailEnabled": false, "securityEnabled": true,
		"description": "Managed by Signari: " + g.ExternalID}, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

func (e *Entra) DeleteGroup(ctx context.Context, remoteID string) error {
	return e.call(ctx, http.MethodDelete, "/groups/"+url.PathEscape(remoteID), nil, nil)
}

// GroupMembers follows Graph's paging: a member on a page unread would read as
// somebody to add, and Graph refuses a reference that already exists.
func (e *Entra) GroupMembers(ctx context.Context, remoteID string) ([]string, error) {
	path := "/groups/" + url.PathEscape(remoteID) + "/members?$select=id&$top=999"
	var out []string
	for {
		var page struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := e.call(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		for _, m := range page.Value {
			out = append(out, m.ID)
		}
		if page.NextLink == "" {
			return out, nil
		}
		next := strings.TrimPrefix(page.NextLink, e.base())
		if strings.HasPrefix(next, "http") {
			// A short list here reads as members to add, then as a refused add.
			return nil, fmt.Errorf("graph sent the next page of %s to another host", remoteID)
		}
		path = next
	}
}

func (e *Entra) AddGroupMembers(ctx context.Context, remoteID string, members []string) error {
	for _, m := range members {
		if err := e.call(ctx, http.MethodPost, "/groups/"+url.PathEscape(remoteID)+"/members/$ref",
			map[string]string{"@odata.id": e.base() + "/directoryObjects/" + url.PathEscape(m)}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (e *Entra) RemoveGroupMembers(ctx context.Context, remoteID string, members []string) error {
	for _, m := range members {
		if err := e.call(ctx, http.MethodDelete,
			"/groups/"+url.PathEscape(remoteID)+"/members/"+url.PathEscape(m)+"/$ref", nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// Google. A group is an address in the domain. Members are named by primary address,
// which is how the API is driven by the client this was read against, so a person's
// id is turned into theirs first.

// forGroups is this target with a token that may touch groups, a scope of its own. A
// token that asked for it on every call would stop a target's user sync the day it
// started, on a deployment whose delegation grants only users: the scope is asked for
// by those who provision a group, and they have granted it.
func (g *Google) forGroups() *Google {
	return &Google{Creds: g.Creds, Impersonate: g.Impersonate, Domain: g.Domain, HTTP: g.HTTP, BaseURL: g.BaseURL,
		scope: directory.ScopeDirectoryWrite + " " + directory.ScopeGroupWrite}
}

func (g *Google) CreateGroup(ctx context.Context, group Group) (string, error) {
	nickname := groupNickname(group.Name)
	if nickname == "" {
		return "", fmt.Errorf("the group %q has no characters an address may hold", group.Name)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := g.call(ctx, http.MethodPost, "/admin/directory/v1/groups", map[string]any{
		"email": nickname + "@" + g.Domain, "name": group.DisplayName,
		"description": "Managed by Signari: " + group.ExternalID}, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

func (g *Google) DeleteGroup(ctx context.Context, remoteID string) error {
	return g.call(ctx, http.MethodDelete, "/admin/directory/v1/groups/"+url.PathEscape(remoteID), nil, nil)
}

func (g *Google) GroupMembers(ctx context.Context, remoteID string) ([]string, error) {
	var out []string
	pageToken := ""
	for {
		q := url.Values{}
		q.Set("maxResults", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		var page struct {
			Members []struct {
				ID string `json:"id"`
			} `json:"members"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := g.call(ctx, http.MethodGet, "/admin/directory/v1/groups/"+url.PathEscape(remoteID)+"/members?"+q.Encode(),
			nil, &page); err != nil {
			return nil, err
		}
		for _, m := range page.Members {
			out = append(out, m.ID)
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}

func (g *Google) primaryEmail(ctx context.Context, id string) (string, error) {
	var u googleUser
	if err := g.call(ctx, http.MethodGet, "/admin/directory/v1/users/"+url.PathEscape(id), nil, &u); err != nil {
		return "", err
	}
	return u.PrimaryEmail, nil
}

func (g *Google) AddGroupMembers(ctx context.Context, remoteID string, members []string) error {
	for _, m := range members {
		email, err := g.primaryEmail(ctx, m)
		if err != nil {
			return err
		}
		if err := g.call(ctx, http.MethodPost, "/admin/directory/v1/groups/"+url.PathEscape(remoteID)+"/members",
			map[string]string{"email": email}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (g *Google) RemoveGroupMembers(ctx context.Context, remoteID string, members []string) error {
	for _, m := range members {
		email, err := g.primaryEmail(ctx, m)
		if errors.Is(err, errGoogleNotFound) {
			continue // The account went, and its memberships with it.
		}
		if err != nil {
			return err
		}
		if err := g.call(ctx, http.MethodDelete,
			"/admin/directory/v1/groups/"+url.PathEscape(remoteID)+"/members/"+url.PathEscape(email), nil, nil); err != nil {
			return err
		}
	}
	return nil
}
