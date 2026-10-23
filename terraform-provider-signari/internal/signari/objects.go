package signari

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// The objects beyond clients (6.17): organisations, groups and their members,
// users. Each read answers the version it was observed at, and each write
// takes the If-Match to send and answers the version it produced, exactly as
// the client's do.

// Do sends one request, conditional when ifMatch is not 0.
func (c *Client) Do(ctx context.Context, method, path string, body any, ifMatch int64) (*Result, error) {
	return c.do(ctx, method, path, body, ifMatch)
}

// Get reads path into out, answering the version it was read at.
func (c *Client) Get(ctx context.Context, path string, out any) (int64, error) {
	res, err := c.do(ctx, http.MethodGet, path, nil, 0)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(res.Body, out); err != nil {
		return 0, fmt.Errorf("decoding %s: %w", path, err)
	}
	return res.Version, nil
}

// List reads every page of a list, handing each element of the field named
// key to each, and answers the version of the last page.
func (c *Client) List(ctx context.Context, path, key string, each func(json.RawMessage) error) (int64, error) {
	cursor := ""
	var version int64
	for {
		q := url.Values{"limit": {"200"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		res, err := c.do(ctx, http.MethodGet, path+sep+q.Encode(), nil, 0)
		if err != nil {
			return 0, err
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(res.Body, &page); err != nil {
			return 0, fmt.Errorf("decoding %s: %w", path, err)
		}
		var items []json.RawMessage
		if raw, ok := page[key]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return 0, fmt.Errorf("decoding %s's %s: %w", path, key, err)
			}
		}
		for _, item := range items {
			if err := each(item); err != nil {
				return 0, err
			}
		}
		version = res.Version
		var next string
		if raw, ok := page["next_cursor"]; ok {
			_ = json.Unmarshal(raw, &next)
		}
		if next == "" || len(items) == 0 {
			return version, nil
		}
		cursor = next
	}
}

// Organization is a tenant (GET /admin/organizations/{id}).
type Organization struct {
	ID          string `json:"id"`
	InstanceID  string `json:"instance_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	// Status is "active" or "suspended".
	Status string `json:"status"`
}

// Group is a group (GET /admin/groups/{id}).
type Group struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	// MayImpersonate is reported and set only on the command line.
	MayImpersonate bool `json:"may_impersonate"`
}

// User is a person (GET /admin/users/{id}).
type User struct {
	ID            string `json:"id"`
	OrgID         string `json:"org_id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	Status        string `json:"status"`
	DisplayName   string `json:"display_name"`
	GivenName     string `json:"given_name"`
	Surname       string `json:"surname"`
	Locale        string `json:"locale"`
	EmailVerified bool   `json:"email_verified"`
}

// created is what a create answers.
type created struct {
	ID            string `json:"id"`
	ConfigVersion int64  `json:"config_version"`
}

// Create posts body to path, answering the new object's id and the version
// the write produced.
func (c *Client) Create(ctx context.Context, path string, body any, ifMatch int64) (string, int64, error) {
	res, err := c.do(ctx, http.MethodPost, path, body, ifMatch)
	if err != nil {
		return "", 0, err
	}
	var out created
	_ = json.Unmarshal(res.Body, &out)
	v := res.Version
	if v == 0 {
		v = out.ConfigVersion
	}
	return out.ID, v, nil
}

// Write sends a write that answers no id, answering the version it produced.
func (c *Client) Write(ctx context.Context, method, path string, body any, ifMatch int64) (int64, error) {
	res, err := c.do(ctx, method, path, body, ifMatch)
	if err != nil {
		return 0, err
	}
	if res.Version > 0 {
		return res.Version, nil
	}
	var out created
	_ = json.Unmarshal(res.Body, &out)
	return out.ConfigVersion, nil
}

// IsMember reports whether the user is a member of the group, paging its
// members, which is the only read of a membership there is.
func (c *Client) IsMember(ctx context.Context, groupID, userID string) (bool, int64, error) {
	found := false
	version, err := c.List(ctx, "/admin/groups/"+url.PathEscape(groupID)+"/members", "members",
		func(raw json.RawMessage) error {
			var m struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &m) == nil && m.ID == userID {
				found = true
			}
			return nil
		})
	return found, version, err
}
