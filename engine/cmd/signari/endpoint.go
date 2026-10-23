package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// The endpoint mode (6.16): given -admin-url, these commands make their change
// through the Admin API rather than the database, as the token in
// SIGNARI_ADMIN_TOKEN or -token-file, so the API audits it under that token and
// refuses what its scopes do not allow. Each takes the flags it takes against
// the database. Every other route is reached with `signari api`.

// withAPI runs fn with a client for the Admin API, under the command's
// deadline.
func withAPI(adminURL, tokenFile string, runFor time.Duration, fn func(context.Context, *apiClient) error) error {
	c, err := newAPIClient(adminURL, tokenFile)
	if err != nil {
		return err
	}
	ctx, cancel := commandContext(runFor)
	defer cancel()
	return fn(ctx, c)
}

// endpointUserCreate is `user create` through POST /admin/users.
func endpointUserCreate(ctx context.Context, c *apiClient, orgID, email, password string) error {
	if orgID == "" || email == "" {
		return fmt.Errorf("give -org and -email: through the Admin API there is no only organisation to assume")
	}
	var out struct {
		ID string `json:"id"`
	}
	body := map[string]any{"org_id": orgID, "email": email}
	if password != "" {
		body["password"] = password
	}
	if err := c.call(ctx, "POST", "/admin/users", body, &out); err != nil {
		return err
	}
	fmt.Printf("created user %s (%s) through the Admin API\n", out.ID, email)
	return nil
}

// endpointGroupCreate is `group create` through POST /admin/groups.
func endpointGroupCreate(ctx context.Context, c *apiClient, orgID, group, name string) error {
	if orgID == "" || group == "" {
		return fmt.Errorf("give -org and -group: through the Admin API there is no only organisation to assume")
	}
	var out struct {
		ID string `json:"id"`
	}
	body := map[string]any{"org_id": orgID, "name": group}
	if name != "" {
		body["display_name"] = name
	}
	if err := c.call(ctx, "POST", "/admin/groups", body, &out); err != nil {
		return err
	}
	fmt.Printf("created group %s (%s) through the Admin API\n", out.ID, group)
	return nil
}

// endpointTokenCreate is `admin-token create` through POST /admin/tokens. The
// secret is printed once, as the database path prints it.
func endpointTokenCreate(ctx context.Context, c *apiClient, name, orgID, scopes string, expiresIn time.Duration,
	expiresGiven bool, clients, groups string) error {
	if name == "" {
		return fmt.Errorf("give -name; it appears in the audit trail, and \"which token " +
			"was that\" is unanswerable without one")
	}
	if groups != "" {
		return errors.New("-groups names groups, which the Admin API takes by id: create the token with " +
			"`signari api POST /admin/tokens` and their ids as group_ids in its body, or against the database")
	}
	body := map[string]any{"name": name, "scopes": splitList(scopes)}
	if orgID != "" {
		body["org_id"] = orgID
	}
	if ids := splitList(clients); len(ids) > 0 {
		body["client_ids"] = ids
	}
	if expiresGiven {
		body["expires_in_s"] = int64(expiresIn.Seconds())
	}
	var out struct {
		ID        string     `json:"id"`
		Secret    string     `json:"secret"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.call(ctx, "POST", "/admin/tokens", body, &out); err != nil {
		return err
	}
	fmt.Printf("\n  %s\n\n  id     : %s\n  name   : %s\n", out.Secret, out.ID, name)
	if out.ExpiresAt != nil {
		fmt.Printf("  expires: %s\n", out.ExpiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Println("\n  Shown once; the Admin API keeps only its hash.")
	return nil
}

// endpointTokenList is `admin-token list` through GET /admin/tokens, printed as
// the API answers it.
func endpointTokenList(ctx context.Context, c *apiClient) error {
	resp, err := c.do(ctx, "GET", "/admin/tokens", nil, "")
	if resp != nil {
		printAPIBody(os.Stdout, resp.Body)
	}
	return err
}

// endpointTokenRevoke is `admin-token revoke` through DELETE /admin/tokens/{id}.
func endpointTokenRevoke(ctx context.Context, c *apiClient, tokenID string) error {
	if tokenID == "" {
		return fmt.Errorf("give -token-id, the token's uuid from `admin-token list`")
	}
	if err := c.call(ctx, "DELETE", "/admin/tokens/"+url.PathEscape(tokenID), nil, nil); err != nil {
		return err
	}
	fmt.Printf("revoked %s through the Admin API; its next request is refused\n", tokenID)
	return nil
}

// endpointRoleList is `role list` through GET /admin/organizations/{id}/role-bindings.
func endpointRoleList(ctx context.Context, c *apiClient, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("role list needs -org")
	}
	resp, err := c.do(ctx, "GET", "/admin/organizations/"+url.PathEscape(orgID)+"/role-bindings", nil, "")
	if resp != nil {
		printAPIBody(os.Stdout, resp.Body)
	}
	return err
}

// endpointRoleRevoke is `role revoke` through DELETE
// /admin/organizations/{id}/role-bindings/{binding}.
func endpointRoleRevoke(ctx context.Context, c *apiClient, orgID, binding string) error {
	if orgID == "" || strings.TrimSpace(binding) == "" {
		return fmt.Errorf("role revoke needs -org and -binding, the binding's id from `role list`")
	}
	if err := c.call(ctx, "DELETE", "/admin/organizations/"+url.PathEscape(orgID)+"/role-bindings/"+
		url.PathEscape(binding), nil, nil); err != nil {
		return err
	}
	fmt.Printf("revoked role binding %s through the Admin API\n", binding)
	return nil
}
