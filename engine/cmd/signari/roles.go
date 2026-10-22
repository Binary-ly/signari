package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// Administrative roles from the command line (6.01): how the first owner of an
// organisation is made, by an operator with the database, before anybody can
// grant one through the Admin API. The binding is the same row the API writes,
// through the same store function; the CLI's own trail records the command.

func roleGrant(ctx context.Context, conn *pgx.Conn, orgID, email, clientID, role, group string) error {
	switch {
	case orgID == "" || role == "":
		return fmt.Errorf("role grant needs -org, -role (%s) and one of -email and -client-id", joinRoles())
	case (email == "") == (clientID == ""):
		return fmt.Errorf("role grant names exactly one holder: -email for a person, -client-id for an application")
	}
	b := store.RoleBinding{OrgID: orgID, Role: role, ClientID: clientID}
	if email != "" {
		if err := conn.QueryRow(ctx, `SELECT id::text FROM core.users
			WHERE org_id = $1::uuid AND lower(email) = lower($2)`, orgID, email).Scan(&b.UserID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("nobody in that organisation has the address %s", email)
			}
			return err
		}
	}
	if group != "" {
		if err := conn.QueryRow(ctx, `SELECT id::text FROM core.groups
			WHERE org_id = $1::uuid AND name = $2`, orgID, group).Scan(&b.GroupID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("no group named %s in that organisation", group)
			}
			return err
		}
	}
	id, err := store.GrantRole(ctx, conn, b)
	if err != nil {
		return err
	}
	reach := "everyone in the organisation"
	if group != "" {
		reach = "the members of " + group
	}
	fmt.Printf("granted %s (binding %s), reaching %s. It applies from the holder's next request.\n", role, id, reach)
	return nil
}

func roleList(ctx context.Context, conn *pgx.Conn, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("role list needs -org")
	}
	bindings, err := store.RoleBindings(ctx, conn, orgID)
	if err != nil {
		return err
	}
	if len(bindings) == 0 {
		fmt.Println("no role bindings: the organisation is administered by admin tokens alone")
		return nil
	}
	for _, b := range bindings {
		holder := "user " + b.UserID
		if b.ClientID != "" {
			holder = "client " + b.ClientID
		}
		over := ""
		if b.GroupID != "" {
			over = "  over group " + b.GroupID
		}
		fmt.Printf("%s  %-12s  %s%s\n", b.ID, b.Role, holder, over)
	}
	return nil
}

func roleRevoke(ctx context.Context, conn *pgx.Conn, orgID, bindingID string) error {
	if orgID == "" || bindingID == "" {
		return fmt.Errorf("role revoke needs -org and -binding (see `signari role list`)")
	}
	b, err := store.RevokeRole(ctx, conn, orgID, bindingID)
	if err != nil {
		return err
	}
	fmt.Printf("revoked %s from %s%s. The holder's next request is refused what it gave.\n",
		b.Role, b.UserID, b.ClientID)
	return nil
}

func joinRoles() string {
	out := ""
	for i, r := range store.AdminRoles {
		if i > 0 {
			out += ", "
		}
		out += r
	}
	return out
}
