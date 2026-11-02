package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/adminapi"
	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// bootstrapLinkLife is how long the first person has. Long enough to read a log the
// morning after; a link that outlives that is a standing way into an empty deployment.
const bootstrapLinkLife = 72 * time.Hour

// bootstrap takes a migrated, empty database to one a person can sign in to: an
// instance with its signing keys, an organisation, and a one-time link for its first
// person. Until there was this, a first run took four commands and, for the
// organisation, a line of SQL or an Admin API nobody could yet reach.
//
// It runs on every start of a compose file, so each step does nothing when its work
// is done. In particular it does not go through instanceCreate on a second run, which
// would put the issuer back over a display name somebody has since chosen. Run again
// while nobody has accepted, it withdraws the last link and prints another, since the
// link is stored hashed and a lost one could otherwise never be replaced. Once the
// organisation has anybody in it there is nothing to say, and no link: a link printed
// on every start would be a way in that outlives its reason.
func bootstrap(ctx context.Context, conn *pgx.Conn, issuer, name, slug, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if slug == "" {
		slug = "default"
	}
	if name == "" {
		name = "Default"
	}
	switch {
	case issuer == "":
		return fmt.Errorf("give -issuer, the URL people will reach this deployment at")
	case email == "":
		return fmt.Errorf("give -email, the first person's address: the link works for nobody else")
	case !strings.Contains(email, "@"):
		return fmt.Errorf("-email %q is not an address", email)
	case !adminapi.ValidSlug(slug):
		return fmt.Errorf("-slug %q is not a slug: lowercase letters, digits and hyphens, "+
			"neither first nor last", slug)
	}

	var instanceID string
	err := conn.QueryRow(ctx, `SELECT id::text FROM core.instances WHERE issuer = $1`, issuer).Scan(&instanceID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if err := instanceCreate(ctx, conn, issuer, ""); err != nil {
			return err
		}
		if err := conn.QueryRow(ctx, `SELECT id::text FROM core.instances WHERE issuer = $1`,
			issuer).Scan(&instanceID); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		root, err := rootKey()
		if err != nil {
			return err
		}
		// A run stopped between the instance and its keys has to be able to finish.
		if _, err := keys.Ensure(ctx, conn, instanceID, root, keys.ES256, keys.RS256); err != nil {
			return fmt.Errorf("ensuring signing keys: %w", err)
		}
		fmt.Printf("instance %s already here\n", instanceID)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var orgID string
	err = tx.QueryRow(ctx, `SELECT id::text FROM core.organizations WHERE instance_id = $1::uuid
		ORDER BY created_at, id LIMIT 1`, instanceID).Scan(&orgID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if err := tx.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ($1::uuid, $2, $3) RETURNING id::text`, instanceID, slug, name).Scan(&orgID); err != nil {
			return err
		}
		// As the Admin API records one: filed under the new organisation, so that it
		// has a record of its own beginning.
		if err := audit.Write(ctx, tx, audit.Event{Type: "admin.organization_created", OrgID: orgID,
			Detail: map[string]any{"slug": slug, "instance_id": instanceID}}); err != nil {
			return err
		}
		fmt.Printf("organisation %s\n  slug %s\n", orgID, slug)
	case err != nil:
		return err
	default:
		fmt.Printf("organisation %s already here\n", orgID)
	}

	var peopled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE org_id = $1::uuid)`,
		orgID).Scan(&peopled); err != nil {
		return err
	}
	if peopled {
		fmt.Println("people are already signing in here, so there is no link to print")
		return tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, `UPDATE core.invitations SET revoked_at = now()
		WHERE org_id = $1::uuid AND used_at IS NULL AND revoked_at IS NULL`, orgID); err != nil {
		return err
	}
	_, token, _, err := store.NewInvitation(ctx, tx, store.InvitationSpec{
		OrgID: orgID, Email: email, TTL: bootstrapLinkLife})
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Printf("\nThe first person, %s, finishes setting up here, once, within %s:\n\n  %s/signup?invite=%s\n\n",
		email, bootstrapLinkLife, strings.TrimRight(issuer, "/"), token)
	fmt.Println("The link is stored hashed, so it cannot be shown again. Run this again for a new one.")
	return nil
}
