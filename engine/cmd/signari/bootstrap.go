package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	root, err := rootKey()
	if err != nil {
		return err
	}
	out, err := bootstrapWith(ctx, conn, root, os.Stdout, issuer, name, slug, email)
	if err != nil || out.Link == "" {
		return err
	}
	fmt.Printf("\nThe first person, %s, finishes setting up here, once, within %s:\n\n  %s\n\n",
		email, bootstrapLinkLife, out.Link)
	fmt.Println("The link is stored hashed, so it cannot be shown again. Run this again for a new one.")
	return nil
}

// bootstrapOutcome is what a bootstrap did, for `signari setup` to report in
// its own words.
type bootstrapOutcome struct {
	InstanceID, OrgID string
	// Link is the first person's one-time link, empty once anybody is here.
	Link    string
	Expires time.Time
}

// bootstrapWith is bootstrap's work under the root key given, reporting each
// step to w. Its arguments are checked already: setup and bootstrap check them
// in their own words, for their own flags.
func bootstrapWith(ctx context.Context, conn *pgx.Conn, root *keys.RootKey, w io.Writer,
	issuer, name, slug, email string) (bootstrapOutcome, error) {
	var out bootstrapOutcome
	err := conn.QueryRow(ctx, `SELECT id::text FROM core.instances WHERE issuer = $1`, issuer).Scan(&out.InstanceID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if err := instanceCreateWith(ctx, conn, root, w, issuer, ""); err != nil {
			return out, err
		}
		if err := conn.QueryRow(ctx, `SELECT id::text FROM core.instances WHERE issuer = $1`,
			issuer).Scan(&out.InstanceID); err != nil {
			return out, err
		}
	case err != nil:
		return out, err
	default:
		// A run stopped between the instance and its keys has to be able to finish.
		if _, err := keys.Ensure(ctx, conn, out.InstanceID, root, keys.ES256, keys.RS256); err != nil {
			return out, fmt.Errorf("ensuring signing keys: %w", err)
		}
		fmt.Fprintf(w, "instance %s already here\n", out.InstanceID)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	err = tx.QueryRow(ctx, `SELECT id::text FROM core.organizations WHERE instance_id = $1::uuid
		ORDER BY created_at, id LIMIT 1`, out.InstanceID).Scan(&out.OrgID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if err := tx.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
			VALUES ($1::uuid, $2, $3) RETURNING id::text`, out.InstanceID, slug, name).Scan(&out.OrgID); err != nil {
			return out, err
		}
		// As the Admin API records one: filed under the new organisation, so that it
		// has a record of its own beginning.
		if err := audit.Write(ctx, tx, audit.Event{Type: "admin.organization_created", OrgID: out.OrgID,
			Detail: map[string]any{"slug": slug, "instance_id": out.InstanceID}}); err != nil {
			return out, err
		}
		fmt.Fprintf(w, "organisation %s\n  slug %s\n", out.OrgID, slug)
	case err != nil:
		return out, err
	default:
		fmt.Fprintf(w, "organisation %s already here\n", out.OrgID)
	}

	var peopled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE org_id = $1::uuid)`,
		out.OrgID).Scan(&peopled); err != nil {
		return out, err
	}
	if peopled {
		fmt.Fprintln(w, "people are already signing in here, so there is no link to print")
		return out, tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx, `UPDATE core.invitations SET revoked_at = now()
		WHERE org_id = $1::uuid AND used_at IS NULL AND revoked_at IS NULL`, out.OrgID); err != nil {
		return out, err
	}
	_, token, expires, err := store.NewInvitation(ctx, tx, store.InvitationSpec{
		OrgID: out.OrgID, Email: email, TTL: bootstrapLinkLife})
	if err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	out.Link = strings.TrimRight(issuer, "/") + "/signup?invite=" + token
	out.Expires = expires
	return out, nil
}
