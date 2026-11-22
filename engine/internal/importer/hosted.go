package importer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Importing from a hosted identity service (6.26): Auth0, Okta and Entra ID.
//
// Their exports have this in common, and it decides the shape of all three: a
// person's profile comes out, and their password does not. Auth0's bulk export
// holds none, and its hashes come only through a support request whose file it
// does not document (auth0.go); Okta answers a password as a bare `{}` (okta.go);
// Entra exports none (entra.go). By the rule every importer here keeps (keycloak.go,
// "REPORT, DO NOT GUESS"), a person with no password and no link to a provider
// registered here is named and skipped, because an account nobody can sign in to
// is worse than one that was refused.
//
// Two things carry a person across. The organisation's migration source, where it
// has one (docs/password-migration.md): people come in pending, and the source
// checks each one's password at their first sign-in, which then keeps a hash here,
// so nobody has to set a new one. Or a link. Some links come in the export: an
// Auth0 identity at a connection this deployment also has, as a provider with that
// slug. The other is the service itself, kept as an upstream provider here for
// as long as the move takes: -via names it, and every person is linked to it by
// the identifier the export gives them. Whether that service sends the same
// identifier as an ID token's sub is the service's to say, and none of the three
// documents read for this says it; sign in once through it before relying on the
// links. A link that does not match finds nobody: sign-in never matches an account
// by email (federation/decide.go), so a wrong one is refused, never another
// person's account.

// hostedPerson is someone a hosted service's export holds, as these importers
// read them.
type hostedPerson struct {
	// ID is the service's identifier for them.
	ID string
	// KeepID is whether ID may be the account's id here: it is a UUID.
	KeepID   bool
	Email    string
	Verified bool
	Username string
	Given    string
	Surname  string
	Display  string
	// Off is why they are not active there ("blocked", "suspended"), "" when they
	// are: not active there is not active here.
	Off string
	// Links are the export's own links to other providers.
	Links []hostedLink
	// Attributes are text values to declared attributes of the same name.
	Attributes map[string]string
	// Lost names what of theirs this does not carry, counted across people.
	Lost []string
}

type hostedLink struct{ Slug, Subject, Label string }

// hostedSource is what an export said about itself, beyond its people.
type hostedSource struct {
	// Name is the service, for the report.
	Name string
	// Dropped is what the export holds and nothing here is made from.
	Dropped []string
}

// HostedOptions are an import's choices.
type HostedOptions struct {
	Options
	// Via is the slug of the provider registered here that is the service itself;
	// every person is linked to it by their ID. "" for none.
	Via string
}

// importHosted creates the people of a hosted service's export, in the caller's
// transaction; a dry run is the same import rolled back.
func importHosted(ctx context.Context, tx pgx.Tx, orgID string, src hostedSource, people []hostedPerson,
	opts HostedOptions) (*Result, error) {
	providers := map[string]bool{}
	if opts.Via != "" {
		known, err := providerRegistered(ctx, tx, orgID, opts.Via, providers)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, fmt.Errorf("importer: -via %s names no provider registered in this organisation; register "+
				"%s there with that slug first (`signari idp add`)", opts.Via, src.Name)
		}
	}
	// The organisation's migration source, which checks a pending person's
	// password at their first sign-in (docs/password-migration.md). Where there is
	// one, a person this carries comes in pending, and that is a way in.
	var sourceName string
	var sourceEnabled bool
	if err := tx.QueryRow(ctx, `SELECT display_name, enabled FROM core.migration_sources WHERE org_id = $1::uuid`,
		orgID).Scan(&sourceName, &sourceEnabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("importer: reading the migration source: %w", err)
	}
	pending := 0

	res := &Result{}
	unlinked := map[string]int{}
	attributes := map[string]int{}
	lost := map[string]int{}
	foreignIDs := 0
	for _, p := range people {
		identifier := cmpOr(p.Email, p.Username)
		if identifier == "" {
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("(a person with no address or username, %s "+
				"%s)", src.Name, cmpOr(p.ID, "id unknown")))
			continue
		}
		if p.Off != "" {
			// Importing them would turn on an account somebody turned off.
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("%s (%s in %s)", identifier, p.Off, src.Name))
			continue
		}
		var theirs []hostedLink
		for _, l := range p.Links {
			known, err := providerRegistered(ctx, tx, orgID, l.Slug, providers)
			if err != nil {
				return nil, err
			}
			if known {
				theirs = append(theirs, l)
			} else {
				unlinked[l.Slug]++
			}
		}
		if opts.Via != "" && p.ID != "" {
			theirs = append(theirs, hostedLink{Slug: opts.Via, Subject: p.ID, Label: src.Name})
		}
		if len(theirs) == 0 && sourceName == "" {
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("%s (no password comes out of %s, and there is "+
				"no link to a provider registered here and no migration source to check one; set up either, then "+
				"import again, or they must use recovery)", identifier, src.Name))
			continue
		}
		subject := ""
		if p.KeepID {
			subject = p.ID
		}
		who, err := importPerson(ctx, tx, orgID, person{Email: p.Email, Username: p.Username, Given: p.Given,
			Surname: p.Surname, Display: cmpOr(p.Display, strings.TrimSpace(p.Given+" "+p.Surname)),
			Verified: p.Verified, Subject: subject, Pending: sourceName != ""})
		if err != nil {
			return nil, fmt.Errorf("importer: creating %s: %w", identifier, err)
		}
		if who.Refused != "" {
			res.UsersSkipped = append(res.UsersSkipped, identifier+" ("+who.Refused+")")
			continue
		}
		if who.New {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}
		if sourceName != "" {
			pending++
		}
		if p.KeepID && who.ID == p.ID {
			res.SubjectsKept++
		} else if p.ID != "" {
			foreignIDs++
		}
		for _, l := range theirs {
			linked, why, err := importLink(ctx, tx, orgID, l.Slug, who.ID, l.Subject)
			if err != nil {
				return nil, err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's link to %s as %s (%s)", identifier, l.Label,
					l.Subject, why))
			} else if linked {
				res.LinksImported++
			}
		}
		for _, name := range sortedKeys(p.Attributes) {
			if opts.Root == nil {
				attributes[name+" (no root key was given to seal it)"]++
				continue
			}
			n, err := importKeycloakAttribute(ctx, tx, orgID, who.ID, name, []string{p.Attributes[name]}, opts.Root)
			if err != nil {
				return nil, fmt.Errorf("importer: %s's %s: %w", identifier, name, err)
			}
			if n == 0 {
				attributes[name+" (declare an attribute of that name, then import again)"]++
			}
			res.AttributesImported += n
		}
		for _, l := range p.Lost {
			lost[l]++
		}
	}
	if pending > 0 {
		state := "it is enabled"
		if !sourceEnabled {
			state = "it is disabled: test it with `signari migration-source test`, then enable it"
		}
		res.Dropped = append(res.Dropped, fmt.Sprintf("the passwords of %d people (none comes out of %s; they "+
			"come in pending, and the migration source %s checks each one's at their first sign-in; %s)", pending,
			src.Name, sourceName, state))
	}
	if foreignIDs > 0 {
		res.Dropped = append(res.Dropped, fmt.Sprintf("the %s identifiers of %d people (an account here has an id "+
			"of its own, which is what applications are sent as sub; one that keyed its accounts on the "+
			"identifier %s gave them meets strangers until it is told the new one)", src.Name, foreignIDs, src.Name))
	}
	for _, s := range sortedKeys(unlinked) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%d link(s) to %s (no provider here has that slug; if it "+
			"is one, register it with that slug and import again)", unlinked[s], s))
	}
	for _, a := range sortedKeys(attributes) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("attribute %s, on %d", a, attributes[a]))
	}
	for _, l := range sortedKeys(lost) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%s of %d people (nothing here holds it)", l, lost[l]))
	}
	res.Dropped = append(res.Dropped, src.Dropped...)
	return res, nil
}
