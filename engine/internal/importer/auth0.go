package importer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Importing from Auth0 (6.26).
//
// The file is its bulk user export in the JSON-compatible format, which is
// NDJSON, one person to a line (Bulk Export User Data,
// specs/exports/auth0-bulk-user-exports.txt:89-93, read 5 November 2026). Its
// CSV form is refused: it cannot hold app_metadata or user_metadata as objects
// (:221-226), nor the identities a person is linked to, and those are what
// carries a person here. A person's fields are the normalised profile's
// (User Profile Attribute Schema, auth0-user-profile-structure.md, cited by line
// below), as many of them as the export asked for.
//
// No password is in it. Auth0 gives hashes only through a support request,
// PGP-encrypted, and documents the request and not the file
// (auth0-export-password-hashes.md:123-168), so this does not read one.

// auth0Person is one line of the export.
type auth0Person struct {
	UserID        string `json:"user_id"`        // :127-129, unique
	Email         string `json:"email"`          // :31-35
	EmailVerified bool   `json:"email_verified"` // :37-39
	Username      string `json:"username"`       // :135-139
	GivenName     string `json:"given_name"`     // :47-51
	FamilyName    string `json:"family_name"`    // :41-45
	Name          string `json:"name"`           // :93-97
	Nickname      string `json:"nickname"`       // :99-103
	Picture       string `json:"picture"`        // :115-117
	PhoneNumber   string `json:"phone_number"`   // :105-109
	Blocked       bool   `json:"blocked"`        // :19-21
	// :57-65: the connection, its provider, and the person's identifier there.
	Identities []struct {
		Connection string `json:"connection"`
		Provider   string `json:"provider"`
		UserID     string `json:"user_id"`
	} `json:"identities"`
	UserMetadata map[string]any  `json:"user_metadata"` // :131-133
	AppMetadata  map[string]any  `json:"app_metadata"`  // :15-17, what decides access
	Multifactor  []string        `json:"multifactor"`   // :85-87
	Guardian     json.RawMessage `json:"guardian_authenticators"`
}

// Auth0Export is a parsed export.
type Auth0Export struct{ people []auth0Person }

// ParseAuth0 reads an export.
func ParseAuth0(r io.Reader) (*Auth0Export, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(512)
	if t := bytes.TrimSpace(head); len(t) > 0 && t[0] != '{' {
		return nil, fmt.Errorf("importer: this is not Auth0's JSON export: export the users as JSON, which is one " +
			"person to a line; a CSV export cannot hold the identities that link a person to a provider here")
	}
	dec := json.NewDecoder(br)
	var exp Auth0Export
	for line := 1; ; line++ {
		var p auth0Person
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("importer: reading person %d of the Auth0 export: %w", line, err)
		}
		exp.people = append(exp.people, p)
	}
	if len(exp.people) == 0 {
		return nil, fmt.Errorf("importer: the Auth0 export holds nobody")
	}
	return &exp, nil
}

// ImportAuth0 creates the export's people, in one transaction.
func ImportAuth0(ctx context.Context, tx pgx.Tx, orgID string, exp *Auth0Export, opts HostedOptions) (*Result, error) {
	people := make([]hostedPerson, 0, len(exp.people))
	for _, a := range exp.people {
		p := hostedPerson{ID: a.UserID, Email: a.Email, Verified: a.EmailVerified, Username: a.Username,
			Given: strings.TrimSpace(a.GivenName), Surname: strings.TrimSpace(a.FamilyName),
			Display: strings.TrimSpace(a.Name), Attributes: map[string]string{}}
		if a.Blocked {
			p.Off = "blocked"
		}
		for _, id := range a.Identities {
			if id.Connection == "" || id.UserID == "" {
				continue
			}
			// A provider here answers to the connection's name as a slug, the rule
			// links from Zitadel resolve by.
			p.Links = append(p.Links, hostedLink{Slug: zitadelSlug(id.Connection), Subject: id.UserID,
				Label: "connection " + id.Connection})
		}
		for _, k := range sortedKeys(a.UserMetadata) {
			if s, ok := a.UserMetadata[k].(string); ok {
				p.Attributes[k] = s
			} else {
				p.Lost = append(p.Lost, "user_metadata "+k+" (not text)")
			}
		}
		if len(a.AppMetadata) > 0 {
			p.Lost = append(p.Lost, "app_metadata (it decided access there; grant groups here instead)")
		}
		if len(a.Multifactor) > 0 || zitadelCount(a.Guardian) > 0 {
			p.Lost = append(p.Lost, "the second factors (the export holds no secret of theirs)")
		}
		for name, v := range map[string]string{"the nickname": a.Nickname, "the picture": a.Picture,
			"the phone number": a.PhoneNumber} {
			if v != "" {
				p.Lost = append(p.Lost, name)
			}
		}
		people = append(people, p)
	}
	return importHosted(ctx, tx, orgID, hostedSource{Name: "Auth0", Dropped: []string{
		"every password (Auth0's bulk export holds none; its hashes come through a support request, and the " +
			"file it sends is not documented, so they are not read)"}}, people, opts)
}
