package importer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Importing from Okta (6.26).
//
// Okta has no export file: the people are what its users API lists, User objects,
// an array of them a page. This reads those pages, saved one after another into
// one file, or one User to a line. The fields are the Management API's User
// schemas (specs/exports/okta-user-schemas.txt, made from the User tag's own data
// on developer.okta.com, read 5 November 2026), cited by line below.
//
// No password is in it: a password in an answer is a bare object, `{}`, saying
// only that one exists (:42). Who signs in against a directory or another
// provider there is in credentials.provider (:88, its types at :6-7).

type oktaUser struct {
	ID     string `json:"id"`     // :73
	Status string `json:"status"` // :79, the values at :129
	// :77, UserProfile at :96-127. Read whole, so what is not carried is named.
	Profile     map[string]json.RawMessage `json:"profile"`
	Credentials struct {
		Provider struct {
			Type string `json:"type"` // :5, AuthenticationProviderType :6-7
			Name string `json:"name"` // :4
		} `json:"provider"`
	} `json:"credentials"`
}

// oktaProfileRead are the profile fields this reads (:101-110).
var oktaProfileRead = []string{"login", "email", "firstName", "lastName", "displayName"}

// oktaOff are the statuses (:129) of somebody turned off there. The others are
// somebody Okta lets sign in, or will once they finish setting up: STAGED and
// PROVISIONED have not activated, PASSWORD_EXPIRED, RECOVERY and LOCKED_OUT are
// partway through something a sign-in here replaces.
var oktaOff = map[string]string{"SUSPENDED": "suspended", "DEPROVISIONED": "deactivated"}

// OktaExport is a parsed export.
type OktaExport struct{ users []oktaUser }

// ParseOkta reads the listed users: arrays of them, or one to a line.
func ParseOkta(r io.Reader) (*OktaExport, error) {
	dec := json.NewDecoder(bufio.NewReader(r))
	var exp OktaExport
	for n := 1; ; n++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("importer: reading part %d of the Okta users: %w (expected what its users "+
				"API lists, User objects)", n, err)
		}
		var page []oktaUser
		if err := json.Unmarshal(raw, &page); err != nil {
			var one oktaUser
			if err := json.Unmarshal(raw, &one); err != nil {
				return nil, fmt.Errorf("importer: part %d of the Okta users is neither a User nor a list of them: %w",
					n, err)
			}
			page = []oktaUser{one}
		}
		exp.users = append(exp.users, page...)
	}
	if len(exp.users) == 0 {
		return nil, fmt.Errorf("importer: the Okta users hold nobody")
	}
	for i, u := range exp.users {
		if u.ID == "" || u.Profile == nil {
			return nil, fmt.Errorf("importer: entry %d is not an Okta User: it has no id or no profile", i+1)
		}
	}
	return &exp, nil
}

func oktaText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// ImportOkta creates the listed people, in one transaction.
func ImportOkta(ctx context.Context, tx pgx.Tx, orgID string, exp *OktaExport, opts HostedOptions) (*Result, error) {
	people := make([]hostedPerson, 0, len(exp.users))
	elsewhere := map[string]int{}
	for _, u := range exp.users {
		p := hostedPerson{ID: u.ID, Username: oktaText(u.Profile["login"]), Email: oktaText(u.Profile["email"]),
			Given: oktaText(u.Profile["firstName"]), Surname: oktaText(u.Profile["lastName"]),
			Display: oktaText(u.Profile["displayName"]), Off: oktaOff[u.Status]}
		// Nothing in a User says the address was confirmed, so it is not taken
		// as confirmed here.
		for _, k := range sortedKeys(u.Profile) {
			if !containsString(oktaProfileRead, k) && zitadelCount(u.Profile[k]) > 0 {
				p.Lost = append(p.Lost, "profile."+k)
			}
		}
		switch t := u.Credentials.Provider.Type; t {
		case "", "OKTA", "IMPORT":
		default:
			elsewhere[t+" "+cmpOr(u.Credentials.Provider.Name, "(unnamed)")]++
		}
		people = append(people, p)
	}
	src := hostedSource{Name: "Okta", Dropped: []string{"every password (Okta answers a password as {}, saying only " +
		"that one exists)"}}
	for _, k := range sortedKeys(elsewhere) {
		src.Dropped = append(src.Dropped, fmt.Sprintf("%d people sign in there against %s, not Okta (a directory "+
			"can be connected here with `signari dir add`, a provider with `signari idp add`)", elsewhere[k], k))
	}
	return importHosted(ctx, tx, orgID, src, people, opts)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
