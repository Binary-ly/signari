package importer

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/passwords"
)

// Importing from Zitadel.
//
// The file is the answer of its Admin API's export, POST /admin/v1/export
// with with_passwords and with_otp (proto/zitadel/admin.proto:4329-4333,
// 9431-9482, at the pinned 6fdb745): ExportDataResponse, a list of
// organisations, as protojson writes it, lowerCamelCase
// (internal/api/grpc/server/gateway.go:38-42). The snake_case spelling
// protojson also reads is accepted.
//
// What the export holds is what internal/api/grpc/admin/export.go writes:
// a person's name, address and verification, password hash and TOTP secret
// (:551-623), IdP links with the IdP's name (:465-490), project roles and the
// grants of them, organisation and project members, metadata. An OIDC
// application is written without its client ID or secret (:802-822), so the
// applications are named, with what to register, not created.

// ZitadelExport is a parsed export.
type ZitadelExport struct {
	Orgs []zitadelOrg `json:"orgs"`
}

type zitadelOrg struct {
	OrgID string `json:"orgId"`
	Org   struct {
		Name string `json:"name"`
	} `json:"org"`
	Projects []struct {
		ProjectID string `json:"projectId"`
		Project   struct {
			Name string `json:"name"`
		} `json:"project"`
	} `json:"projects"`
	ProjectRoles []struct {
		ProjectID   string `json:"projectId"`
		RoleKey     string `json:"roleKey"`
		DisplayName string `json:"displayName"`
	} `json:"projectRoles"`
	OIDCApps []struct {
		App struct {
			ProjectID              string   `json:"projectId"`
			Name                   string   `json:"name"`
			RedirectURIs           []string `json:"redirectUris"`
			PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
		} `json:"app"`
	} `json:"oidcApps"`
	APIApps []struct {
		App struct {
			ProjectID string `json:"projectId"`
			Name      string `json:"name"`
		} `json:"app"`
	} `json:"apiApps"`
	HumanUsers   []zitadelHuman `json:"humanUsers"`
	MachineUsers []struct {
		UserID string `json:"userId"`
		User   struct {
			UserName string `json:"userName"`
		} `json:"user"`
	} `json:"machineUsers"`
	UserGrants []struct {
		UserID    string   `json:"userId"`
		ProjectID string   `json:"projectId"`
		RoleKeys  []string `json:"roleKeys"`
	} `json:"userGrants"`
	OrgMembers []struct {
		UserID string   `json:"userId"`
		Roles  []string `json:"roles"`
	} `json:"orgMembers"`
	ProjectMembers []struct {
		ProjectID string   `json:"projectId"`
		UserID    string   `json:"userId"`
		Roles     []string `json:"roles"`
	} `json:"projectMembers"`
	UserMetadata []struct {
		ID    string `json:"id"`
		Key   string `json:"key"`
		Value string `json:"value"` // bytes, so base64
	} `json:"userMetadata"`
	UserLinks []struct {
		UserID         string `json:"userId"`
		IdpName        string `json:"idpName"`
		ProvidedUserID string `json:"providedUserId"`
	} `json:"userLinks"`
	// Everything else the organisation holds, by field, to be named.
	rest map[string]json.RawMessage
}

// zitadelHuman is a DataHumanUser (proto/zitadel/v1.proto:172-176) holding
// an ImportHumanUserRequest (management.proto:8674).
type zitadelHuman struct {
	UserID string          `json:"userId"`
	State  json.RawMessage `json:"state"`
	User   struct {
		UserName string `json:"userName"`
		Profile  struct {
			FirstName   string `json:"firstName"`
			LastName    string `json:"lastName"`
			NickName    string `json:"nickName"`
			DisplayName string `json:"displayName"`
		} `json:"profile"`
		Email *struct {
			Email           string `json:"email"`
			IsEmailVerified bool   `json:"isEmailVerified"`
		} `json:"email"`
		Phone *struct {
			Phone string `json:"phone"`
		} `json:"phone"`
		HashedPassword *struct {
			Value string `json:"value"`
		} `json:"hashedPassword"`
		OTPCode string `json:"otpCode"`
	} `json:"user"`
}

// zitadelRead are the organisation's fields this reads.
var zitadelRead = []string{"orgId", "org", "projects", "projectRoles", "oidcApps", "apiApps", "humanUsers",
	"machineUsers", "userGrants", "orgMembers", "projectMembers", "userMetadata", "userLinks"}

// zitadelStates are user.proto:55-61's, by number for an export written
// with enums as numbers.
var zitadelStates = map[string]string{"0": "USER_STATE_UNSPECIFIED", "1": "USER_STATE_ACTIVE",
	"2": "USER_STATE_INACTIVE", "3": "USER_STATE_DELETED", "4": "USER_STATE_LOCKED", "5": "USER_STATE_SUSPEND",
	"6": "USER_STATE_INITIAL"}

// camelKeys rewrites every object key from snake_case to lowerCamelCase, the
// two spellings protojson reads.
func camelKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			parts := strings.Split(k, "_")
			for i := 1; i < len(parts); i++ {
				if parts[i] != "" {
					parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
				}
			}
			out[strings.Join(parts, "")] = camelKeys(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = camelKeys(t[i])
		}
	}
	return v
}

// ParseZitadel reads an export.
func ParseZitadel(r io.Reader) (*ZitadelExport, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("importer: reading the Zitadel export: %w (expected the JSON its Admin API's "+
			"export answers)", err)
	}
	body, err := json.Marshal(camelKeys(raw))
	if err != nil {
		return nil, err
	}
	var exp ZitadelExport
	if err := json.Unmarshal(body, &exp); err != nil {
		return nil, fmt.Errorf("importer: reading the Zitadel export: %w", err)
	}
	var orgs struct {
		Orgs []map[string]json.RawMessage `json:"orgs"`
	}
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, err
	}
	for i := range exp.Orgs {
		exp.Orgs[i].rest = map[string]json.RawMessage{}
		for k, v := range orgs.Orgs[i] {
			if !slices.Contains(zitadelRead, k) {
				exp.Orgs[i].rest[k] = v
			}
		}
	}
	if len(exp.Orgs) == 0 {
		return nil, fmt.Errorf("importer: this does not look like a Zitadel export: it holds no organisation")
	}
	return &exp, nil
}

// ZitadelResult reports what an import did.
type ZitadelResult struct {
	Result
	HashFormats map[string]int
}

var zitadelSlugPart = regexp.MustCompile(`[^a-z0-9]+`)

// zitadelSlug is the slug a provider here has for links to an IdP of that
// name to resolve: lower case, other characters hyphens.
func zitadelSlug(name string) string {
	return strings.Trim(zitadelSlugPart.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// ImportZitadel creates the people and groups of the export's one
// organisation, in one transaction; a dry run is the same import rolled back.
func ImportZitadel(ctx context.Context, tx pgx.Tx, orgID string, exp *ZitadelExport, opts Options) (*ZitadelResult,
	error) {
	if len(exp.Orgs) != 1 {
		return nil, fmt.Errorf("importer: the export holds %d organisations; export them one at a time, naming "+
			"each in org_ids, and import each into its own organisation here", len(exp.Orgs))
	}
	o := exp.Orgs[0]
	res := &ZitadelResult{HashFormats: map[string]int{}}

	projects := map[string]string{}
	for _, p := range o.Projects {
		projects[p.ProjectID] = p.Project.Name
	}
	// A project role is a group, project.role: who holds a role is what a
	// policy here names.
	roles := map[string]string{}
	taken := map[string]string{}
	for _, r := range o.ProjectRoles {
		project := cmpOr(projects[r.ProjectID], r.ProjectID)
		label := project + "." + r.RoleKey
		name := groupNameOf("/" + strings.ReplaceAll(project, "/", "-") + "/" + strings.ReplaceAll(r.RoleKey, "/", "-"))
		switch {
		case name == "":
			res.Dropped = append(res.Dropped, fmt.Sprintf("role %s (it makes no group name of at most 64 letters, "+
				"digits, dots, hyphens and underscores)", label))
			continue
		case taken[name] != "":
			res.Dropped = append(res.Dropped, fmt.Sprintf("role %s (it would be group %s, as %s is)", label, name,
				taken[name]))
			continue
		}
		taken[name] = label
		roles[r.ProjectID+"\x00"+r.RoleKey] = name
		res.Renamed = append(res.Renamed, fmt.Sprintf("role %s of project %s is group %s", r.RoleKey, project, name))
		created, err := importGroup(ctx, tx, orgID, name, cmpOr(r.DisplayName, r.RoleKey),
			"From Zitadel, role "+r.RoleKey+" of project "+project)
		if err != nil {
			return nil, err
		}
		if created {
			res.GroupsCreated++
		}
	}
	held := map[string][]string{}
	for _, g := range o.UserGrants {
		for _, k := range g.RoleKeys {
			if name, ok := roles[g.ProjectID+"\x00"+k]; ok {
				held[g.UserID] = append(held[g.UserID], name)
			} else {
				res.Dropped = append(res.Dropped, fmt.Sprintf("a grant of role %s of project %s (no such role came "+
					"across)", k, cmpOr(projects[g.ProjectID], g.ProjectID)))
			}
		}
	}
	links := map[string][]struct{ slug, subject, name string }{}
	for _, l := range o.UserLinks {
		links[l.UserID] = append(links[l.UserID], struct{ slug, subject, name string }{zitadelSlug(l.IdpName),
			l.ProvidedUserID, l.IdpName})
	}
	metadata := map[string]map[string]string{}
	for _, m := range o.UserMetadata {
		v, err := base64.StdEncoding.DecodeString(m.Value)
		if err != nil || !utf8.Valid(v) {
			res.Dropped = append(res.Dropped, fmt.Sprintf("metadata %s of a person (not text)", m.Key))
			continue
		}
		if metadata[m.ID] == nil {
			metadata[m.ID] = map[string]string{}
		}
		metadata[m.ID][m.Key] = string(v)
	}
	members := map[string][]string{}
	for _, m := range o.OrgMembers {
		members[m.UserID] = append(members[m.UserID], m.Roles...)
	}
	for _, m := range o.ProjectMembers {
		for _, r := range m.Roles {
			members[m.UserID] = append(members[m.UserID], r+" on project "+cmpOr(projects[m.ProjectID], m.ProjectID))
		}
	}

	providers := map[string]bool{}
	unlinked := map[string]int{}
	attributes := map[string]int{}
	extras := 0
	imported := 0
	for _, h := range o.HumanUsers {
		u := h.User
		email := ""
		verified := false
		if u.Email != nil {
			email, verified = u.Email.Email, u.Email.IsEmailVerified
		}
		identifier := cmpOr(email, u.UserName)
		if identifier == "" {
			res.UsersSkipped = append(res.UsersSkipped, "(a user with no username or email)")
			continue
		}
		hash := ""
		if u.HashedPassword != nil {
			hash = u.HashedPassword.Value
		}
		res.HashFormats[hashFormatName(hash)]++

		state := strings.Trim(string(h.State), `"`)
		if s, ok := zitadelStates[state]; ok {
			state = s
		}
		if state != "USER_STATE_ACTIVE" && state != "USER_STATE_INITIAL" && state != "" {
			// Not active there is not active here: importing them would
			// re-enable an account somebody turned off.
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("%s (%s in Zitadel)", identifier,
				strings.ToLower(strings.TrimPrefix(state, "USER_STATE_"))))
			continue
		}

		var theirs []struct{ slug, subject, name string }
		for _, l := range links[h.UserID] {
			known, err := providerRegistered(ctx, tx, orgID, l.slug, providers)
			if err != nil {
				return nil, err
			}
			if known {
				theirs = append(theirs, l)
			} else {
				unlinked[l.slug]++
			}
		}
		verifiable := passwords.CanVerify(hash)
		if !verifiable && len(theirs) == 0 {
			reason := fmt.Sprintf("password format %q cannot be verified here", hashFormatName(hash))
			if err := passwords.CostRefusal(hash); err != nil {
				reason = fmt.Sprintf("its password hash costs more than this server verifies: %v", err)
			}
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf("%s (%s, and no link to a provider registered "+
				"here; they must use recovery or delegated sign-in)", identifier, reason))
			continue
		}

		given, surname := strings.TrimSpace(u.Profile.FirstName), strings.TrimSpace(u.Profile.LastName)
		who, err := importPerson(ctx, tx, orgID, person{Email: email, Username: u.UserName, Given: given,
			Surname: surname, Display: cmpOr(strings.TrimSpace(u.Profile.DisplayName),
				strings.TrimSpace(given+" "+surname)), Verified: verified, Pending: verifiable})
		if err != nil {
			return nil, fmt.Errorf("importer: creating user %s: %w", identifier, err)
		}
		if who.Refused != "" {
			res.UsersSkipped = append(res.UsersSkipped, identifier+" ("+who.Refused+")")
			continue
		}
		imported++
		userID := who.ID
		if who.New {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}
		if verifiable {
			// Pending, so the first sign-in verifies it and replaces it with
			// Argon2id, as for every foreign hash.
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, source_system, is_current)
				VALUES ($1::uuid, $2::uuid, $3, 'zitadel', 'zitadel', false)
				ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash, algorithm = 'zitadel',
					source_system = 'zitadel', is_current = false, updated_at = now()`,
				userID, orgID, hash); err != nil {
				return nil, fmt.Errorf("importing the password for %q: %w", identifier, err)
			}
		}
		for _, name := range held[h.UserID] {
			added, err := importMembership(ctx, tx, orgID, name, userID)
			if err != nil {
				return nil, err
			}
			if added {
				res.Memberships++
			}
		}
		if u.OTPCode != "" {
			ok, why, err := importZitadelOTP(ctx, tx, orgID, userID, u.OTPCode, opts)
			if err != nil {
				return nil, err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's TOTP (%s)", identifier, why))
			} else if ok {
				res.OTPImported++
			}
		}
		for _, l := range theirs {
			linked, why, err := importLink(ctx, tx, orgID, l.slug, userID, l.subject)
			if err != nil {
				return nil, err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's link to %s as %s (%s)", identifier, l.name,
					l.subject, why))
			} else if linked {
				res.LinksImported++
			}
		}
		for _, key := range sortedKeys(metadata[h.UserID]) {
			n, err := importKeycloakAttribute(ctx, tx, orgID, userID, key, []string{metadata[h.UserID][key]}, opts.Root)
			if err != nil {
				return nil, fmt.Errorf("importer: %s's metadata %s: %w", identifier, key, err)
			}
			if n == 0 {
				attributes[key]++
			}
			res.AttributesImported += n
		}
		if r := members[h.UserID]; len(r) > 0 {
			res.Dropped = append(res.Dropped, fmt.Sprintf("%s's administrative roles %s (nothing is granted here; "+
				"grant what they need explicitly)", identifier, strings.Join(r, ", ")))
		}
		if u.Profile.NickName != "" || u.Phone != nil {
			extras++
		}
	}
	if imported > 0 {
		// userinfo.go:167: the subject is the user's ID, a number written as
		// text, and an id here is a UUID.
		res.Dropped = append(res.Dropped, fmt.Sprintf("the subjects of %d people (Zitadel sent each person's user "+
			"ID as sub; here applications are sent the account's id, so one that keyed accounts on sub meets "+
			"strangers)", imported))
	}
	if extras > 0 {
		res.Dropped = append(res.Dropped, fmt.Sprintf("the nicknames and phone numbers of %d people (nothing here "+
			"holds them)", extras))
	}
	for _, s := range sortedKeys(unlinked) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%d link(s) to IdP slug %s (register a provider here with "+
			"that slug, then import again)", unlinked[s], s))
	}
	for _, a := range sortedKeys(attributes) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("metadata %s on %d (declare an attribute of that name, then "+
			"import again)", a, attributes[a]))
	}
	for _, m := range o.MachineUsers {
		res.UsersSkipped = append(res.UsersSkipped, m.User.UserName+" (a machine user: it signs in with a key or "+
			"a secret, which are not carried; register what uses it as a client)")
	}
	for _, a := range o.OIDCApps {
		res.Dropped = append(res.Dropped, fmt.Sprintf("OIDC application %s of project %s (the export holds no "+
			"client ID or secret: register it with `signari client create -client-id <the ID it uses>`; its "+
			"redirect URIs are %s, its post-logout ones %s)", a.App.Name, cmpOr(projects[a.App.ProjectID],
			a.App.ProjectID), zitadelList(a.App.RedirectURIs), zitadelList(a.App.PostLogoutRedirectURIs)))
	}
	for _, a := range o.APIApps {
		res.Dropped = append(res.Dropped, fmt.Sprintf("API application %s of project %s (the export holds no "+
			"client ID or secret)", a.App.Name, cmpOr(projects[a.App.ProjectID], a.App.ProjectID)))
	}
	for _, k := range sortedKeys(o.rest) {
		if n := zitadelCount(o.rest[k]); n > 0 {
			res.Dropped = append(res.Dropped, fmt.Sprintf("%s: %d (nothing here is made from it)", k, n))
		}
	}
	return res, nil
}

// zitadelList is a list for the report.
func zitadelList(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}

// zitadelCount is how many things a field holds: a list's length, else one
// for anything set.
func zitadelCount(raw json.RawMessage) int {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		return len(list)
	}
	if t := bytes.TrimSpace(raw); len(t) == 0 || string(t) == "null" || string(t) == "{}" || string(t) == `""` {
		return 0
	}
	return 1
}

// importZitadelOTP assigns the TOTP secret, base32, SHA-1, six digits every
// thirty seconds, as Zitadel enrols it (its enrolment URI,
// apps/docs/content/guides/integrate/login-ui/mfa.mdx:60, made by
// internal/domain/human_otp.go:19 and checked at :32 with the library's own
// settings).
func importZitadelOTP(ctx context.Context, tx pgx.Tx, orgID, userID, code string, opts Options) (bool, string,
	error) {
	v := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(code, " ", ""), "="))
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(v)
	if err != nil || len(seed) == 0 {
		return false, "its secret is not base32", nil
	}
	return importOTP(ctx, tx, orgID, userID, seed, "totp",
		mfa.Params{Algorithm: mfa.SHA1, Digits: 6, Period: 30 * time.Second}, 0, opts.Root)
}
