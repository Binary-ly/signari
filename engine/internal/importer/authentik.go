package importer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/passwords"
)

// Importing from authentik.
//
// # Why the password hashes come across
//
// authentik is a Django application and does not set PASSWORD_HASHERS, so
// Django's defaults apply and the first of those -- the one used for every
// password set -- is PBKDF2PasswordHasher, which writes
//
//	pbkdf2_sha256$<iterations>$<salt>$<base64 hash>
//
// internal/passwords already verifies that format, because it is common to a
// great deal of Python software. So an authentik user signs in here with the
// password they already had, and is transparently upgraded to Argon2id on first
// success. Nobody has to reset anything.
//
// # Why a dumpdata file rather than the API
//
// authentik's REST API never returns password hashes -- Django does not expose
// them, correctly. The portable export that does is Django's own `ak dumpdata`,
// a documented management command, not a private interface, naming the models
// AuthentikModels lists.
//
// # What it is read from
//
// The models at the pinned b2a50ac: authentik/core/models.py for people,
// groups, sources, providers and applications; providers/oauth2 and
// providers/saml; stages/authenticator_totp and authenticator_webauthn for the
// factors. Older shapes are read too, each from the migration that changed it:
// a user's ak_groups (core migrations/0057:29-33), a group's single parent
// (0055:18-26) and newline-separated redirect URIs (oauth2 migrations/0024:10-24).

// AuthentikModels are the models an export should hold, in the order `ak
// dumpdata` takes them. A version that lacks one has it in another shape this
// reads, and the command names it as unknown: leave it out.
var AuthentikModels = []string{
	"authentik_core.user", "authentik_core.group", "authentik_core.usergroup",
	"authentik_core.groupparentagenode", "authentik_core.source", "authentik_core.usersourceconnection",
	"authentik_core.provider", "authentik_core.application", "authentik_providers_oauth2.oauth2provider",
	"authentik_providers_saml.samlprovider", "authentik_stages_authenticator_totp.totpdevice",
	"authentik_stages_authenticator_webauthn.webauthndevice",
}

// authentikRecord is one row of a Django dumpdata file.
type authentikRecord struct {
	Model  string          `json:"model"`
	PK     json.RawMessage `json:"pk"`
	Fields json.RawMessage `json:"fields"`
}

// authentikKey is a primary key, or a reference to one, as text: a number
// or a UUID, so that a key and a reference to it compare equal.
func authentikKey(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func authentikKeys(raws []json.RawMessage) []string {
	var out []string
	for _, r := range raws {
		if k := authentikKey(r); k != "" {
			out = append(out, k)
		}
	}
	return out
}

type authentikUserFields struct {
	Username   string         `json:"username"`
	Name       string         `json:"name"`
	Email      string         `json:"email"`
	Password   string         `json:"password"`
	IsActive   bool           `json:"is_active"`
	UUID       string         `json:"uuid"`
	Type       string         `json:"type"`
	Attributes map[string]any `json:"attributes"`
	// Membership where the export lists it on the person: ak_groups, then
	// groups after the rename. Later exports hold it in usergroup records.
	AKGroups []json.RawMessage `json:"ak_groups"`
	Groups   []json.RawMessage `json:"groups"`
}

type authentikGroupFields struct {
	Name        string          `json:"name"`
	IsSuperuser bool            `json:"is_superuser"`
	Parent      json.RawMessage `json:"parent"`
	Attributes  map[string]any  `json:"attributes"`
}

// authentikPair is a usergroup or a groupparentagenode record.
type authentikPair struct {
	User   json.RawMessage `json:"user"`
	Group  json.RawMessage `json:"group"`
	Child  json.RawMessage `json:"child"`
	Parent json.RawMessage `json:"parent"`
}

type authentikSourceFields struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type authentikConnectionFields struct {
	User       json.RawMessage `json:"user"`
	Source     json.RawMessage `json:"source"`
	Identifier string          `json:"identifier"`
}

type authentikProviderFields struct {
	Name             string            `json:"name"`
	PropertyMappings []json.RawMessage `json:"property_mappings"`
}

type authentikApplicationFields struct {
	Name     string          `json:"name"`
	Slug     string          `json:"slug"`
	Provider json.RawMessage `json:"provider"`
}

// AuthentikOAuth2 is an OAuth2/OpenID provider (oauth2/models.py:219-320).
type AuthentikOAuth2 struct {
	ClientType   string `json:"client_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// RedirectURIs are {matching_mode, url, redirect_uri_type}
	// (models.py:143-149); OldRedirectURIs the newline-separated text before.
	RedirectURIs []struct {
		MatchingMode string `json:"matching_mode"`
		URL          string `json:"url"`
		Type         string `json:"redirect_uri_type"`
	} `json:"_redirect_uris"`
	OldRedirectURIs *string `json:"redirect_uris"`
	// GrantTypes is absent before the field was added, when every grant
	// was allowed (migrations/0032:7-18).
	GrantTypes   *[]string       `json:"grant_types"`
	SubMode      string          `json:"sub_mode"`
	SigningKey   json.RawMessage `json:"signing_key"`
	LogoutURI    string          `json:"logout_uri"`
	LogoutMethod string          `json:"logout_method"`
}

// AuthentikSAML is a SAML provider (saml/models.py:62-241).
type AuthentikSAML struct {
	ACSURL              string          `json:"acs_url"`
	Audience            string          `json:"audience"`
	NameIDMapping       json.RawMessage `json:"name_id_mapping"`
	DefaultNameIDPolicy string          `json:"default_name_id_policy"`
	SLSURL              string          `json:"sls_url"`
}

type authentikTOTPFields struct {
	User      json.RawMessage `json:"user"`
	Confirmed *bool           `json:"confirmed"`
	Key       string          `json:"key"`
	Step      int             `json:"step"`
	T0        int64           `json:"t0"`
	Digits    int             `json:"digits"`
	LastT     *int64          `json:"last_t"`
}

type authentikWebAuthnFields struct {
	User         json.RawMessage `json:"user"`
	Name         string          `json:"name"`
	CredentialID string          `json:"credential_id"`
	PublicKey    string          `json:"public_key"`
	SignCount    int64           `json:"sign_count"`
	RPID         string          `json:"rp_id"`
	AAGUID       string          `json:"aaguid"`
}

// AuthentikExport is a parsed dumpdata file.
type AuthentikExport struct {
	Users  []AuthentikUser
	Groups map[string]string // pk -> group name
	// Parents are each group's direct parents, by pk.
	Parents     map[string][]string
	Superuser   map[string]bool
	GroupAttrs  map[string][]string
	Sources     map[string]string // pk -> slug
	Providers   []AuthentikProvider
	Unparsed    map[string]int // model -> records that would not parse
	NotCarried  map[string]int // model -> records of a model this does not read
	totp        map[string][]authentikTOTPFields
	webauthn    map[string][]authentikWebAuthnFields
	connections map[string][]authentikConnectionFields
}

// AuthentikUser is one imported person.
type AuthentikUser struct {
	PK         string
	UUID       string
	Type       string
	Username   string
	Name       string
	Email      string
	Password   string
	IsActive   bool
	Groups     []string // names
	groupPKs   []string
	Attributes map[string]any
}

// AuthentikProvider is a provider with the application it serves.
type AuthentikProvider struct {
	PK, Name         string
	Application      string
	PropertyMappings int
	OAuth2           *AuthentikOAuth2
	SAML             *AuthentikSAML
}

// ParseAuthentik reads a Django dumpdata export.
func ParseAuthentik(r io.Reader) (*AuthentikExport, error) {
	var records []authentikRecord
	if err := json.NewDecoder(r).Decode(&records); err != nil {
		return nil, fmt.Errorf("importer: reading the authentik export: %w "+
			"(expected the JSON array Django's `ak dumpdata` produces)", err)
	}
	out := &AuthentikExport{Groups: map[string]string{}, Parents: map[string][]string{},
		Superuser: map[string]bool{}, GroupAttrs: map[string][]string{}, Sources: map[string]string{},
		Unparsed: map[string]int{}, NotCarried: map[string]int{},
		totp: map[string][]authentikTOTPFields{}, webauthn: map[string][]authentikWebAuthnFields{},
		connections: map[string][]authentikConnectionFields{}}
	member := map[string][]string{} // user pk -> group pks
	providers := map[string]*AuthentikProvider{}
	var order []string
	oauth2 := map[string]*AuthentikOAuth2{}
	saml := map[string]*AuthentikSAML{}
	apps := map[string]string{} // provider pk -> application name
	var users []authentikRecord

	parse := func(rec authentikRecord, into any) bool {
		if err := json.Unmarshal(rec.Fields, into); err != nil {
			out.Unparsed[rec.Model]++
			return false
		}
		return true
	}
	// References come before what they name in no particular order, so
	// everything is read before a person's groups are resolved.
	for _, rec := range records {
		rec.Model = strings.ToLower(rec.Model)
		pk := authentikKey(rec.PK)
		switch rec.Model {
		case "authentik_core.user":
			users = append(users, rec)
		case "authentik_core.group":
			var g authentikGroupFields
			if parse(rec, &g) && g.Name != "" {
				out.Groups[pk] = g.Name
				out.Superuser[pk] = g.IsSuperuser
				out.GroupAttrs[pk] = sortedKeys(g.Attributes)
				if p := authentikKey(g.Parent); p != "" {
					out.Parents[pk] = append(out.Parents[pk], p)
				}
			}
		case "authentik_core.usergroup":
			var p authentikPair
			if parse(rec, &p) {
				u := authentikKey(p.User)
				member[u] = append(member[u], authentikKey(p.Group))
			}
		case "authentik_core.groupparentagenode":
			var p authentikPair
			if parse(rec, &p) {
				c := authentikKey(p.Child)
				out.Parents[c] = append(out.Parents[c], authentikKey(p.Parent))
			}
		case "authentik_core.source":
			var s authentikSourceFields
			if parse(rec, &s) {
				out.Sources[pk] = s.Slug
			}
		case "authentik_core.usersourceconnection":
			var c authentikConnectionFields
			if parse(rec, &c) {
				u := authentikKey(c.User)
				out.connections[u] = append(out.connections[u], c)
			}
		case "authentik_core.provider":
			var p authentikProviderFields
			if parse(rec, &p) {
				providers[pk] = &AuthentikProvider{PK: pk, Name: p.Name, PropertyMappings: len(p.PropertyMappings)}
				order = append(order, pk)
			}
		case "authentik_core.application":
			var a authentikApplicationFields
			if parse(rec, &a) {
				if p := authentikKey(a.Provider); p != "" {
					apps[p] = a.Name
				}
			}
		case "authentik_providers_oauth2.oauth2provider":
			var o AuthentikOAuth2
			if parse(rec, &o) {
				oauth2[pk] = &o
			}
		case "authentik_providers_saml.samlprovider":
			var s AuthentikSAML
			if parse(rec, &s) {
				saml[pk] = &s
			}
		case "authentik_stages_authenticator_totp.totpdevice":
			var d authentikTOTPFields
			if parse(rec, &d) {
				u := authentikKey(d.User)
				out.totp[u] = append(out.totp[u], d)
			}
		case "authentik_stages_authenticator_webauthn.webauthndevice":
			var d authentikWebAuthnFields
			if parse(rec, &d) {
				u := authentikKey(d.User)
				out.webauthn[u] = append(out.webauthn[u], d)
			}
		default:
			// A source's own kind of person's connection (User<Kind>Source-
			// Connection, e.g. sources/oauth/models.py:324) is the same row as
			// its usersourceconnection, which is what is read.
			if _, model, ok := strings.Cut(rec.Model, "."); ok && strings.HasPrefix(rec.Model, "authentik_sources_") &&
				strings.HasPrefix(model, "user") && strings.HasSuffix(model, "sourceconnection") {
				continue
			}
			out.NotCarried[rec.Model]++
		}
	}

	for _, rec := range users {
		var f authentikUserFields
		if !parse(rec, &f) {
			continue
		}
		pk := authentikKey(rec.PK)
		u := AuthentikUser{PK: pk, UUID: f.UUID, Type: f.Type, Username: f.Username, Name: f.Name,
			Email: f.Email, Password: f.Password, IsActive: f.IsActive, Attributes: f.Attributes}
		for _, g := range slices.Concat(authentikKeys(f.AKGroups), authentikKeys(f.Groups), member[pk]) {
			if name, ok := out.Groups[g]; ok && !slices.Contains(u.groupPKs, g) {
				u.groupPKs = append(u.groupPKs, g)
				u.Groups = append(u.Groups, name)
			}
		}
		out.Users = append(out.Users, u)
	}
	for _, pk := range order {
		p := providers[pk]
		p.Application, p.OAuth2, p.SAML = apps[pk], oauth2[pk], saml[pk]
		out.Providers = append(out.Providers, *p)
	}

	if len(out.Users) == 0 {
		return nil, fmt.Errorf("importer: no authentik_core.user records found. Export with `ak dumpdata %s`",
			strings.Join(AuthentikModels, " "))
	}
	return out, nil
}

// AuthentikResult reports what an import did.
type AuthentikResult struct {
	Result
	// HashFormats counts what was seen, so an operator learns immediately if
	// this deployment stores something we cannot verify -- rather than finding
	// out when people cannot sign in.
	HashFormats map[string]int
}

// authentikUID is what authentik derives from a person's key and its
// installation, `uid` (core/models.py:607-609): the default OAuth2 subject,
// the persistent NameID (providers/saml/processors/assertion.py:243) and
// the user handle every passkey was registered under
// (stages/authenticator_webauthn/stage.py:176). "" without the installation.
func authentikUID(pk, installID string) string {
	if installID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(pk + "-" + installID))
	return hex.EncodeToString(sum[:])
}

// ImportAuthentik creates people, groups and clients from a parsed export.
//
// One transaction, for the same reason as the Keycloak importer: a half-imported
// directory is the worst outcome, because nobody can tell which half. A dry run
// is the same import in a transaction the caller rolls back; it once counted
// every person as created without asking who was here.
func ImportAuthentik(ctx context.Context, tx pgx.Tx, orgID string, exp *AuthentikExport,
	opts Options) (*AuthentikResult, error) {
	res := &AuthentikResult{HashFormats: map[string]int{}}
	groups, err := importAuthentikGroups(ctx, tx, orgID, exp, &res.Result)
	if err != nil {
		return nil, err
	}

	providers := map[string]bool{}
	unlinked := map[string]int{}
	attributes := map[string]int{}
	type nameIDs struct{ userID, identifier, uid string }
	var persistent []nameIDs

	for _, u := range exp.Users {
		identifier := u.Email
		if identifier == "" {
			identifier = u.Username
		}
		if identifier == "" {
			res.UsersSkipped = append(res.UsersSkipped, "(a user with no username or email)")
			continue
		}
		res.HashFormats[hashFormatName(u.Password)]++

		switch u.Type {
		case "internal_service_account":
			// What authentik makes for its outposts (core/models.py:129-131).
			res.BuiltIns = append(res.BuiltIns, "user "+u.Username)
			continue
		case "service_account":
			res.UsersSkipped = append(res.UsersSkipped, identifier+" (a service account: it signs in with "+
				"tokens, which are not carried; register what uses it as a client)")
			continue
		}
		if !u.IsActive {
			// Inactive there means inactive here. Importing them as active would
			// silently re-enable accounts somebody deliberately turned off.
			res.UsersSkipped = append(res.UsersSkipped, identifier+" (inactive in authentik)")
			continue
		}

		// A person signs in with a password, or through a source this
		// organisation has as a provider: either is an account somebody can use.
		var links []authentikConnectionFields
		for _, c := range exp.connections[u.PK] {
			slug := exp.Sources[authentikKey(c.Source)]
			if slug == "" {
				res.Dropped = append(res.Dropped, identifier+"'s link to a source the export does not hold")
				continue
			}
			known, err := providerRegistered(ctx, tx, orgID, slug, providers)
			if err != nil {
				return nil, err
			}
			if known {
				links = append(links, c)
			} else {
				unlinked[slug]++
			}
		}
		verifiable := passwords.CanVerify(u.Password)
		if !verifiable && len(links) == 0 {
			// Named rather than imported without a credential. An account nobody
			// can sign in to is worse than one that was refused out loud.
			reason := fmt.Sprintf("password format %q cannot be verified here", hashFormatName(u.Password))
			if err := passwords.CostRefusal(u.Password); err != nil {
				reason = fmt.Sprintf("its password hash costs more than this server verifies: %v", err)
			}
			res.UsersSkipped = append(res.UsersSkipped, fmt.Sprintf(
				"%s (%s, and no link to a source registered here; they must use recovery or delegated sign-in)",
				identifier, reason))
			continue
		}

		uid := authentikUID(u.PK, opts.InstallID)
		p := person{Email: u.Email, Username: u.Username, Display: strings.TrimSpace(u.Name), Pending: verifiable,
			Subject: u.UUID}
		devices := exp.webauthn[u.PK]
		if len(devices) > 0 && uid != "" {
			p.Handle = []byte(uid)
		}
		who, err := importPerson(ctx, tx, orgID, p)
		if err != nil {
			return nil, fmt.Errorf("importer: creating user %s: %w", identifier, err)
		}
		if who.Refused != "" {
			res.UsersSkipped = append(res.UsersSkipped, identifier+" ("+who.Refused+")")
			continue
		}
		userID := who.ID
		if u.UUID != "" && userID == u.UUID {
			res.SubjectsKept++
		}
		for _, l := range who.Lost {
			res.Dropped = append(res.Dropped, identifier+"'s "+l)
		}
		if who.New {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}

		// is_current = false and migration_state = 'pending' on purpose: that is
		// what routes this credential through the migration path, where the
		// Django hash is verified on first sign-in and replaced with Argon2id in
		// the same transaction. Storing it as current instead would work and
		// would quietly bypass the rehash, leaving a foreign hash in place
		// forever.
		if verifiable {
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.password_credentials
					(user_id, org_id, hash, algorithm, source_system, is_current)
				VALUES ($1::uuid, $2::uuid, $3, 'django-pbkdf2', 'authentik', false)
				ON CONFLICT (user_id) DO UPDATE SET
					hash = EXCLUDED.hash, algorithm = 'django-pbkdf2',
					source_system = 'authentik', is_current = false, updated_at = now()`,
				userID, orgID, u.Password); err != nil {
				return nil, fmt.Errorf("importing the password for %q: %w", identifier, err)
			}
		}

		// Membership, with each group's ancestors: authentik counts a member
		// of a group as a member of every group above it (core/models.py:
		// 238-240, 416-418), and groups here do not nest.
		var in []string
		for _, g := range u.groupPKs {
			for _, a := range append([]string{g}, authentikAncestors(exp, g)...) {
				if name, ok := groups[a]; ok && !slices.Contains(in, name) {
					in = append(in, name)
				}
			}
		}
		for _, name := range in {
			added, err := importMembership(ctx, tx, orgID, name, userID)
			if err != nil {
				return nil, err
			}
			if added {
				res.Memberships++
			}
		}

		if err := importAuthentikFactors(ctx, tx, orgID, userID, identifier, exp, u, uid, who.HandleKept,
			opts, &res.Result); err != nil {
			return nil, err
		}
		for _, l := range links {
			slug := exp.Sources[authentikKey(l.Source)]
			linked, why, err := importLink(ctx, tx, orgID, slug, userID, l.Identifier)
			if err != nil {
				return nil, err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's link to %s as %s (%s)", identifier, slug,
					l.Identifier, why))
			} else if linked {
				res.LinksImported++
			}
		}
		for _, name := range sortedKeys(u.Attributes) {
			value, ok := authentikText(u.Attributes[name])
			if !ok {
				attributes[name]++
				continue
			}
			n, err := importKeycloakAttribute(ctx, tx, orgID, userID, name, []string{value}, opts.Root)
			if err != nil {
				return nil, fmt.Errorf("importer: %s's attribute %s: %w", identifier, name, err)
			}
			if n == 0 {
				attributes[name]++
			}
			res.AttributesImported += n
		}
		if uid != "" {
			persistent = append(persistent, nameIDs{userID, identifier, uid})
		}
	}
	for _, s := range sortedKeys(unlinked) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%d link(s) to source %s (register a provider here with "+
			"that slug, then import again)", unlinked[s], s))
	}
	for _, a := range sortedKeys(attributes) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("attribute %s on %d (declare it, then import again; only "+
			"text comes across)", a, attributes[a]))
	}

	var entities []string
	for _, p := range exp.Providers {
		entity, err := importAuthentikProvider(ctx, tx, orgID, p, opts, &res.Result)
		if err != nil {
			return nil, err
		}
		if entity != "" {
			entities = append(entities, entity)
		}
	}
	// The NameIDs each persistent service provider knows people by.
	for _, entity := range entities {
		if opts.InstallID == "" {
			res.Dropped = append(res.Dropped, fmt.Sprintf("the NameIDs SAML provider %s knows people by "+
				"(authentik makes them from its installation ID; give it with -install-id)", entity))
			continue
		}
		for _, n := range persistent {
			kept, why, err := importNameID(ctx, tx, orgID, entity, n.userID, n.uid)
			if err != nil {
				return nil, err
			}
			if why != "" {
				res.Dropped = append(res.Dropped, fmt.Sprintf("%s's NameID at %s (%s)", n.identifier, entity, why))
			} else if kept {
				res.NameIDsKept++
			}
		}
	}
	for _, m := range sortedKeys(exp.NotCarried) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%d %s record(s) (nothing here is made from them)",
			exp.NotCarried[m], m))
	}
	for _, m := range sortedKeys(exp.Unparsed) {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%d %s record(s) that do not parse", exp.Unparsed[m], m))
	}
	return res, nil
}

// authentikText is an attribute's value as text: a string, or the first of
// a list of them.
func authentikText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case []any:
		if len(t) > 0 {
			s, ok := t[0].(string)
			return s, ok && s != ""
		}
	}
	return "", false
}

// authentikAncestors are every group above g, each once, a cycle included
// only once.
func authentikAncestors(exp *AuthentikExport, g string) []string {
	var out []string
	seen := map[string]bool{g: true}
	next := slices.Clone(exp.Parents[g])
	for len(next) > 0 {
		p := next[0]
		next = next[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		next = append(next, exp.Parents[p]...)
	}
	return out
}

// importAuthentikGroups makes every group, answering each pk's name here.
func importAuthentikGroups(ctx context.Context, tx pgx.Tx, orgID string, exp *AuthentikExport,
	res *Result) (map[string]string, error) {
	pks := sortedKeys(exp.Groups)
	slices.SortFunc(pks, func(a, b string) int { return strings.Compare(exp.Groups[a], exp.Groups[b]) })
	names := map[string]string{}
	taken := map[string]string{}
	for _, pk := range pks {
		display := exp.Groups[pk]
		name := groupNameOf("/" + strings.ReplaceAll(display, "/", "-"))
		switch {
		case name == "":
			res.Dropped = append(res.Dropped, fmt.Sprintf("group %s (its name makes no name of at most 64 letters, "+
				"digits, dots, hyphens and underscores)", display))
			continue
		case taken[name] != "":
			res.Dropped = append(res.Dropped, fmt.Sprintf("group %s (it would be named %s, as %s is)", display, name,
				taken[name]))
			continue
		}
		taken[name] = display
		names[pk] = name
		if name != display {
			res.Renamed = append(res.Renamed, fmt.Sprintf("group %s is %s", display, name))
		}
		created, err := importGroup(ctx, tx, orgID, name, display, "From authentik")
		if err != nil {
			return nil, err
		}
		if created {
			res.GroupsCreated++
		}
		if exp.Superuser[pk] {
			// Fails closed: nobody is an administrator here by having been one
			// there. Capabilities attach to a group one by one.
			res.Dropped = append(res.Dropped, fmt.Sprintf("group %s's superuser flag (nothing is granted here; "+
				"grant what its members need explicitly)", display))
		}
		if a := exp.GroupAttrs[pk]; len(a) > 0 {
			res.Dropped = append(res.Dropped, fmt.Sprintf("group %s's attributes %s", display, strings.Join(a, ", ")))
		}
		if up := authentikAncestors(exp, pk); len(up) > 0 {
			var above []string
			for _, a := range up {
				above = append(above, exp.Groups[a])
			}
			res.Dropped = append(res.Dropped, fmt.Sprintf("the nesting of group %s under %s (its members are made "+
				"members of those too, as authentik counts them, since groups here do not nest)", display,
				strings.Join(above, ", ")))
		}
	}
	return names, nil
}

// importAuthentikFactors brings a person's TOTP device and passkeys.
func importAuthentikFactors(ctx context.Context, tx pgx.Tx, orgID, userID, identifier string, exp *AuthentikExport,
	u AuthentikUser, uid string, handleKept bool, opts Options, res *Result) error {
	otp := false
	for _, d := range exp.totp[u.PK] {
		if d.Confirmed != nil && !*d.Confirmed {
			res.Dropped = append(res.Dropped, identifier+"'s unconfirmed TOTP device (enrolment never finished)")
			continue
		}
		if otp {
			res.Dropped = append(res.Dropped, identifier+"'s second TOTP device (one is held here)")
			continue
		}
		otp = true
		imported, why, err := importAuthentikTOTP(ctx, tx, orgID, userID, d, opts)
		if err != nil {
			return err
		}
		if why != "" {
			res.Dropped = append(res.Dropped, fmt.Sprintf("%s's TOTP device (%s)", identifier, why))
		} else if imported {
			res.OTPImported++
		}
	}
	devices := exp.webauthn[u.PK]
	if len(devices) == 0 {
		return nil
	}
	if uid == "" {
		res.Dropped = append(res.Dropped, fmt.Sprintf("%s's %d passkey(s) (registered under a user handle authentik "+
			"makes from its installation ID, which sign-in must match; give it with -install-id)", identifier,
			len(devices)))
		return nil
	}
	if !handleKept {
		return nil
	}
	for _, d := range devices {
		imported, why, err := importAuthentikPasskey(ctx, tx, orgID, userID, d)
		if err != nil {
			return err
		}
		if why != "" {
			res.Dropped = append(res.Dropped, fmt.Sprintf("%s's passkey %s (%s)", identifier, d.Name, why))
		} else if imported {
			res.PasskeysImported++
		}
	}
	return nil
}

// importAuthentikTOTP assigns a device's seed: hex (totp/models.py:66-74,
// 124-129), HMAC-SHA1 (stages/authenticator/oath.py:4,36, and SHA1 in the
// URI enrolment shows, totp/models.py:210), its step and digits, and the
// last step used, which counts steps as the counter here does (oath.py:143-145).
func importAuthentikTOTP(ctx context.Context, tx pgx.Tx, orgID, userID string, d authentikTOTPFields,
	opts Options) (bool, string, error) {
	seed, err := hex.DecodeString(d.Key)
	if err != nil || len(seed) == 0 {
		return false, "its key is not hex", nil
	}
	if d.T0 != 0 {
		return false, "it counts steps from a start time other than the epoch, which nothing here does", nil
	}
	step, digits := d.Step, d.Digits
	if step == 0 {
		step = 30
	}
	if digits == 0 {
		digits = 6
	}
	last := int64(0)
	if d.LastT != nil && *d.LastT > 0 {
		last = *d.LastT
	}
	return importOTP(ctx, tx, orgID, userID, seed, "totp",
		mfa.Params{Algorithm: mfa.SHA1, Digits: digits, Period: time.Duration(step) * time.Second}, last, opts.Root)
}

// importAuthentikPasskey saves a device, its id and COSE key base64url as
// authentik wrote them (webauthn/stage.py:231-232), under the relying party ID
// it was registered with (:234).
func importAuthentikPasskey(ctx context.Context, tx pgx.Tx, orgID, userID string,
	d authentikWebAuthnFields) (bool, string, error) {
	id, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(d.CredentialID, "="))
	if err != nil || len(id) == 0 {
		return false, "its credential id does not decode", nil
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(d.PublicKey, "="))
	if err != nil {
		return false, "its public key does not decode", nil
	}
	var aaguid []byte
	if a, err := uuid.Parse(d.AAGUID); err == nil && a != uuid.Nil {
		aaguid = a[:]
	}
	// Discoverable is not recorded; a credential made under authentik's
	// default resident key "preferred" usually is, and is offered without a
	// username either way, since its handle is the account's.
	return importPasskey(ctx, tx, orgID, userID, passkey{RPID: d.RPID, ID: id, PublicKey: key, AAGUID: aaguid,
		SignCount: d.SignCount, Label: d.Name})
}

// authentikDefaultGrants are a provider's grants before it held a list
// (oauth2 migrations/0032:7-18).
var authentikDefaultGrants = []string{"authorization_code", "hybrid", "implicit", "client_credentials", "password",
	"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}

// authentikNameIDFormats are common/saml/constants.py:19-24's, as this
// server's: unspecified is sent the persistent value (assertion.py:270-279).
var authentikNameIDFormats = map[string]string{
	"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": "emailAddress",
	"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent":   "persistent",
	"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified":  "persistent",
	"": "persistent",
	"urn:oasis:names:tc:SAML:2.0:nameid-format:transient": "transient",
}

// importAuthentikProvider makes an OAuth2 provider a client and a SAML one a
// service provider, answering the entity ID of one sent persistent NameIDs.
func importAuthentikProvider(ctx context.Context, tx pgx.Tx, orgID string, p AuthentikProvider, opts Options,
	res *Result) (string, error) {
	name := p.Application
	if name == "" {
		name = p.Name
	}
	if p.PropertyMappings > 0 {
		res.Dropped = append(res.Dropped, fmt.Sprintf("provider %s's %d property mapping(s) (declare claim mappers)",
			p.Name, p.PropertyMappings))
	}
	switch {
	case p.OAuth2 != nil:
		return "", importAuthentikOAuth2(ctx, tx, orgID, p.Name, name, *p.OAuth2, opts, res)
	case p.SAML != nil:
		return importAuthentikSAML(ctx, tx, orgID, p.Name, name, *p.SAML, res)
	}
	res.Dropped = append(res.Dropped, fmt.Sprintf("provider %s (of a kind not carried: OAuth2 and SAML providers "+
		"come across)", p.Name))
	return "", nil
}

func importAuthentikOAuth2(ctx context.Context, tx pgx.Tx, orgID, provider, name string, o AuthentikOAuth2,
	opts Options, res *Result) error {
	if o.ClientID == "" {
		res.ClientsSkipped = append(res.ClientsSkipped, "provider "+provider+" (no client ID)")
		return nil
	}
	public := o.ClientType == "public"
	listed := authentikDefaultGrants
	if o.GrantTypes != nil {
		listed = *o.GrantTypes
	}
	var grants []string
	for _, g := range listed {
		switch g {
		case "authorization_code", "refresh_token", oauth.GrantTypeDeviceCode,
			"urn:ietf:params:oauth:grant-type:token-exchange":
			grants = append(grants, g)
		case "client_credentials":
			// A public client holds no secret to authenticate this grant with.
			if !public {
				grants = append(grants, g)
			}
		case "implicit", "hybrid":
			res.Dropped = append(res.Dropped, fmt.Sprintf("client %s's %s flow (not implemented: tokens in a URL "+
				"fragment; it uses the code flow here)", o.ClientID, g))
		case "password":
			res.Dropped = append(res.Dropped, "client "+o.ClientID+"'s password grant (not implemented)")
		default:
			res.Dropped = append(res.Dropped, "client "+o.ClientID+"'s grant "+g+" (not one this server implements)")
		}
	}
	if len(grants) == 0 {
		res.ClientsSkipped = append(res.ClientsSkipped, o.ClientID+" (uses no flow this server implements)")
		return nil
	}

	var redirects, logouts []string
	add := func(mode, url, kind string) {
		if mode == "regex" {
			res.ClientsSkipped = append(res.ClientsSkipped, fmt.Sprintf("%s redirect %s (a regular expression; "+
				"register each URI it should match)", o.ClientID, url))
			return
		}
		if kind == "logout" {
			logouts = append(logouts, url)
		} else {
			redirects = append(redirects, url)
		}
	}
	for _, r := range o.RedirectURIs {
		add(r.MatchingMode, r.URL, r.Type)
	}
	if o.OldRedirectURIs != nil {
		for _, u := range strings.Split(*o.OldRedirectURIs, "\n") {
			if u = strings.TrimSpace(u); u == "*" || u == ".*" {
				add("regex", u, "")
			} else if u != "" {
				add("strict", u, "")
			}
		}
	}

	created, err := importClient(ctx, tx, orgID, o.ClientID, name, o.ClientSecret, public, true, grants, redirects,
		logouts, opts.Hasher, res)
	if err != nil {
		return err
	}
	if created {
		res.ClientsCreated++
	}
	// What an application keys its accounts on (oauth2/id_token.py:141-152):
	// the user's UUID is the account's id here, and nothing else can be sent.
	if mode := cmpOr(o.SubMode, "hashed_user_id"); mode != "user_uuid" {
		res.Dropped = append(res.Dropped, fmt.Sprintf("client %s's subjects (it was sent %s as sub; here it is sent "+
			"each account's id, the authentik user's UUID, so an account it keyed on the old sub meets a stranger)",
			o.ClientID, mode))
	}
	if len(o.SigningKey) == 0 || string(o.SigningKey) == "null" {
		// With no key, the client secret signs, HS256 (oauth2/models.py:356-363).
		res.Dropped = append(res.Dropped, fmt.Sprintf("client %s's HS256 ID tokens (signed with its secret there; "+
			"here with ES256, from the published keys, which the application must accept)", o.ClientID))
	}
	if o.LogoutURI != "" {
		res.Dropped = append(res.Dropped, fmt.Sprintf("client %s's %s logout URI %s (set it with `signari client "+
			"set-logout`)", o.ClientID, cmpOr(o.LogoutMethod, "backchannel"), o.LogoutURI))
	}
	return nil
}

func importAuthentikSAML(ctx context.Context, tx pgx.Tx, orgID, provider, name string, s AuthentikSAML,
	res *Result) (string, error) {
	if s.Audience == "" {
		res.ClientsSkipped = append(res.ClientsSkipped, "SAML provider "+provider+" (it states no audience, the "+
			"entity ID of the service provider, which is how a request is matched to it)")
		return "", nil
	}
	if len(s.NameIDMapping) > 0 && string(s.NameIDMapping) != "null" {
		res.ClientsSkipped = append(res.ClientsSkipped, fmt.Sprintf("SAML provider %s (a property mapping makes "+
			"its NameID, which nothing here runs; brought across with another, every account at the service "+
			"provider would be keyed on a subject it has never seen)", s.Audience))
		return "", nil
	}
	format, ok := authentikNameIDFormats[s.DefaultNameIDPolicy]
	if !ok {
		res.ClientsSkipped = append(res.ClientsSkipped, fmt.Sprintf("SAML provider %s (its NameID policy %s is "+
			"read from a directory attribute, which nothing here sends)", s.Audience, s.DefaultNameIDPolicy))
		return "", nil
	}
	created, skipped, err := importSAMLProvider(ctx, tx, orgID, s.Audience, name, format, true, []string{s.ACSURL})
	if err != nil {
		return "", err
	}
	res.ClientsSkipped = append(res.ClientsSkipped, skipped...)
	if created {
		res.SAMLProvidersCreated++
	}
	if len(skipped) > 0 && !created {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.saml_providers WHERE org_id = $1::uuid
			AND entity_id = $2)`, orgID, s.Audience).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return "", nil
		}
	}
	res.Dropped = append(res.Dropped, fmt.Sprintf("SAML provider %s's certificates, signing settings, property "+
		"mappings and logout URL (set them with `signari saml`)", s.Audience))
	if format != "persistent" {
		return "", nil
	}
	return s.Audience, nil
}

func cmpOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// hashFormatName names a stored hash's format for reporting.
//
// Reported rather than guessed at: "we imported 400 users" means nothing if 380
// of them carry a format nothing here can check.
//
// The verifiable/not verdict comes from passwords.CanVerify rather than from a
// second list here. A first version kept its own prefixes and got one wrong --
// it tested for "argon2" where the stored form is "$argon2id$" -- so a perfectly
// importable hash was reported as unrecognised, which would send an operator
// into a cutover planning password resets nobody needed.
func hashFormatName(stored string) string {
	verdict := " (NOT verifiable here)"
	if passwords.CanVerify(stored) {
		verdict = " (verifiable)"
	}

	switch {
	case stored == "":
		return "(none)"
	case strings.HasPrefix(stored, "!"):
		// Django's marker for "no usable password": a user who only ever signed
		// in through a federated source, or whose password was disabled.
		return "unusable (federated or never set)"
	case strings.HasPrefix(stored, "pbkdf2_sha256$"):
		return "pbkdf2_sha256, Django default" + verdict
	case strings.HasPrefix(stored, "$argon2"):
		return "argon2" + verdict
	case strings.HasPrefix(stored, "$2a$"), strings.HasPrefix(stored, "$2b$"),
		strings.HasPrefix(stored, "$2y$"):
		return "bcrypt" + verdict
	case strings.HasPrefix(stored, "scrypt$"):
		// Django's own scrypt hasher, which is NOT the "$scrypt$" form this
		// engine verifies. Different encodings with confusingly similar names.
		return "scrypt, Django variant" + verdict
	case strings.HasPrefix(stored, "$1$"), strings.HasPrefix(stored, "$5$"),
		strings.HasPrefix(stored, "$6$"), strings.HasPrefix(stored, "$y$"):
		return cryptFormat(stored) + verdict
	default:
		if i := strings.Index(stored, "$"); i > 0 {
			return stored[:i] + verdict
		}
		return "unrecognised" + verdict
	}
}
