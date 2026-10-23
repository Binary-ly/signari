package config

import (
	"context"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// Scopes, attributes, resource servers and the sign-up rule in a configuration
// file (6.19), each written through the function the Admin API's route for it
// uses, so a file declares a thing exactly as the route would.

// Scope is a scope the organisation declares beyond the standard ones.
type Scope struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description"`
	// Advertise lists it in the discovery document.
	Advertise bool `yaml:"advertise"`
}

type scopeSection struct{}

func (scopeSection) kind() string { return "scope" }
func (scopeSection) first() bool  { return true }

func (scopeSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "scopes")
	for i, s := range f.Scopes {
		if !once(i, s.Name) {
			continue
		}
		if store.IsStandardScope(s.Name) {
			add("scopes[%s]: a standard scope's meaning is the specification's and is not declared", s.Name)
		}
	}
}

func (scopeSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.Scopes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	planKeyed(p, "scope", keyBy(f.Scopes, func(s Scope) string { return s.Name }),
		keyBy(have, func(s store.Scope) string { return s.Name }), prune,
		func(h store.Scope, w Scope) string {
			var c changed
			c.note(h.DisplayName != w.DisplayName, "display_name")
			c.note(h.Description != w.Description, "description")
			c.note(h.Advertise != w.Advertise, "advertise")
			return c.String()
		}, "a client asking for it is refused it; a claim mapper gated on it stops the apply")
	return nil
}

func (scopeSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, s := range f.Scopes {
		if c, ok := p.planned("scope", s.Name); !ok || c.Action == "delete" {
			continue
		}
		if err := store.DeclareScope(ctx, tx, orgID, store.Scope{Name: s.Name, DisplayName: s.DisplayName,
			Description: s.Description, Advertise: s.Advertise}); err != nil {
			return err
		}
	}
	return nil
}

// remove refuses a scope a claim mapper is gated on, as the Admin API's
// DELETE does: the mapper would release nothing, silently.
func (scopeSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM core.scopes WHERE org_id = $1::uuid AND name = $2`, orgID, name); err != nil {
		return err
	}
	var mappers int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.claim_mappers WHERE org_id = $1::uuid AND required_scope = $2`,
		orgID, name).Scan(&mappers); err != nil {
		return err
	}
	if mappers > 0 {
		return refuse("scope %q gates %d claim mapper(s), which would then release nothing; remove them "+
			"from the file too, or keep the scope", name, mappers)
	}
	return nil
}

func (scopeSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.Scopes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, s := range have {
		f.Scopes = append(f.Scopes, Scope{Name: s.Name, DisplayName: s.DisplayName, Description: s.Description,
			Advertise: s.Advertise})
	}
	return nil
}

// Attribute is a declared user attribute.
type Attribute struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name"`
	// ValueType is string, number, boolean or date; empty is string.
	ValueType string `yaml:"value_type"`
	// Personal seals each value under the person's own key. Fixed once
	// declared: changing it would move personal data between storage
	// classes, so a file that changes it is refused.
	Personal     bool `yaml:"personal"`
	UserReadable bool `yaml:"user_readable"`
	UserWritable bool `yaml:"user_writable"`
	Required     bool `yaml:"required"`
}

func (a Attribute) valueType() string {
	if a.ValueType == "" {
		return "string"
	}
	return a.ValueType
}

type attributeSection struct{}

func (attributeSection) kind() string { return "attribute" }
func (attributeSection) first() bool  { return true }

func (attributeSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "attributes")
	for i, a := range f.Attributes {
		if !once(i, a.Name) {
			continue
		}
		if !slices.Contains([]string{"string", "number", "boolean", "date"}, a.valueType()) {
			add("attributes[%s]: value_type is string, number, boolean or date, not %q", a.Name, a.ValueType)
		}
		if a.UserWritable && !a.UserReadable {
			add("attributes[%s]: user_writable needs user_readable: a person cannot be asked for what they "+
				"may not see", a.Name)
		}
	}
}

func (attributeSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.Attributes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	byName := keyBy(have, func(a store.Attribute) string { return a.Name })
	for _, w := range f.Attributes {
		h, ok := byName[w.Name]
		if !ok {
			continue
		}
		if h.Personal != w.Personal {
			return refuse("attribute %q is declared %s, and whether its values are sealed is fixed once "+
				"declared: declare a new attribute and move the values deliberately", w.Name, sealedOrNot(h.Personal))
		}
		if h.ValueType != w.valueType() {
			var held bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.user_attributes WHERE attribute_id = $1::uuid)`,
				h.ID).Scan(&held); err != nil {
				return err
			}
			if held {
				return refuse("attribute %q holds values written as a %s, and retyping it would release them "+
					"as something else; declare a new attribute", w.Name, h.ValueType)
			}
		}
	}
	planKeyed(p, "attribute", keyBy(f.Attributes, func(a Attribute) string { return a.Name }), byName, prune,
		func(h store.Attribute, w Attribute) string {
			var c changed
			c.note(h.DisplayName != w.DisplayName, "display_name")
			c.note(h.ValueType != w.valueType(), "value_type")
			c.note(h.UserReadable != w.UserReadable, "user_readable")
			c.note(h.UserWritable != w.UserWritable, "user_writable")
			c.note(h.Required != w.Required, "required")
			return c.String()
		}, "every person's value of it is erased, and what maps or releases it stops")
	return nil
}

func sealedOrNot(personal bool) string {
	if personal {
		return "personal, its values sealed"
	}
	return "not personal, its values stored as given"
}

func (attributeSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, a := range f.Attributes {
		if c, ok := p.planned("attribute", a.Name); !ok || c.Action == "delete" {
			continue
		}
		if _, err := store.DeclareAttribute(ctx, tx, orgID, store.Attribute{Name: a.Name, DisplayName: a.DisplayName,
			ValueType: a.valueType(), Personal: a.Personal, UserReadable: a.UserReadable,
			UserWritable: a.UserWritable, Required: a.Required}); err != nil {
			return err
		}
	}
	return nil
}

func (attributeSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	_, err := tx.Exec(ctx, `DELETE FROM core.user_attribute_schema WHERE org_id = $1::uuid AND name = $2`, orgID, name)
	return err
}

func (attributeSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.Attributes(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, a := range have {
		f.Attributes = append(f.Attributes, Attribute{Name: a.Name, DisplayName: a.DisplayName,
			ValueType: a.ValueType, Personal: a.Personal, UserReadable: a.UserReadable,
			UserWritable: a.UserWritable, Required: a.Required})
	}
	return nil
}

// Resource is an RFC 8707 resource the organisation's tokens may be
// audienced to.
type Resource struct {
	Resource string `yaml:"resource"`
	Name     string `yaml:"name"`
}

type resourceSection struct{}

func (resourceSection) kind() string { return "resource" }
func (resourceSection) first() bool  { return false }

func (resourceSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "resources")
	for i, r := range f.Resources {
		if !once(i, r.Resource) {
			continue
		}
		// RFC 8707 §2: an absolute URI with no fragment.
		if u, err := url.Parse(r.Resource); err != nil || !u.IsAbs() || u.Fragment != "" {
			add("resources[%s]: a resource is an absolute URI with no fragment (RFC 8707 section 2)", r.Resource)
		}
	}
}

func (resourceSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.ResourceServers(ctx, tx, orgID)
	if err != nil {
		return err
	}
	planKeyed(p, "resource", keyBy(f.Resources, func(r Resource) string { return r.Resource }),
		keyBy(have, func(r store.ResourceServer) string { return r.Resource }), prune,
		func(h store.ResourceServer, w Resource) string {
			if h.Name != w.Name {
				return "name"
			}
			return ""
		}, "a token asking for it is refused from the next request")
	return nil
}

func (resourceSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, r := range f.Resources {
		if c, ok := p.planned("resource", r.Resource); !ok || c.Action == "delete" {
			continue
		}
		if err := store.SetResourceServer(ctx, tx, orgID, r.Resource, r.Name); err != nil {
			return err
		}
	}
	return nil
}

func (resourceSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	return store.RemoveResourceServer(ctx, tx, orgID, name)
}

func (resourceSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.ResourceServers(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, r := range have {
		f.Resources = append(f.Resources, Resource{Resource: r.Resource, Name: r.Name})
	}
	sort.Slice(f.Resources, func(i, j int) bool { return f.Resources[i].Resource < f.Resources[j].Resource })
	return nil
}

// Signup is the organisation's self-sign-up rule. Absent leaves it as it is;
// with prune, absent closes sign-up.
type Signup struct {
	// Domains are the email domains that may sign up; AnyDomain admits every
	// address instead, which is never assumed from an empty list.
	Domains   []string `yaml:"domains"`
	AnyDomain bool     `yaml:"any_domain"`
	// Groups are what a new account joins, groups of the organisation.
	Groups []string `yaml:"groups"`
	// VerifyEmail has a new account prove its address before it signs in;
	// absent is true.
	VerifyEmail     *bool `yaml:"verify_email"`
	RequireApproval bool  `yaml:"require_approval"`
}

func (s Signup) verify() bool { return s.VerifyEmail == nil || *s.VerifyEmail }

func (s Signup) domains() []string {
	out := make([]string, 0, len(s.Domains))
	for _, d := range s.Domains {
		out = append(out, strings.ToLower(strings.TrimSpace(d)))
	}
	sort.Strings(out)
	return out
}

type signupSection struct{}

func (signupSection) kind() string { return "signup" }
func (signupSection) first() bool  { return false }

func (signupSection) validate(f *File, add func(string, ...any)) {
	s := f.Signup
	switch {
	case s == nil:
	case s.AnyDomain && len(s.Domains) > 0:
		add("signup: any_domain admits every address; name domains or ask for any, not both")
	case !s.AnyDomain && len(s.Domains) == 0:
		add("signup: name the domains, or set any_domain to let anyone on the internet make an account")
	}
}

func (signupSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.LoadSignupRule(ctx, tx, orgID)
	if err != nil {
		return err
	}
	// The groups a new account joins must be the organisation's, or the file's
	// own, whether the rule is new or not.
	if want := f.Signup; want != nil {
		missing, err := missingGroups(ctx, tx, orgID, f, want.Groups)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			return refuse("signup: the organisation has no group %s for a new account to join; declare it "+
				"in groups", strings.Join(missing, ", "))
		}
	}
	switch want := f.Signup; {
	case want == nil && have != nil && prune:
		p.Add(Change{Action: "delete", Kind: "signup", Name: "rule", Destructive: true,
			Detail: "self-sign-up closes; the people it made keep their accounts"})
	case want == nil:
	case have == nil:
		p.Add(Change{Action: "create", Kind: "signup", Name: "rule"})
	default:
		var c changed
		c.note(!slices.Equal(sortedCopy(have.AllowedDomains), want.domains()), "domains")
		c.note(!sameSet(have.DefaultGroups, want.Groups), "groups")
		c.note(have.RequireVerify != want.verify(), "verify_email")
		c.note(have.RequireApproval != want.RequireApproval, "require_approval")
		if d := c.String(); d != "" {
			p.Add(Change{Action: "update", Kind: "signup", Name: "rule", Detail: d})
		}
	}
	return nil
}

func groupNames(f *File) []string {
	out := make([]string, 0, len(f.Groups))
	for _, g := range f.Groups {
		out = append(out, g.Name)
	}
	return out
}

// missingGroups are the names neither the organisation nor the file has a
// group of, sorted.
func missingGroups(ctx context.Context, tx pgx.Tx, orgID string, f *File, names []string) ([]string, error) {
	var missing []string
	err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(n ORDER BY n), '{}') FROM unnest($2::text[]) n
		WHERE NOT EXISTS (SELECT 1 FROM core.groups g WHERE g.org_id = $1::uuid AND g.name = n)
		  AND NOT n = ANY($3::text[])`, orgID, names, groupNames(f)).Scan(&missing)
	return missing, err
}

func sortedCopy(l []string) []string {
	out := append([]string(nil), l...)
	sort.Strings(out)
	return out
}

func (signupSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	c, ok := p.planned("signup", "rule")
	if !ok || c.Action == "delete" || f.Signup == nil {
		return nil
	}
	s := f.Signup
	return store.SetSignupRule(ctx, tx, store.SignupRule{OrgID: orgID, AllowedDomains: s.domains(),
		DefaultGroups: s.Groups, RequireVerify: s.verify(), RequireApproval: s.RequireApproval})
}

func (signupSection) remove(ctx context.Context, tx pgx.Tx, orgID, _ string) error {
	_, err := store.RemoveSignupRule(ctx, tx, orgID)
	return err
}

func (signupSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.LoadSignupRule(ctx, tx, orgID)
	if err != nil || have == nil {
		return err
	}
	verify := have.RequireVerify
	f.Signup = &Signup{Domains: sortedCopy(have.AllowedDomains), AnyDomain: len(have.AllowedDomains) == 0,
		Groups: have.DefaultGroups, VerifyEmail: &verify, RequireApproval: have.RequireApproval}
	return nil
}

// keyBy indexes a list by a key.
func keyBy[T any](l []T, key func(T) string) map[string]T {
	out := make(map[string]T, len(l))
	for _, v := range l {
		out[key(v)] = v
	}
	return out
}
