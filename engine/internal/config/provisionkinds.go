package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Provisioning targets in a configuration file (6.19): the systems the
// organisation's people are written out to. What a target authenticates with,
// a bearer token or a service account, is issued by the system at the far
// end, so the file names it by reference: needed to make a target, compared
// when given afterwards, and never in an export.

// SCIMTarget is a system people are provisioned to.
type SCIMTarget struct {
	Slug string `yaml:"slug"`
	// Kind is scim (the default), google or entra, fixed once made.
	Kind string `yaml:"kind,omitempty"`
	Name string `yaml:"name,omitempty"`
	// BaseURL is a SCIM target's, https.
	BaseURL string `yaml:"base_url,omitempty"`
	// Token is a SCIM target's bearer token, Credentials a native target's
	// service account file, each by reference.
	Token       *SecretRef `yaml:"token,omitempty"`
	Credentials *SecretRef `yaml:"credentials,omitempty"`
	// Impersonate and TargetDomain are a Google target's administrator to act
	// as and the domain accounts are made in.
	Impersonate  string `yaml:"impersonate,omitempty"`
	TargetDomain string `yaml:"target_domain,omitempty"`
	// OnDeactivate is deactivate (the default), delete or nothing.
	OnDeactivate string `yaml:"on_deactivate,omitempty"`
	// Each left as it is when absent.
	DryRun  *bool `yaml:"dry_run,omitempty"`
	Enabled *bool `yaml:"enabled,omitempty"`
	// ScopeGroup limits the target to one group's members; "" is everybody.
	ScopeGroup *string `yaml:"scope_group,omitempty"`
}

func (w SCIMTarget) targetKind() string {
	if w.Kind == "" {
		return "scim"
	}
	return w.Kind
}

// secretRef is what the target authenticates with, and where the file names
// it.
func (w SCIMTarget) secretRef() (*SecretRef, string) {
	if w.targetKind() == "scim" {
		return w.Token, fmt.Sprintf("scim_targets[%s].token", w.Slug)
	}
	return w.Credentials, fmt.Sprintf("scim_targets[%s].credentials", w.Slug)
}

// spec is the target as provision.AddTarget takes it, its secret resolved.
func (w SCIMTarget) spec() provision.TargetSpec {
	s := provision.TargetSpec{Kind: w.targetKind(), Slug: w.Slug, Name: w.Name, BaseURL: w.BaseURL,
		Impersonate: w.Impersonate, Domain: w.TargetDomain, OnDeactivate: w.OnDeactivate,
		DryRun: w.DryRun != nil && *w.DryRun}
	if r, _ := w.secretRef(); r != nil && s.Kind == "scim" {
		s.Token = r.value
	} else if r != nil {
		s.Credentials = []byte(r.value)
	}
	return s
}

type scimSection struct{}

func (scimSection) kind() string { return "scim_target" }

// first is false: a target may be limited to a group the file makes.
func (scimSection) first() bool { return false }

func (scimSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "scim_targets")
	for i, w := range f.SCIMTargets {
		if !once(i, w.Slug) {
			continue
		}
		at := "scim_targets[" + w.Slug + "]"
		switch k := w.targetKind(); k {
		case "scim":
			switch {
			case !strings.HasPrefix(w.BaseURL, "https://"):
				add("%s: give the target's https base_url: its token can create and delete accounts there, and "+
					"is sent on every request", at)
			case safedial.CheckURL(w.BaseURL) != nil:
				add("%s: %v", at, safedial.CheckURL(w.BaseURL))
			}
			if w.Credentials != nil || w.Impersonate != "" || w.TargetDomain != "" {
				add("%s: a SCIM target has a base_url and a token, not credentials, impersonate or target_domain", at)
			}
		case "google", "entra":
			if w.BaseURL != "" || w.Token != nil {
				add("%s: a %s target is reached through its own API with credentials, not a base_url and token",
					at, k)
			}
			if k == "google" && (w.Impersonate == "" || w.TargetDomain == "") {
				add("%s: a Google target needs impersonate, the administrator to act as, and target_domain, "+
					"where accounts are made", at)
			}
			if k == "entra" && (w.Impersonate != "" || w.TargetDomain != "") {
				add("%s: impersonate and target_domain are a Google target's", at)
			}
		default:
			add("%s: kind is scim, google or entra, not %q", at, w.Kind)
		}
		switch w.OnDeactivate {
		case "", "deactivate", "delete", "nothing":
		default:
			add("%s: on_deactivate is deactivate, delete or nothing, not %q", at, w.OnDeactivate)
		}
		if r, where := w.secretRef(); r != nil {
			r.check(where, add)
		}
	}
}

// keptTarget is the plan's detail for a target a pruned file leaves out.
const keptTarget = "disabled rather than deleted: its links are the only record of which accounts there are " +
	"this organisation's people"

func (scimSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.SCIMTargets(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(t store.SCIMTargetRow) string { return t.Slug })
	var scopes []string
	for _, w := range f.SCIMTargets {
		at := "scim_targets[" + w.Slug + "]"
		if w.ScopeGroup != nil && *w.ScopeGroup != "" {
			scopes = append(scopes, *w.ScopeGroup)
		}
		h, exists := held[w.Slug]
		r, where := w.secretRef()
		switch {
		case r == nil && !exists:
			return refuse("%s: name it by reference, `{env: NAME}` or `{file: path}`: the target issued it, so "+
				"this engine cannot make one, and an export never carries one", where)
		case r != nil:
			if _, err := r.secret(where); err != nil {
				return err
			}
			// Checked whole, now its secret is known: credentials that will not
			// parse are refused here rather than at the first sync.
			s := w.spec()
			if err := s.Validate(); err != nil {
				return refuse("%s: %v", at, err)
			}
		}
		if !exists {
			continue
		}
		if h.Kind != w.targetKind() {
			return refuse("%s: it is a %s target, and a target's kind is fixed once made; register the %s one "+
				"under another slug", at, h.Kind, w.targetKind())
		}
		if h.Kind == "scim" && h.BaseURL != w.BaseURL && w.Token == nil {
			return refuse("%s: a new base_url needs the token too, named by reference: the one held was issued "+
				"for the old address, and would be sent to whoever answers at the new one", at)
		}
	}
	if missing, err := missingGroups(ctx, tx, orgID, f, prune, scopes); err != nil {
		return err
	} else if len(missing) > 0 {
		return refuse("scim_targets: the organisation has no group %s to limit a target to; declare it in groups",
			strings.Join(missing, ", "))
	}

	var compared error
	// Never deleted, so prune is false here: what a pruned file leaves out is
	// switched off below.
	planKeyed(p, "scim_target", keyBy(f.SCIMTargets, func(w SCIMTarget) string { return w.Slug }), held, false,
		func(h store.SCIMTargetRow, w SCIMTarget) string {
			var c changed
			c.note(w.Name != "" && h.Name != w.Name, "name")
			c.note(h.BaseURL != w.BaseURL && h.Kind == "scim", "base_url")
			c.note(w.OnDeactivate != "" && h.OnDeactivate != w.OnDeactivate, "on_deactivate")
			c.note(h.Impersonate != w.Impersonate && h.Kind == "google", "impersonate")
			c.note(h.TargetDomain != w.TargetDomain && h.Kind == "google", "target_domain")
			c.note(w.DryRun != nil && h.DryRun != *w.DryRun, "dry_run")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			c.note(w.ScopeGroup != nil && h.ScopeGroup != *w.ScopeGroup, "scope_group")
			if r, where := w.secretRef(); r != nil && compared == nil {
				if compared = p.needsRoot("scim_target", w.Slug, "comparing the secret the file names"); compared == nil {
					var secret string
					secret, compared = store.SCIMTargetSecret(ctx, tx, p.opts.Root, orgID, w.Slug)
					c.note(secret != r.value, where[strings.LastIndex(where, ".")+1:])
				}
			}
			return c.String()
		}, "")
	if compared != nil {
		return compared
	}
	if prune {
		inFile := keyBy(f.SCIMTargets, func(w SCIMTarget) string { return w.Slug })
		for _, h := range have {
			if _, ok := inFile[h.Slug]; !ok && h.Enabled {
				p.Add(Change{Action: "update", Kind: "scim_target", Name: h.Slug, Detail: keptTarget})
			}
		}
	}
	for i, c := range p.Changes {
		if c.Kind != "scim_target" || c.Action != "create" {
			continue
		}
		w := keyBy(f.SCIMTargets, func(w SCIMTarget) string { return w.Slug })[c.Name]
		r, where := w.secretRef()
		p.Changes[i].Detail = where[strings.LastIndex(where, ".")+1:] + " from " + r.String() +
			"; nothing is sent until it is synced"
		if err := p.needsRoot("scim_target", c.Name, "sealing what it authenticates with"); err != nil {
			return err
		}
	}
	return nil
}

func (scimSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.SCIMTargets(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(t store.SCIMTargetRow) string { return t.Slug })
	inFile := map[string]bool{}
	for _, w := range f.SCIMTargets {
		inFile[w.Slug] = true
		c, ok := p.planned("scim_target", w.Slug)
		if !ok {
			continue
		}
		if c.Action == "create" {
			if err := provision.AddTarget(ctx, tx, p.opts.Root, orgID, w.spec()); err != nil {
				return err
			}
		} else {
			h := held[w.Slug]
			var change provision.TargetChange
			if w.Name != "" {
				change.Name = &w.Name
			}
			if h.Kind == "scim" && h.BaseURL != w.BaseURL {
				change.BaseURL = &w.BaseURL
			}
			if w.OnDeactivate != "" {
				change.OnDeactivate = &w.OnDeactivate
			}
			if h.Kind == "google" {
				change.Impersonate, change.Domain = &w.Impersonate, &w.TargetDomain
			}
			change.DryRun = w.DryRun
			if r, _ := w.secretRef(); r != nil && h.Kind == "scim" {
				change.Token = &r.value
			} else if r != nil {
				change.Credentials = []byte(r.value)
			}
			if err := provision.UpdateTarget(ctx, tx, p.opts.Root, orgID, w.Slug, h.Kind, change); err != nil {
				return err
			}
		}
		if w.Enabled != nil {
			if err := store.SetSCIMTargetEnabled(ctx, tx, orgID, w.Slug, *w.Enabled); err != nil {
				return err
			}
		}
		if w.ScopeGroup != nil {
			if err := store.SetSCIMTargetScope(ctx, tx, orgID, w.Slug, *w.ScopeGroup); err != nil {
				return err
			}
		}
	}
	for _, h := range have {
		if c, ok := p.planned("scim_target", h.Slug); ok && !inFile[h.Slug] && c.Detail == keptTarget {
			if err := store.SetSCIMTargetEnabled(ctx, tx, orgID, h.Slug, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// scopedTo refuses deleting a group a provisioning target is left limited to,
// as the schema does at the delete: the target would provision everybody.
// Given another scope_group in the same file, the target moves before the
// group goes, since deletions are made last.
func scopedTo(ctx context.Context, tx pgx.Tx, orgID string, f *File, group string) error {
	rows, err := tx.Query(ctx, `SELECT t.slug FROM core.scim_targets t JOIN core.groups g ON g.id = t.scope_group_id
		WHERE t.org_id = $1::uuid AND g.name = $2 ORDER BY t.slug`, orgID, group)
	if err != nil {
		return err
	}
	slugs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	inFile := keyBy(f.SCIMTargets, func(w SCIMTarget) string { return w.Slug })
	for _, slug := range slugs {
		if w, ok := inFile[slug]; ok && w.ScopeGroup != nil && *w.ScopeGroup != group {
			continue
		}
		return refuse("group %s: provisioning target %s is limited to it, and deleting the group would widen "+
			"the target to everybody; give the target another scope_group in the same file, \"\" for everybody",
			group, slug)
	}
	return nil
}

// remove is never planned: a pruned target is switched off, not deleted.
func (scimSection) remove(context.Context, pgx.Tx, string, string) error {
	return fmt.Errorf("a provisioning target is disabled by a pruned file, never deleted")
}

// export leaves out the token or credentials, which the target issued; the
// file applied to another deployment names them by reference.
func (scimSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.SCIMTargets(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		dryRun, enabled, scope := h.DryRun, h.Enabled, h.ScopeGroup
		w := SCIMTarget{Slug: h.Slug, Kind: h.Kind, Name: h.Name, OnDeactivate: h.OnDeactivate, DryRun: &dryRun,
			Enabled: &enabled, ScopeGroup: &scope}
		switch h.Kind {
		case "scim":
			w.Kind, w.BaseURL = "", h.BaseURL
		case "google":
			w.Impersonate, w.TargetDomain = h.Impersonate, h.TargetDomain
		}
		f.SCIMTargets = append(f.SCIMTargets, w)
	}
	return nil
}
