package config

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/duo"
	"signari.dev/engine/internal/store"
)

// What an organisation reads people from and verifies them with, in a
// configuration file (6.25): directory sources, the Duo integration and the
// migration source. Each authenticates with something its own system issued,
// named by reference as 6.19's kinds name theirs, and none is contacted by a
// plan: `signari dir`, `signari duo set` and `signari migration-source` reach
// the far end when they register one, and a file is checked for shape.

// DirectorySource is a directory people are synced from.
type DirectorySource struct {
	Slug string `yaml:"slug"`
	// Kind is google, entra or ldap, fixed once made.
	Kind string `yaml:"kind"`
	Name string `yaml:"name,omitempty"`
	// Credentials are a Google or Entra source's service account file;
	// Password an LDAP source's bind password. By reference, needed to make
	// one, compared when given.
	Credentials *SecretRef `yaml:"credentials,omitempty"`
	Password    *SecretRef `yaml:"password,omitempty"`
	// A Google source's administrator to act as and domain.
	Impersonate string `yaml:"impersonate,omitempty"`
	Domain      string `yaml:"domain,omitempty"`
	Filter      string `yaml:"filter,omitempty"`
	// An LDAP source's directory, bind, base, flavour (openldap, ad or
	// freeipa), StartTLS and CA.
	URL            string `yaml:"url,omitempty"`
	BindDN         string `yaml:"bind_dn,omitempty"`
	BaseDN         string `yaml:"base_dn,omitempty"`
	Flavour        string `yaml:"flavour,omitempty"`
	StartTLS       bool   `yaml:"start_tls,omitempty"`
	CA             string `yaml:"ca,omitempty"`
	GroupAttribute string `yaml:"group_attribute,omitempty"`
	// How it syncs; each left as it is when absent, and a new source starts
	// in dry run, reporting rather than deactivating.
	FetchGroups   *bool   `yaml:"fetch_groups,omitempty"`
	OnMissing     *string `yaml:"on_missing,omitempty"`
	MaxDeactivate *int    `yaml:"max_deactivate_percent,omitempty"`
	DryRun        *bool   `yaml:"dry_run,omitempty"`
	Enabled       *bool   `yaml:"enabled,omitempty"`
	// GroupMap is which local group each directory group grants: exactly
	// these when given.
	GroupMap *[]DirectoryMapping `yaml:"group_map,omitempty"`
}

// DirectoryMapping is one directory group and the local group it grants.
type DirectoryMapping struct {
	Remote string `yaml:"remote"`
	Group  string `yaml:"group"`
}

func (w DirectorySource) at() string { return "directory_sources[" + w.Slug + "]" }

// secretRef is what the source authenticates with, and where the file names
// it.
func (w DirectorySource) secretRef() (*SecretRef, string) {
	if w.Kind == "ldap" {
		return w.Password, w.at() + ".password"
	}
	return w.Credentials, w.at() + ".credentials"
}

func (w DirectorySource) spec() directory.SourceSpec {
	s := directory.SourceSpec{Kind: w.Kind, Slug: w.Slug, Name: w.Name, Domain: w.Domain, Impersonate: w.Impersonate,
		Filter: w.Filter, LDAPURL: w.URL, LDAPBindDN: w.BindDN, LDAPBaseDN: w.BaseDN, LDAPFlavour: w.Flavour,
		LDAPCAPEM: w.CA, LDAPStartTLS: w.StartTLS, GroupAttribute: w.GroupAttribute,
		FetchGroups: w.FetchGroups != nil && *w.FetchGroups}
	if r, _ := w.secretRef(); r != nil {
		if w.Kind == "ldap" {
			s.LDAPPassword = r.value
		} else {
			s.Credentials = []byte(r.value)
		}
	}
	return s
}

func (w DirectorySource) change() directory.SourceChange {
	c := directory.SourceChange{OnMissing: w.OnMissing, MaxDeactivate: w.MaxDeactivate, Enabled: w.Enabled,
		DryRun: w.DryRun, FetchGroups: w.FetchGroups}
	if w.Kind == "ldap" {
		attr := w.GroupAttribute
		c.GroupAttribute = &attr
	}
	return c
}

// registrationDiffers reports whether how the source is reached differs from
// what is held, which only UpdateSource writes.
func (w DirectorySource) registrationDiffers(h directory.SourceSettings) bool {
	return (w.Name != "" && h.Name != w.Name) || h.LDAPURL != w.URL || h.LDAPBindDN != w.BindDN ||
		h.LDAPBaseDN != w.BaseDN || h.LDAPFlavour != w.Flavour || h.LDAPStartTLS != w.StartTLS ||
		h.LDAPCAPEM != w.CA || h.Impersonate != w.Impersonate || h.Domain != w.Domain || h.Filter != w.Filter
}

type directorySection struct{}

func (directorySection) kind() string { return "directory_source" }

// first is false: a mapping grants a group the file may make.
func (directorySection) first() bool { return false }

func (directorySection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "directory_sources")
	for i, w := range f.DirectorySources {
		if !once(i, w.Slug) {
			continue
		}
		switch w.Kind {
		case "ldap":
			if w.Credentials != nil {
				add("%s: an LDAP source binds with a password, not credentials", w.at())
			}
			// Its shape does not depend on the password, so it is checked
			// here, with a stand-in for it, rather than once the plan reads it.
			s := w.spec()
			s.LDAPPassword = "stand-in"
			if err := s.Validate(); err != nil {
				add("%s: %v", w.at(), err)
			}
		case "google", "entra":
			if w.Password != nil || w.URL != "" || w.BindDN != "" || w.BaseDN != "" {
				add("%s: a %s source is read through its API with credentials, not an LDAP bind", w.at(), w.Kind)
			}
		default:
			add("%s: kind is google, entra or ldap, not %q", w.at(), w.Kind)
		}
		if err := w.change().Validate(); err != nil {
			add("%s: %v", w.at(), err)
		}
		if r, where := w.secretRef(); r != nil {
			r.check(where, add)
		}
	}
}

const keptSource = "disabled rather than deleted: its links are which accounts here it made, and a sync " +
	"that cannot see them cannot undo them"

func (directorySection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	held, err := directory.SourceSettingsOf(ctx, tx, orgID)
	if err != nil {
		return err
	}
	sources, err := directory.Sources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	maps := map[string][]directory.Mapping{}
	for _, s := range sources {
		maps[s.Slug] = s.Mappings
	}
	var groups []string
	for _, w := range f.DirectorySources {
		r, where := w.secretRef()
		h, exists := held[w.Slug]
		switch {
		case r == nil && !exists:
			return refuse("%s: name it by reference, `{env: NAME}` or `{file: path}`: the directory issued it, "+
				"so this engine cannot make one, and an export never carries one", where)
		case r != nil:
			if _, err := r.secret(where); err != nil {
				return err
			}
			s := w.spec()
			if err := s.Validate(); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
		}
		if exists {
			if h.Kind != w.Kind {
				return refuse("%s: it is a %s source, and a source's kind is fixed once made", w.at(), h.Kind)
			}
			if r == nil && (h.LDAPURL != w.URL || h.LDAPBindDN != w.BindDN || h.Impersonate != w.Impersonate ||
				h.Domain != w.Domain) {
				return refuse("%s: %v", w.at(), directory.ErrCredentialsForAnotherDirectory)
			}
		}
		if w.GroupMap != nil {
			for _, m := range *w.GroupMap {
				groups = append(groups, m.Group)
			}
		}
	}
	if missing, err := missingGroups(ctx, tx, orgID, f, prune, groups); err != nil {
		return err
	} else if len(missing) > 0 {
		return refuse("directory_sources: the organisation has no group %s to map onto; declare it in groups",
			strings.Join(missing, ", "))
	}

	var failed error
	planKeyed(p, "directory_source", keyBy(f.DirectorySources, func(w DirectorySource) string { return w.Slug }),
		held, false, func(h directory.SourceSettings, w DirectorySource) string {
			var c changed
			c.note(w.registrationDiffers(h), "registration")
			c.note(w.Kind == "ldap" && h.GroupAttribute != w.GroupAttribute, "group_attribute")
			c.note(w.FetchGroups != nil && h.FetchGroups != *w.FetchGroups, "fetch_groups")
			c.note(w.OnMissing != nil && h.OnMissing != *w.OnMissing, "on_missing")
			c.note(w.MaxDeactivate != nil && h.MaxDeactivate != *w.MaxDeactivate, "max_deactivate_percent")
			c.note(w.DryRun != nil && h.DryRun != *w.DryRun, "dry_run")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			if w.GroupMap != nil {
				var have, want []string
				for _, m := range maps[w.Slug] {
					have = append(have, m.RemoteGroup+"\t"+m.Group)
				}
				for _, m := range *w.GroupMap {
					want = append(want, m.Remote+"\t"+m.Group)
				}
				c.note(!sameSet(have, want), "group_map")
			}
			if r, where := w.secretRef(); r != nil && failed == nil {
				if failed = p.needsRoot("directory_source", w.Slug, "comparing what the file names"); failed == nil {
					var creds []byte
					creds, failed = directory.SourceCredentials(ctx, tx, p.opts.Root, orgID, w.Slug)
					c.note(string(creds) != r.value, where[strings.LastIndex(where, ".")+1:])
				}
			}
			return c.String()
		}, "")
	if failed != nil {
		return failed
	}
	inFile := keyBy(f.DirectorySources, func(w DirectorySource) string { return w.Slug })
	if prune {
		for slug, h := range held {
			if _, ok := inFile[slug]; !ok && h.Enabled {
				p.Add(Change{Action: "update", Kind: "directory_source", Name: slug, Detail: keptSource})
			}
		}
	}
	for i, c := range p.Changes {
		if c.Kind != "directory_source" || c.Action != "create" {
			continue
		}
		r, where := inFile[c.Name].secretRef()
		p.Changes[i].Detail = where[strings.LastIndex(where, ".")+1:] + " from " + r.String() +
			"; it starts in dry run unless the file says otherwise"
		if err := p.needsRoot("directory_source", c.Name, "sealing what it authenticates with"); err != nil {
			return err
		}
	}
	return nil
}

func (directorySection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	held, err := directory.SourceSettingsOf(ctx, tx, orgID)
	if err != nil {
		return err
	}
	sources, err := directory.Sources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	maps := map[string][]directory.Mapping{}
	for _, s := range sources {
		maps[s.Slug] = s.Mappings
	}
	inFile := map[string]bool{}
	for _, w := range f.DirectorySources {
		inFile[w.Slug] = true
		c, ok := p.planned("directory_source", w.Slug)
		if !ok {
			continue
		}
		r, _ := w.secretRef()
		if c.Action == "create" {
			if _, err := directory.AddSource(ctx, tx, p.opts.Root, orgID, w.spec()); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
		} else if w.registrationDiffers(held[w.Slug]) || r != nil {
			s := w.spec()
			if s.Name == "" {
				s.Name = held[w.Slug].Name
			}
			if err := directory.UpdateSource(ctx, tx, p.opts.Root, orgID, w.Slug, s, r != nil); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
		}
		if ch := w.change(); !ch.Empty() {
			if err := directory.ChangeSource(ctx, tx, orgID, w.Slug, ch); err != nil {
				return refuse("%s: %v", w.at(), err)
			}
		}
		if w.GroupMap == nil {
			continue
		}
		want := map[string]bool{}
		for _, m := range *w.GroupMap {
			want[m.Remote+"\t"+m.Group] = true
			if err := directory.MapGroup(ctx, tx, orgID, w.Slug, m.Remote, m.Group); err != nil {
				return refuse("%s: %s onto %s: %v", w.at(), m.Remote, m.Group, err)
			}
		}
		for _, m := range maps[w.Slug] {
			if !want[m.RemoteGroup+"\t"+m.Group] {
				if err := directory.UnmapGroup(ctx, tx, orgID, w.Slug, m.RemoteGroup, m.Group); err != nil {
					return err
				}
			}
		}
	}
	off := false
	for slug := range held {
		if c, ok := p.planned("directory_source", slug); ok && !inFile[slug] && c.Detail == keptSource {
			if err := directory.ChangeSource(ctx, tx, orgID, slug, directory.SourceChange{Enabled: &off}); err != nil {
				return err
			}
		}
	}
	return nil
}

// remove is never planned: a pruned source is switched off, not deleted.
func (directorySection) remove(context.Context, pgx.Tx, string, string) error {
	return errors.New("a directory source is disabled by a pruned file, never deleted")
}

// export leaves out the credentials, which the directory issued.
func (directorySection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	held, err := directory.SourceSettingsOf(ctx, tx, orgID)
	if err != nil {
		return err
	}
	sources, err := directory.Sources(ctx, tx, orgID)
	if err != nil {
		return err
	}
	maps := map[string][]DirectoryMapping{}
	for _, s := range sources {
		maps[s.Slug] = []DirectoryMapping{}
		for _, m := range s.Mappings {
			maps[s.Slug] = append(maps[s.Slug], DirectoryMapping{Remote: m.RemoteGroup, Group: m.Group})
		}
	}
	for _, slug := range sortedKeys(held) {
		h := held[slug]
		fetch, onMissing, ceiling, dry, enabled, groupMap := h.FetchGroups, h.OnMissing, h.MaxDeactivate, h.DryRun,
			h.Enabled, maps[slug]
		f.DirectorySources = append(f.DirectorySources, DirectorySource{Slug: slug, Kind: h.Kind, Name: h.Name,
			Impersonate: h.Impersonate, Domain: h.Domain, Filter: h.Filter, URL: h.LDAPURL, BindDN: h.LDAPBindDN,
			BaseDN: h.LDAPBaseDN, Flavour: h.LDAPFlavour, StartTLS: h.LDAPStartTLS, CA: h.LDAPCAPEM,
			GroupAttribute: h.GroupAttribute, FetchGroups: &fetch, OnMissing: &onMissing, MaxDeactivate: &ceiling,
			DryRun: &dry, Enabled: &enabled, GroupMap: &groupMap})
	}
	return nil
}

// Duo is the organisation's Duo application, for multi-factor sign-in.
type Duo struct {
	// ClientID is the integration key; Secret its secret key, by reference,
	// needed to make it and again for a new integration key.
	ClientID string     `yaml:"client_id"`
	Secret   *SecretRef `yaml:"secret,omitempty"`
	APIHost  string     `yaml:"api_host"`
	// FailOpen lets a sign-in through when Duo cannot be reached.
	FailOpen bool `yaml:"fail_open,omitempty"`
}

// config is the integration as duo.Config validates it.
func (d Duo) config(secret string) *duo.Config {
	return &duo.Config{ClientID: d.ClientID, ClientSecret: secret, APIHost: d.APIHost, FailOpen: d.FailOpen,
		RedirectURI: "https://configured-at-runtime.invalid/login/duo/callback"}
}

type duoSection struct{}

func (duoSection) kind() string { return "duo" }
func (duoSection) first() bool  { return false }

func (duoSection) validate(f *File, add func(string, ...any)) {
	d := f.Duo
	if d == nil {
		return
	}
	// The secret's length is the plan's to check, once it is read; this
	// stands in for it.
	if err := d.config(strings.Repeat("x", 40)).Validate(); err != nil {
		add("duo: %v", err)
	}
	if d.Secret != nil {
		d.Secret.check("duo.secret", add)
	}
}

func (duoSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.DuoIntegrationOf(ctx, tx, orgID)
	if err != nil {
		return err
	}
	want := f.Duo
	switch {
	case want == nil && prune && have.Configured:
		p.Add(Change{Action: "delete", Kind: "duo", Name: "integration", Destructive: true,
			Detail: "the Duo stage stops being offered; enrolments are kept for when it is set again"})
		return nil
	case want == nil:
		return nil
	}
	if want.Secret != nil {
		secret, err := want.Secret.secret("duo.secret")
		if err != nil {
			return err
		}
		if err := want.config(secret).Validate(); err != nil {
			return refuse("duo: %v", err)
		}
	}
	if !have.Configured {
		if want.Secret == nil {
			return refuse("duo.secret: name it by reference, `{env: NAME}` or `{file: path}`: Duo issued it")
		}
		if err := p.needsRoot("duo", "integration", "sealing its secret"); err != nil {
			return err
		}
		p.Add(Change{Action: "create", Kind: "duo", Name: "integration",
			Detail: "secret from " + want.Secret.String() + "; the keys are not checked against Duo, as `signari duo set` checks them"})
		return nil
	}
	if want.Secret == nil && have.ClientID != want.ClientID {
		return refuse("duo: a new integration key needs its own secret, named by reference")
	}
	var c changed
	c.note(have.ClientID != want.ClientID, "client_id")
	c.note(have.APIHost != want.APIHost, "api_host")
	c.note(have.FailOpen != want.FailOpen, "fail_open")
	c.note(!have.Enabled, "enabled")
	if want.Secret != nil {
		if err := p.needsRoot("duo", "integration", "comparing the secret the file names"); err != nil {
			return err
		}
		held, err := store.DuoSecretOf(ctx, tx, p.opts.Root, orgID)
		if err != nil {
			return err
		}
		c.note(held != want.Secret.value, "secret")
	}
	if d := c.String(); d != "" {
		p.Add(Change{Action: "update", Kind: "duo", Name: "integration", Detail: d})
	}
	return nil
}

func (duoSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	if c, ok := p.planned("duo", "integration"); !ok || c.Action == "delete" {
		return nil
	}
	d := f.Duo
	var sealed []byte
	var err error
	if d.Secret != nil {
		sealed, err = p.opts.Root.Seal([]byte(d.Secret.value), "duo_secret")
	} else {
		sealed, err = store.DuoSealedSecretOf(ctx, tx, orgID)
	}
	if err != nil {
		return err
	}
	return store.SetDuoIntegration(ctx, tx, orgID, d.ClientID, sealed, d.APIHost, d.FailOpen)
}

func (duoSection) remove(ctx context.Context, tx pgx.Tx, orgID, _ string) error {
	return store.RemoveDuoIntegration(ctx, tx, orgID)
}

func (duoSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.DuoIntegrationOf(ctx, tx, orgID)
	if err != nil || !have.Configured {
		return err
	}
	f.Duo = &Duo{ClientID: have.ClientID, APIHost: have.APIHost, FailOpen: have.FailOpen}
	return nil
}

// MigrationSource is the old provider a person's first password sign-in is
// verified against, as `signari migration-source add` sets it.
type MigrationSource struct {
	// Kind is oidc_password or ldap.
	Kind string `yaml:"kind"`
	Name string `yaml:"name"`
	// URL is the token endpoint (https) or the directory (ldaps://, or
	// ldap:// with StartTLS).
	URL string `yaml:"url"`
	// An oidc_password source's client; its secret by reference, kept when
	// left out and needed again for a new endpoint or client id.
	ClientID     string     `yaml:"client_id,omitempty"`
	ClientSecret *SecretRef `yaml:"client_secret,omitempty"`
	Scope        string     `yaml:"scope,omitempty"`
	// An ldap source's bind DN, with {username} once, StartTLS and CA.
	BindDNTemplate string `yaml:"bind_dn_template,omitempty"`
	StartTLS       bool   `yaml:"start_tls,omitempty"`
	CA             string `yaml:"ca,omitempty"`
	// Enabled is off for a new source, which forwards every unmigrated
	// person's password once on; left as it is when absent.
	Enabled *bool `yaml:"enabled,omitempty"`
}

func (m MigrationSource) config() store.MigrationSourceConfig {
	c := store.MigrationSourceConfig{Kind: m.Kind, DisplayName: m.Name, URL: m.URL, ClientID: m.ClientID,
		Scope: m.Scope, BindDNTemplate: m.BindDNTemplate, StartTLS: m.StartTLS, CAPEM: m.CA}
	if m.ClientSecret != nil {
		c.ClientSecret = m.ClientSecret.value
	}
	return c
}

type migrationSection struct{}

func (migrationSection) kind() string { return "migration_source" }
func (migrationSection) first() bool  { return false }

func (migrationSection) validate(f *File, add func(string, ...any)) {
	m := f.MigrationSource
	if m == nil {
		return
	}
	if _, err := store.CheckMigrationSource(m.config()); err != nil {
		add("migration_source: %v", err)
	}
	if m.ClientSecret != nil {
		m.ClientSecret.check("migration_source.client_secret", add)
	}
}

const keptMigration = "switched off rather than deleted: its cutover figures are kept, and people not yet " +
	"migrated are refused a password sign-in until they reset"

func (migrationSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.MigrationSourceOf(ctx, tx, orgID)
	if errors.Is(err, store.ErrMigrationSourceUnknown) {
		have, err = nil, nil
	}
	if err != nil {
		return err
	}
	want := f.MigrationSource
	switch {
	case want == nil && prune && have != nil && have.Enabled:
		p.Add(Change{Action: "update", Kind: "migration_source", Name: "source", Destructive: true, Detail: keptMigration})
		return nil
	case want == nil:
		return nil
	}
	if want.ClientSecret != nil {
		if _, err := want.ClientSecret.secret("migration_source.client_secret"); err != nil {
			return err
		}
		if err := p.needsRoot("migration_source", "source", "sealing or comparing its client secret"); err != nil {
			return err
		}
	}
	checked, err := store.CheckMigrationSource(want.config())
	if err != nil {
		return refuse("migration_source: %v", err)
	}
	if have == nil {
		p.Add(Change{Action: "create", Kind: "migration_source", Name: "source",
			Detail: "off until enabled: on, it forwards every unmigrated person's password to " + want.URL})
		return nil
	}
	if have.HasSecret && want.ClientSecret == nil &&
		(have.Kind != want.Kind || have.URL != want.URL || have.ClientID != want.ClientID) {
		return refuse("migration_source: the token endpoint or client id changed, so name the client secret " +
			"again: the stored one was issued for the old provider and is sent nowhere else")
	}
	ca, secret, err := store.MigrationSourceMaterial(ctx, tx, p.opts.Root, orgID)
	if err != nil {
		return err
	}
	var c changed
	c.note(have.Kind != checked.Kind || have.DisplayName != checked.DisplayName || have.URL != checked.URL ||
		have.ClientID != checked.ClientID || (checked.Kind == "oidc_password" && have.Scope != checked.Scope) ||
		have.BindDNTemplate != checked.BindDNTemplate || have.StartTLS != checked.StartTLS || ca != checked.CAPEM,
		"the source")
	c.note(want.ClientSecret != nil && secret != want.ClientSecret.value, "client_secret")
	c.note(want.Enabled != nil && have.Enabled != *want.Enabled, "enabled")
	if d := c.String(); d != "" {
		p.Add(Change{Action: "update", Kind: "migration_source", Name: "source", Detail: d})
	}
	return nil
}

func (migrationSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	c, ok := p.planned("migration_source", "source")
	if !ok {
		return nil
	}
	if c.Detail == keptMigration {
		return store.SetMigrationSourceEnabled(ctx, tx, orgID, false)
	}
	m := f.MigrationSource
	if c.Action == "create" || strings.Contains(c.Detail, "the source") || strings.Contains(c.Detail, "client_secret") {
		if _, err := store.SetMigrationSource(ctx, tx, p.opts.Root, orgID, m.config()); err != nil {
			return refuse("migration_source: %v", err)
		}
	}
	if m.Enabled != nil {
		return store.SetMigrationSourceEnabled(ctx, tx, orgID, *m.Enabled)
	}
	return nil
}

// remove is never planned: a pruned source is switched off, not deleted.
func (migrationSection) remove(context.Context, pgx.Tx, string, string) error {
	return errors.New("the migration source is switched off by a pruned file, never deleted")
}

func (migrationSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.MigrationSourceOf(ctx, tx, orgID)
	if errors.Is(err, store.ErrMigrationSourceUnknown) {
		return nil
	}
	if err != nil {
		return err
	}
	ca, _, err := store.MigrationSourceMaterial(ctx, tx, nil, orgID)
	if err != nil {
		return err
	}
	enabled := have.Enabled
	f.MigrationSource = &MigrationSource{Kind: have.Kind, Name: have.DisplayName, URL: have.URL,
		ClientID: have.ClientID, Scope: have.Scope, BindDNTemplate: have.BindDNTemplate, StartTLS: have.StartTLS,
		CA: ca, Enabled: &enabled}
	return nil
}
