package config

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/policy"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
)

// Claim mappers, the access policy, the sign-in flows and prompts in a
// configuration file (6.19), written through the functions the Admin API's
// routes for them use.

// ClaimMapper releases a user attribute as a claim. Exactly one of ClientID
// and AllClients: releasing to every client is the wider disclosure, and is
// stated rather than read from a client left out.
type ClaimMapper struct {
	Attribute     string `yaml:"attribute"`
	Claim         string `yaml:"claim"`
	Destination   string `yaml:"destination"` // id_token, userinfo or access_token
	ClientID      string `yaml:"client_id,omitempty"`
	AllClients    bool   `yaml:"all_clients,omitempty"`
	RequiredScope string `yaml:"required_scope,omitempty"`
}

// key is what makes a mapper the one it is: its audience, attribute and
// destination, as the schema makes them unique.
func (m ClaimMapper) key() string { return mapperKey(m.ClientID, m.Attribute, m.Destination) }

func mapperKey(client, attribute, destination string) string {
	if client == "" {
		client = "*"
	}
	return attribute + " to " + destination + " for " + client
}

type mapperSection struct{}

func (mapperSection) kind() string { return "claim_mapper" }

// first is false: a mapper may name a client the file creates.
func (mapperSection) first() bool { return false }

func (mapperSection) validate(f *File, add func(string, ...any)) {
	keys := map[string]bool{}
	for i, m := range f.ClaimMappers {
		switch {
		case m.Attribute == "" || m.Claim == "" || m.Destination == "":
			add("claim_mappers[%d]: attribute, claim and destination are all required", i)
			continue
		case !slices.Contains([]string{"id_token", "userinfo", "access_token"}, m.Destination):
			add("claim_mappers[%d]: destination is id_token, userinfo or access_token, not %q", i, m.Destination)
		case (m.ClientID == "") == !m.AllClients:
			add("claim_mappers[%d]: name a client_id, or set all_clients to release to every client: the "+
				"difference is the whole disclosure, and a field left out must not be what widens it", i)
		}
		if keys[m.key()] {
			add("claim_mappers[%d]: %s appears twice", i, m.key())
		}
		keys[m.key()] = true
	}
}

func (mapperSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.ClaimMappers(ctx, tx, orgID)
	if err != nil {
		return err
	}
	planKeyed(p, "claim_mapper", keyBy(f.ClaimMappers, ClaimMapper.key),
		keyBy(have, func(m store.ClaimMapper) string { return mapperKey(m.ClientID, m.Attribute, m.Destination) }),
		prune, func(h store.ClaimMapper, w ClaimMapper) string {
			var c changed
			c.note(h.ClaimName != w.Claim, "claim")
			c.note(h.RequiredScope != w.RequiredScope, "required_scope")
			return c.String()
		}, "the claim stops being released")
	return nil
}

func (mapperSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, m := range f.ClaimMappers {
		if c, ok := p.planned("claim_mapper", m.key()); !ok || c.Action == "delete" {
			continue
		}
		if _, _, err := store.SetClaimMapper(ctx, tx, orgID, store.ClaimMapper{Attribute: m.Attribute,
			ClaimName: m.Claim, Destination: m.Destination, ClientID: m.ClientID,
			RequiredScope: m.RequiredScope}); err != nil {
			return refuse("claim mapper %s: %v", m.key(), err)
		}
	}
	return nil
}

func (mapperSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	have, err := store.ClaimMappers(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, m := range have {
		if mapperKey(m.ClientID, m.Attribute, m.Destination) == name {
			return store.RemoveClaimMapper(ctx, tx, orgID, m.ID)
		}
	}
	return nil
}

func (mapperSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.ClaimMappers(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, m := range have {
		f.ClaimMappers = append(f.ClaimMappers, ClaimMapper{Attribute: m.Attribute, Claim: m.ClaimName,
			Destination: m.Destination, ClientID: m.ClientID, AllClients: m.ClientID == "",
			RequiredScope: m.RequiredScope})
	}
	return nil
}

// documentSection is the access policy or the sign-in flows: one document,
// held as the text it was written in, so what is exported is what was applied.
type documentSection struct {
	name  string // the plan's Kind
	field func(*File) **string
	parse func([]byte) error
	read  func(context.Context, pgx.Tx, string) (store.AppliedDocument, error)
	write func(context.Context, pgx.Tx, string, []byte) error
	table string
	gone  string
}

func (d documentSection) kind() string { return d.name }
func (d documentSection) first() bool  { return false }

func (d documentSection) validate(f *File, add func(string, ...any)) {
	if doc := *d.field(f); doc != nil {
		if err := d.parse([]byte(*doc)); err != nil {
			add("%s: %v", d.name, err)
		}
	}
}

func (d documentSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := d.read(ctx, tx, orgID)
	if err != nil {
		return err
	}
	switch want := *d.field(f); {
	case want == nil && have.AppliedAt != nil && prune:
		p.Add(Change{Action: "delete", Kind: d.name, Name: "document", Destructive: true, Detail: d.gone})
	case want == nil:
	case have.AppliedAt == nil:
		p.Add(Change{Action: "create", Kind: d.name, Name: "document"})
	case have.Document != *want:
		p.Add(Change{Action: "update", Kind: d.name, Name: "document", Detail: "the document"})
	}
	return nil
}

func (d documentSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	c, ok := p.planned(d.name, "document")
	if want := *d.field(f); !ok || c.Action == "delete" || want == nil {
		return nil
	}
	return d.write(ctx, tx, orgID, []byte(**d.field(f)))
}

func (d documentSection) remove(ctx context.Context, tx pgx.Tx, orgID, _ string) error {
	_, err := tx.Exec(ctx, "DELETE FROM core."+d.table+" WHERE org_id = $1::uuid", orgID)
	return err
}

func (d documentSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := d.read(ctx, tx, orgID)
	if err != nil || have.AppliedAt == nil {
		return err
	}
	doc := have.Document
	*d.field(f) = &doc
	return nil
}

var accessPolicySection = documentSection{
	name:  "access_policy",
	field: func(f *File) **string { return &f.AccessPolicy },
	parse: func(b []byte) error { _, err := policy.Parse(b); return err },
	read: func(ctx context.Context, tx pgx.Tx, org string) (store.AppliedDocument, error) {
		return store.AccessPolicyOf(ctx, tx, org)
	},
	write: func(ctx context.Context, tx pgx.Tx, org string, doc []byte) error {
		_, err := store.ApplyAccessPolicy(ctx, tx, org, doc)
		return err
	},
	table: "access_policies",
	gone:  "no policy is in force, so every sign-in is allowed",
}

var signInFlowSection = documentSection{
	name:  "sign_in_flow",
	field: func(f *File) **string { return &f.SignInFlow },
	parse: func(b []byte) error { _, err := flow.Parse(b); return err },
	read: func(ctx context.Context, tx pgx.Tx, org string) (store.AppliedDocument, error) {
		return store.SignInFlowOf(ctx, tx, org)
	},
	write: func(ctx context.Context, tx pgx.Tx, org string, doc []byte) error {
		_, err := store.ApplySignInFlow(ctx, tx, org, doc)
		return err
	},
	table: "sign_in_flows",
	gone:  "the built-in flows are used again",
}

// Prompt is an interstitial prompt: terms, a notice, questions.
type Prompt struct {
	Slug  string `yaml:"slug"`
	Title string `yaml:"title"`
	Body  string `yaml:"body,omitempty"`
	// Once asks it a person's first time only; Order is where it comes.
	Once  bool `yaml:"once,omitempty"`
	Order int  `yaml:"order,omitempty"`
	// Enabled absent leaves it as it is, and on for a new one.
	Enabled *bool           `yaml:"enabled,omitempty"`
	Fields  []prompts.Field `yaml:"fields,omitempty"`
}

type promptSection struct{}

func (promptSection) kind() string { return "prompt" }

// first is false: a field may write an attribute the file declares, which
// the attribute section, being first, has made by then.
func (promptSection) first() bool { return false }

func (promptSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "prompts")
	for i, p := range f.Prompts {
		if !once(i, p.Slug) {
			continue
		}
		candidate := prompts.Prompt{Slug: p.Slug, Title: p.Title, Body: p.Body, Fields: p.Fields}
		if err := candidate.Validate(); err != nil {
			add("prompts[%s]: %v", p.Slug, err)
		}
	}
}

func fieldsOf(l []prompts.Field) string {
	if l == nil {
		l = []prompts.Field{}
	}
	b, _ := json.Marshal(l)
	return string(b)
}

const keptPrompt = "disabled rather than deleted: its answers are the record of who agreed to what"

func (promptSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.OrgPrompts(ctx, tx, orgID)
	if err != nil {
		return err
	}
	byName := keyBy(have, func(s store.PromptSummary) string { return s.Slug })
	// Pruned, a prompt is switched off and kept: deleting it would delete the
	// answers, and a consent nobody can show was given is no consent.
	planKeyed(p, "prompt", keyBy(f.Prompts, func(w Prompt) string { return w.Slug }), byName, false,
		func(h store.PromptSummary, w Prompt) string {
			var c changed
			c.note(h.Title != w.Title || h.Body != w.Body || fieldsOf(h.Fields) != fieldsOf(w.Fields),
				"what it asks, so everybody who answered is asked again")
			c.note(h.Once != w.Once, "once")
			c.note(h.Order != w.Order, "order")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			return c.String()
		}, "")
	if prune {
		inFile := keyBy(f.Prompts, func(w Prompt) string { return w.Slug })
		for _, h := range have {
			if _, ok := inFile[h.Slug]; !ok && h.Enabled {
				p.Add(Change{Action: "update", Kind: "prompt", Name: h.Slug, Detail: keptPrompt})
			}
		}
	}
	return nil
}

func (promptSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	inFile := map[string]bool{}
	for _, w := range f.Prompts {
		inFile[w.Slug] = true
		if c, ok := p.planned("prompt", w.Slug); !ok || c.Action == "delete" {
			continue
		}
		if _, _, err := store.SavePrompt(ctx, tx, orgID, store.PromptDefinition{Slug: w.Slug, Title: w.Title,
			Body: w.Body, Once: w.Once, Order: w.Order, Fields: w.Fields}); err != nil {
			return refuse("prompt %q: %v", w.Slug, err)
		}
		if w.Enabled != nil {
			if _, err := store.SetPromptEnabled(ctx, tx, orgID, w.Slug, *w.Enabled); err != nil {
				return err
			}
		}
	}
	have, err := store.OrgPrompts(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		if c, ok := p.planned("prompt", h.Slug); ok && !inFile[h.Slug] && strings.HasPrefix(c.Detail, "disabled") {
			if _, err := store.SetPromptEnabled(ctx, tx, orgID, h.Slug, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// remove is never planned: a pruned prompt is disabled, not deleted.
func (promptSection) remove(context.Context, pgx.Tx, string, string) error {
	return fmt.Errorf("a prompt is disabled by a pruned file, never deleted")
}

func (promptSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.OrgPrompts(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		enabled := h.Enabled
		f.Prompts = append(f.Prompts, Prompt{Slug: h.Slug, Title: h.Title, Body: h.Body, Once: h.Once,
			Order: h.Order, Enabled: &enabled, Fields: h.Fields})
	}
	return nil
}
