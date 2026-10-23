package config

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provider"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Extension providers and event subscriptions in a configuration file (6.19):
// the two kinds holding a signing secret, which the engine mints when one is
// created unless the file names one the receiver already holds.

// Provider is the operator's own service, consulted at a hook (ADR-011).
type Provider struct {
	Hook string `yaml:"hook"`
	URL  string `yaml:"url"`
	// Mode is fail_closed or fail_open, never assumed: an authorization hook
	// that fails open stops enforcing exactly when something is wrong.
	Mode string `yaml:"mode"`
	// Timeout is 2s for a new one when absent, and left as it is afterwards.
	Timeout *time.Duration `yaml:"timeout,omitempty"`
	// Claims are what a token_issue provider may add; absent leaves them.
	Claims *[]string `yaml:"claims,omitempty"`
	// Secret absent, one is minted when the provider is created and shown
	// once; a provider already registered keeps the one it holds.
	Secret *SecretRef `yaml:"secret,omitempty"`
}

// defaultProviderTimeout is what `signari provider add` and the Admin API wait
// when given none.
const defaultProviderTimeout = 2 * time.Second

// registration is the provider as store.SaveProvider takes it, named as the
// command and the route name one.
func (w Provider) registration(timeout time.Duration) provider.Provider {
	return provider.Provider{Name: "provider-" + w.Hook, Hook: provider.Hook(w.Hook), URL: w.URL,
		Mode: provider.Mode(w.Mode), Timeout: timeout}
}

func (w Provider) where() string { return fmt.Sprintf("providers[%s].secret", w.Hook) }

type providerSection struct{}

func (providerSection) kind() string { return "provider" }
func (providerSection) first() bool  { return false }

func (providerSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "providers")
	for i, w := range f.Providers {
		if !once(i, w.Hook) {
			continue
		}
		timeout := defaultProviderTimeout
		if w.Timeout != nil {
			timeout = *w.Timeout
		}
		reg := w.registration(timeout)
		if err := reg.Validate(); err != nil {
			add("providers[%s]: %v", w.Hook, err)
		}
		if w.Claims != nil {
			if len(*w.Claims) > 0 && reg.Hook != provider.HookTokenIssue {
				add("providers[%s]: claims are what a %s provider may add to a token, and this hook adds none",
					w.Hook, provider.HookTokenIssue)
			}
			reg.AllowedClaims = *w.Claims
			for _, c := range *w.Claims {
				if !reg.MayContribute(c) {
					add("providers[%s]: %q is a protocol claim, which no provider may set", w.Hook, c)
				}
			}
		}
		if w.Secret != nil {
			w.Secret.check(w.where(), add)
		}
	}
}

func (providerSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.ListProviders(ctx, tx, orgID)
	if err != nil {
		return err
	}
	// The secret a file names is checked whether or not it differs, so a
	// reference that will not do is refused at the plan and not at the apply.
	for _, w := range f.Providers {
		if w.Secret == nil {
			continue
		}
		secret, err := w.Secret.secret(w.where())
		if err != nil {
			return err
		}
		if err := store.CheckSigningSecret(secret); err != nil {
			return refuse("%s: %v", w.where(), err)
		}
	}
	var compared error
	planKeyed(p, "provider", keyBy(f.Providers, func(w Provider) string { return w.Hook }),
		keyBy(have, func(r store.ProviderRow) string { return r.Hook }), prune,
		func(h store.ProviderRow, w Provider) string {
			var c changed
			c.note(h.URL != w.URL, "url")
			c.note(h.Mode != w.Mode, "mode")
			c.note(w.Timeout != nil && h.Timeout != *w.Timeout, "timeout")
			c.note(w.Claims != nil && !sameSet(h.AllowedClaims, *w.Claims), "claims")
			if w.Secret != nil && compared == nil {
				if compared = p.needsRoot("provider", w.Hook, "comparing the secret the file names"); compared == nil {
					var held string
					held, compared = store.ProviderSecret(ctx, tx, p.opts.Root, orgID, provider.Hook(w.Hook))
					c.note(held != w.Secret.value, "secret")
				}
			}
			return c.String()
		}, "the hook stops being consulted, so what it decided nothing decides")
	if compared != nil {
		return compared
	}
	return describeSecrets(p, "provider", f.Providers, func(w Provider) (string, *SecretRef) { return w.Hook, w.Secret },
		func(c Change) bool { return true })
}

// describeSecrets says on each planned create where its secret comes from, and
// refuses the plan when what a change needs to seal cannot be sealed here.
func describeSecrets[W any](p *Plan, kind string, want []W, ref func(W) (string, *SecretRef),
	seals func(Change) bool) error {
	refs := map[string]*SecretRef{}
	for _, w := range want {
		name, r := ref(w)
		refs[name] = r
	}
	for i, c := range p.Changes {
		if c.Kind != kind || c.Action == "delete" {
			continue
		}
		if c.Action == "create" {
			if r := refs[c.Name]; r != nil {
				p.Changes[i].Detail = "its signing secret from " + r.String()
			} else {
				p.Changes[i].Detail = "a signing secret is minted and shown once"
			}
		}
		if c.Action == "create" || refs[c.Name] != nil || seals(c) {
			if err := p.needsRoot(kind, c.Name, "sealing its signing secret"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (providerSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.ListProviders(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(r store.ProviderRow) string { return r.Hook })
	for _, w := range f.Providers {
		if c, ok := p.planned("provider", w.Hook); !ok || c.Action == "delete" {
			continue
		}
		timeout := defaultProviderTimeout
		if h, ok := held[w.Hook]; ok {
			timeout = h.Timeout
		}
		if w.Timeout != nil {
			timeout = *w.Timeout
		}
		_, minted, err := store.SaveProvider(ctx, tx, p.opts.Root, orgID, w.registration(timeout))
		if err != nil {
			return err
		}
		if w.Claims != nil {
			if err := store.SetProviderClaims(ctx, tx, orgID, provider.Hook(w.Hook), *w.Claims); err != nil {
				return err
			}
		}
		switch {
		case w.Secret != nil:
			if err := store.SetProviderSecret(ctx, tx, p.opts.Root, orgID, provider.Hook(w.Hook),
				w.Secret.value); err != nil {
				return err
			}
		case minted != "":
			p.Minted = append(p.Minted, Minted{Kind: "provider", Name: w.Hook, Secret: minted})
		}
	}
	return nil
}

func (providerSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	_, err := store.DeleteProvider(ctx, tx, orgID, provider.Hook(name))
	return err
}

// export leaves the secret out: applied elsewhere, a provider is given a new
// one, which its service must then be given, or the file names it.
func (providerSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.ListProviders(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		w := Provider{Hook: h.Hook, URL: h.URL, Mode: h.Mode, Timeout: &h.Timeout}
		if len(h.AllowedClaims) > 0 {
			claims := sortedCopy(h.AllowedClaims)
			w.Claims = &claims
		}
		f.Providers = append(f.Providers, w)
	}
	return nil
}

// Subscription is a URL the organisation's events are delivered to, signed.
type Subscription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// EventTypes are what is delivered: every event for a new subscription
	// that names none, and left as they are afterwards when absent.
	EventTypes *[]string `yaml:"event_types,omitempty"`
	// Enabled absent leaves it; true switches back on a subscription the
	// deliveries gave up on, and false stops delivering to it.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Secret absent, one is minted when the subscription is created and shown
	// once; one already made keeps the one it holds.
	Secret *SecretRef `yaml:"secret,omitempty"`
}

func (w Subscription) where() string { return fmt.Sprintf("event_subscriptions[%s].secret", w.Name) }

func (w Subscription) types() []string {
	if w.EventTypes == nil {
		return nil
	}
	return *w.EventTypes
}

type subscriptionSection struct{}

func (subscriptionSection) kind() string { return "event_subscription" }
func (subscriptionSection) first() bool  { return false }

func (subscriptionSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "event_subscriptions")
	for i, w := range f.Subscriptions {
		if !once(i, w.Name) {
			continue
		}
		if err := safedial.CheckURL(w.URL); err != nil {
			add("event_subscriptions[%s]: %v", w.Name, err)
		}
		if err := store.CheckEventTypes(w.types()); err != nil {
			add("event_subscriptions[%s]: %v", w.Name, err)
		}
		if w.Secret != nil {
			w.Secret.check(w.where(), add)
		}
	}
}

// disabledByFile is the reason recorded on a subscription a file switches off.
const disabledByFile = "disabled by a configuration file"

func (subscriptionSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	have, err := store.OrgSubscriptions(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, w := range f.Subscriptions {
		if w.Secret == nil {
			continue
		}
		secret, err := w.Secret.secret(w.where())
		if err != nil {
			return err
		}
		if err := store.CheckSigningSecret(secret); err != nil {
			return refuse("%s: %v", w.where(), err)
		}
	}
	var compared error
	planKeyed(p, "event_subscription", keyBy(f.Subscriptions, func(w Subscription) string { return w.Name }),
		keyBy(have, func(s store.SubscriptionStatus) string { return s.Name }), prune,
		func(h store.SubscriptionStatus, w Subscription) string {
			var c changed
			c.note(h.URL != w.URL, "url")
			c.note(w.EventTypes != nil && !sameSet(h.EventTypes, *w.EventTypes), "event_types")
			c.note(w.Enabled != nil && h.Enabled != *w.Enabled, "enabled")
			if w.Secret != nil && compared == nil {
				if compared = p.needsRoot("event_subscription", w.Name,
					"comparing the secret the file names"); compared == nil {
					var held string
					held, compared = store.SubscriptionSecret(ctx, tx, p.opts.Root, orgID, w.Name)
					c.note(held != w.Secret.value, "secret")
				}
			}
			return c.String()
		}, "its events stop being delivered")
	if compared != nil {
		return compared
	}
	// Only a create, or a secret the file names, is sealed: a new URL or list
	// of events is not.
	return describeSecrets(p, "event_subscription", f.Subscriptions,
		func(w Subscription) (string, *SecretRef) { return w.Name, w.Secret }, func(Change) bool { return false })
}

func (subscriptionSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	have, err := store.OrgSubscriptions(ctx, tx, orgID)
	if err != nil {
		return err
	}
	held := keyBy(have, func(s store.SubscriptionStatus) string { return s.Name })
	for _, w := range f.Subscriptions {
		c, ok := p.planned("event_subscription", w.Name)
		if !ok || c.Action == "delete" {
			continue
		}
		var id string
		if c.Action == "create" {
			sub, err := store.CreateSubscription(ctx, tx, p.opts.Root, orgID, w.Name, w.URL, w.types())
			if err != nil {
				return err
			}
			id = sub.ID
			if w.Secret == nil {
				p.Minted = append(p.Minted, Minted{Kind: "event_subscription", Name: w.Name, Secret: sub.Secret})
			}
		} else {
			h := held[w.Name]
			id = h.ID
			types := h.EventTypes
			if w.EventTypes != nil {
				types = *w.EventTypes
			}
			if err := store.UpdateSubscription(ctx, tx, orgID, w.Name, w.URL, types); err != nil {
				return err
			}
		}
		if w.Secret != nil {
			if err := store.SetSubscriptionSecret(ctx, tx, p.opts.Root, orgID, w.Name, w.Secret.value); err != nil {
				return err
			}
		}
		switch {
		case w.Enabled == nil:
		case *w.Enabled && c.Action == "update" && !held[w.Name].Enabled:
			if err := store.EnableSubscription(ctx, tx, orgID, w.Name); err != nil {
				return err
			}
		case !*w.Enabled:
			if err := store.DisableSubscription(ctx, tx, id, disabledByFile); err != nil {
				return err
			}
		}
	}
	return nil
}

func (subscriptionSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	_, err := store.RemoveSubscription(ctx, tx, orgID, name)
	return err
}

// export leaves out the secret, as a provider's, and whether it is switched
// on: a subscription the deliveries gave up on is the deployment's state,
// and applied elsewhere it starts afresh.
func (subscriptionSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	have, err := store.OrgSubscriptions(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, h := range have {
		types := sortedCopy(h.EventTypes)
		f.Subscriptions = append(f.Subscriptions, Subscription{Name: h.Name, URL: h.URL, EventTypes: &types})
	}
	return nil
}
