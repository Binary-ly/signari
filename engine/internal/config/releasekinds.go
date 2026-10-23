package config

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// What is told of group membership, in a configuration file (6.25): to an
// OIDC client or a SAML service provider, and to a network device as a VLAN
// or a filter. Membership is authorization data, so a release names its
// groups or says all_groups, and the wider disclosure is never what a field
// left out means.

// GroupRelease is the groups one application is told a person is in.
type GroupRelease struct {
	// ClientID or SAMLProvider (an entity id), one of the two.
	ClientID     string `yaml:"client_id,omitempty"`
	SAMLProvider string `yaml:"saml_provider,omitempty"`
	// Groups, or AllGroups for every group the person is in.
	Groups    []string `yaml:"groups,omitempty"`
	AllGroups bool     `yaml:"all_groups,omitempty"`
	// Attribute is the SAML attribute they are sent in, groups when absent.
	Attribute string `yaml:"attribute,omitempty"`
}

func (r GroupRelease) key() string {
	if r.ClientID != "" {
		return "client " + r.ClientID
	}
	return "saml " + r.SAMLProvider
}

func (r GroupRelease) attribute() string {
	if r.Attribute == "" && r.SAMLProvider != "" {
		return "groups"
	}
	return r.Attribute
}

type releaseSection struct{}

func (releaseSection) kind() string { return "group_release" }

// first is false: a release names clients, providers and groups the file may
// make.
func (releaseSection) first() bool { return false }

func (releaseSection) validate(f *File, add func(string, ...any)) {
	keys := map[string]bool{}
	for i, r := range f.GroupReleases {
		switch {
		case (r.ClientID == "") == (r.SAMLProvider == ""):
			add("group_releases[%d]: name a client_id or a saml_provider, one of the two", i)
			continue
		case (len(r.Groups) == 0) == !r.AllGroups:
			add("group_releases[%s]: name the groups, or set all_groups: membership is authorization data, and "+
				"a list left out must not be what releases all of it", r.key())
		case r.Attribute != "" && r.ClientID != "":
			add("group_releases[%s]: attribute is a SAML provider's; a client is told in the groups claim", r.key())
		}
		if keys[r.key()] {
			add("group_releases[%s]: appears twice", r.key())
		}
		keys[r.key()] = true
	}
}

// heldReleases is every release the organisation has, by key.
func heldReleases(ctx context.Context, tx pgx.Tx, orgID string) (map[string]GroupRelease, map[string]string, error) {
	clients, err := store.ClientGroupReleases(ctx, tx, orgID)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]GroupRelease{}
	for id, only := range clients {
		r := GroupRelease{ClientID: id, Groups: sortedCopy(only), AllGroups: len(only) == 0}
		out[r.key()] = r
	}
	providers, err := store.SAMLProviders(ctx, tx, orgID)
	if err != nil {
		return nil, nil, err
	}
	ids := map[string]string{}
	for _, p := range providers {
		ids[p.EntityID] = p.ID
		if p.ReleasesGroups {
			r := GroupRelease{SAMLProvider: p.EntityID, Groups: sortedCopy(p.OnlyGroups),
				AllGroups: len(p.OnlyGroups) == 0, Attribute: p.GroupAttribute}
			out[r.key()] = r
		}
	}
	return out, ids, nil
}

func (releaseSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	held, providers, err := heldReleases(ctx, tx, orgID)
	if err != nil {
		return err
	}
	inFile := map[string]bool{}
	for _, c := range f.Clients {
		inFile["client "+c.ClientID] = true
	}
	for _, s := range f.SAMLProviders {
		inFile["saml "+s.EntityID] = true
	}
	var groups []string
	for _, r := range f.GroupReleases {
		groups = append(groups, r.Groups...)
		if inFile[r.key()] {
			continue
		}
		if r.SAMLProvider != "" {
			if _, ok := providers[r.SAMLProvider]; !ok {
				return refuse("group_releases[%s]: the organisation has no such service provider; declare it in "+
					"saml_providers", r.key())
			}
			continue
		}
		var ours bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1 AND org_id = $2::uuid)`,
			r.ClientID, orgID).Scan(&ours); err != nil {
			return err
		}
		if !ours {
			return refuse("group_releases[%s]: the organisation has no such client; declare it in clients", r.key())
		}
	}
	if missing, err := missingGroups(ctx, tx, orgID, f, prune, groups); err != nil {
		return err
	} else if len(missing) > 0 {
		return refuse("group_releases: the organisation has no group %s to release; declare it in groups",
			strings.Join(missing, ", "))
	}
	planKeyed(p, "group_release", keyBy(f.GroupReleases, GroupRelease.key), held, prune,
		func(h, w GroupRelease) string {
			var c changed
			c.note(h.AllGroups != w.AllGroups || !sameSet(h.Groups, w.Groups), "groups")
			c.note(h.attribute() != w.attribute(), "attribute")
			return c.String()
		}, "the application stops being told which groups a person is in")
	return nil
}

func (releaseSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	_, providers, err := heldReleases(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, r := range f.GroupReleases {
		if c, ok := p.planned("group_release", r.key()); !ok || c.Action == "delete" {
			continue
		}
		only := r.Groups
		if r.AllGroups {
			only = nil
		}
		if r.ClientID != "" {
			err = store.ReleaseGroupsToClient(ctx, tx, orgID, r.ClientID, only)
		} else {
			err = store.SetSAMLGroupRelease(ctx, tx, orgID, providers[r.SAMLProvider], r.Attribute, only)
		}
		if err != nil {
			return refuse("group_releases[%s]: %v", r.key(), err)
		}
	}
	return nil
}

func (releaseSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	kind, target, _ := strings.Cut(name, " ")
	if kind == "client" {
		_, err := store.StopGroupRelease(ctx, tx, target)
		return err
	}
	_, providers, err := heldReleases(ctx, tx, orgID)
	if err != nil {
		return err
	}
	if err := store.StopSAMLGroupRelease(ctx, tx, orgID, providers[target]); err != nil &&
		!errors.Is(err, store.ErrSAMLReleaseUnknown) {
		return err
	}
	return nil
}

func (releaseSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	held, _, err := heldReleases(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, k := range sortedKeys(held) {
		r := held[k]
		if r.Attribute == "groups" {
			r.Attribute = ""
		}
		f.GroupReleases = append(f.GroupReleases, r)
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return sortedCopy(out)
}

// RADIUSAuthorization places a group's members on a VLAN, a filter or both,
// when a network device asks about them.
type RADIUSAuthorization struct {
	Group string `yaml:"group"`
	// VLAN is 1 to 4094 (RFC 3580 section 3.31); FilterID the name of a filter
	// list the device already has. One or both.
	VLAN     int    `yaml:"vlan,omitempty"`
	FilterID string `yaml:"filter_id,omitempty"`
	// Priority decides for somebody in several authorised groups, highest
	// first.
	Priority int `yaml:"priority,omitempty"`
}

type radiusAuthSection struct{}

func (radiusAuthSection) kind() string { return "radius_authorization" }

// first is false: the group may be one the file makes.
func (radiusAuthSection) first() bool { return false }

func (radiusAuthSection) validate(f *File, add func(string, ...any)) {
	once := seen(add, "radius_authorizations")
	for i, a := range f.RADIUSAuthorizations {
		if !once(i, a.Group) {
			continue
		}
		switch {
		case a.VLAN == 0 && strings.TrimSpace(a.FilterID) == "":
			add("radius_authorizations[%s]: %v", a.Group, store.ErrRADIUSNothingAuthorised)
		case a.VLAN < 0 || a.VLAN > 4094:
			add("radius_authorizations[%s]: %v", a.Group, store.ErrVLANRange)
		case len(a.FilterID) > 253:
			add("radius_authorizations[%s]: %v", a.Group, store.ErrFilterIDLength)
		}
	}
}

func heldAuthorizations(ctx context.Context, tx pgx.Tx, orgID string) (map[string]RADIUSAuthorization, error) {
	have, err := store.RADIUSAuthorizations(ctx, tx, orgID, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]RADIUSAuthorization{}
	for _, a := range have {
		r := RADIUSAuthorization{Group: a.Group, FilterID: a.FilterID, Priority: a.Priority}
		if a.VLAN != nil {
			r.VLAN = *a.VLAN
		}
		out[a.Group] = r
	}
	return out, nil
}

func (radiusAuthSection) plan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool, p *Plan) error {
	held, err := heldAuthorizations(ctx, tx, orgID)
	if err != nil {
		return err
	}
	var groups []string
	for _, a := range f.RADIUSAuthorizations {
		groups = append(groups, a.Group)
	}
	if missing, err := missingGroups(ctx, tx, orgID, f, prune, groups); err != nil {
		return err
	} else if len(missing) > 0 {
		return refuse("radius_authorizations: the organisation has no group %s; declare it in groups",
			strings.Join(missing, ", "))
	}
	planKeyed(p, "radius_authorization", keyBy(f.RADIUSAuthorizations, func(a RADIUSAuthorization) string {
		return a.Group
	}), held, prune, func(h, w RADIUSAuthorization) string {
		var c changed
		c.note(h.VLAN != w.VLAN, "vlan")
		c.note(h.FilterID != strings.TrimSpace(w.FilterID), "filter_id")
		c.note(h.Priority != w.Priority, "priority")
		return c.String()
	}, "members are put on the device's default network")
	return nil
}

func (radiusAuthSection) apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, p *Plan) error {
	for _, a := range f.RADIUSAuthorizations {
		if c, ok := p.planned("radius_authorization", a.Group); !ok || c.Action == "delete" {
			continue
		}
		id, err := store.GroupIDNamed(ctx, tx, orgID, a.Group)
		if err != nil {
			return err
		}
		if err := store.SetRADIUSAuthorization(ctx, tx, orgID, id, a.VLAN, a.FilterID, a.Priority); err != nil {
			return err
		}
	}
	return nil
}

func (radiusAuthSection) remove(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	id, err := store.GroupIDNamed(ctx, tx, orgID, name)
	if err != nil || id == "" {
		return err
	}
	if err := store.RemoveRADIUSAuthorization(ctx, tx, orgID, id); err != nil &&
		!errors.Is(err, store.ErrRADIUSNotAuthorised) {
		return err
	}
	return nil
}

func (radiusAuthSection) export(ctx context.Context, tx pgx.Tx, orgID string, f *File) error {
	held, err := heldAuthorizations(ctx, tx, orgID)
	if err != nil {
		return err
	}
	for _, k := range sortedKeys(held) {
		f.RADIUSAuthorizations = append(f.RADIUSAuthorizations, held[k])
	}
	return nil
}
