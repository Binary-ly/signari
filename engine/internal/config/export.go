package config

import (
	"context"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

// Export is an organisation's configuration as a file `signari apply` takes
// (6.11): what plan and apply read, so the file applied to a deployment that
// holds it already plans nothing, and applied to an empty one makes it so.
//
// Read through the same function BuildPlan diffs against, so an export cannot
// describe a field the plan does not compare, or leave out one it does.
// Sorted by each kind's key, so two exports of one configuration are one file.
//
// What it does not carry, by design: secrets. A confidential client applied
// from it has no secret until one is rotated, and a RADIUS client none until
// `signari radius add-client` sets it, which is why a RADIUS client's
// `enabled` is left out: applied, it is created disabled whatever the file
// says, and the file must not plan to enable it.
func Export(ctx context.Context, tx pgx.Tx, orgID string) (*File, error) {
	cur, err := read(ctx, tx, orgID)
	if err != nil {
		return nil, fmt.Errorf("reading the organisation's configuration: %w", err)
	}
	f := &File{Version: 1, Org: orgID}
	for _, g := range cur.groups {
		f.Groups = append(f.Groups, g)
	}
	sort.Slice(f.Groups, func(i, j int) bool { return f.Groups[i].Name < f.Groups[j].Name })
	for _, c := range cur.clients {
		sort.Strings(c.RedirectURIs)
		f.Clients = append(f.Clients, c)
	}
	sort.Slice(f.Clients, func(i, j int) bool { return f.Clients[i].ClientID < f.Clients[j].ClientID })
	for _, p := range cur.samlProviders {
		f.SAMLProviders = append(f.SAMLProviders, p)
	}
	sort.Slice(f.SAMLProviders, func(i, j int) bool { return f.SAMLProviders[i].EntityID < f.SAMLProviders[j].EntityID })
	for _, r := range cur.radiusClients {
		r.Enabled, r.Secret = nil, ""
		f.RADIUSClients = append(f.RADIUSClients, r)
	}
	sort.Slice(f.RADIUSClients, func(i, j int) bool { return f.RADIUSClients[i].Network < f.RADIUSClients[j].Network })
	for _, h := range cur.proxyHosts {
		f.ProxyHosts = append(f.ProxyHosts, h)
	}
	sort.Slice(f.ProxyHosts, func(i, j int) bool { return f.ProxyHosts[i].Host < f.ProxyHosts[j].Host })
	return f, nil
}

// Marshal renders a File as the YAML Parse reads.
func (f *File) Marshal() ([]byte, error) {
	return yaml.Marshal(f)
}
