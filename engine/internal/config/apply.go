package config

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Reading the deployment, diffing it against the file, and applying.
//
// The read and the diff are separate from the write on purpose: `signari plan`
// runs the first two and stops. An operator sees exactly what would happen
// before anything does, which is the whole difference from configuration that
// applies itself at boot.

// current is what the deployment holds right now.
type current struct {
	groups        map[string]Group
	clients       map[string]Client
	samlProviders map[string]SAMLProvider
	radiusClients map[string]RADIUSClient
}

// read loads the current state for one organisation.
func read(ctx context.Context, tx pgx.Tx, orgID string) (*current, error) {
	c := &current{
		groups:        map[string]Group{},
		clients:       map[string]Client{},
		samlProviders: map[string]SAMLProvider{},
		radiusClients: map[string]RADIUSClient{},
	}

	rows, err := tx.Query(ctx, `
		SELECT name, COALESCE(display_name,''), COALESCE(description,'')
		  FROM core.groups WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.Name, &g.DisplayName, &g.Description); err != nil {
			rows.Close()
			return nil, err
		}
		c.groups[g.Name] = g
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
		SELECT c.client_id, c.display_name, c.client_type, c.scopes, c.enabled,
		       COALESCE(c.initiate_login_uri,''), COALESCE(c.logo_uri,''),
		       c.portal_hidden,
		       COALESCE(array_agg(r.redirect_uri) FILTER (WHERE r.redirect_uri IS NOT NULL),
		                '{}') AS uris
		  FROM core.clients c
		  LEFT JOIN core.client_redirect_uris r ON r.client_id = c.client_id
		 WHERE c.org_id = $1::uuid
		 GROUP BY c.client_id, c.display_name, c.client_type, c.scopes, c.enabled,
		          c.initiate_login_uri, c.logo_uri, c.portal_hidden`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cl Client
		var kind string
		var enabled bool
		if err := rows.Scan(&cl.ClientID, &cl.Name, &kind, &cl.Scopes, &enabled,
			&cl.LaunchURL, &cl.LogoURL, &cl.PortalHidden, &cl.RedirectURIs); err != nil {
			rows.Close()
			return nil, err
		}
		cl.Public = kind == "public"
		cl.Enabled = &enabled
		c.clients[cl.ClientID] = cl
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
		SELECT p.entity_id, p.display_name, p.name_id_format, p.enabled,
		       COALESCE(array_agg(a.url) FILTER (WHERE a.url IS NOT NULL), '{}')
		  FROM core.saml_providers p
		  LEFT JOIN core.saml_acs_urls a ON a.provider_id = p.id
		 WHERE p.org_id = $1::uuid
		 GROUP BY p.entity_id, p.display_name, p.name_id_format, p.enabled`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p SAMLProvider
		var enabled bool
		if err := rows.Scan(&p.EntityID, &p.Name, &p.NameID, &enabled, &p.ACSURLs); err != nil {
			rows.Close()
			return nil, err
		}
		p.Enabled = &enabled
		c.samlProviders[p.EntityID] = p
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
		SELECT name, network::text, enabled FROM core.radius_clients
		 WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r RADIUSClient
		var enabled bool
		if err := rows.Scan(&r.Name, &r.Network, &enabled); err != nil {
			rows.Close()
			return nil, err
		}
		r.Enabled = &enabled
		c.radiusClients[r.Network] = r
	}
	rows.Close()

	return c, nil
}

// BuildPlan diffs a file against the deployment.
//
// prune turns absence into deletion. Without it a file that omits a client
// leaves that client alone, which is the safe reading: a missing line in an
// identity provider's configuration takes down an application and every session
// through it, and that should never be the result of an edit somebody did not
// realise was destructive.
func BuildPlan(ctx context.Context, tx pgx.Tx, orgID string, f *File, prune bool) (*Plan, error) {
	cur, err := read(ctx, tx, orgID)
	if err != nil {
		return nil, err
	}
	p := &Plan{}

	for _, g := range f.Groups {
		have, ok := cur.groups[g.Name]
		switch {
		case !ok:
			p.Add(Change{Action: "create", Kind: "group", Name: g.Name})
		case have.DisplayName != g.DisplayName || have.Description != g.Description:
			p.Add(Change{Action: "update", Kind: "group", Name: g.Name,
				Detail: "display name or description"})
		}
	}

	for _, c := range f.Clients {
		have, ok := cur.clients[c.ClientID]
		if !ok {
			p.Add(Change{Action: "create", Kind: "client", Name: c.ClientID})
			continue
		}
		if d := clientDiff(have, c); d != "" {
			p.Add(Change{Action: "update", Kind: "client", Name: c.ClientID, Detail: d})
		}
	}

	for _, s := range f.SAMLProviders {
		have, ok := cur.samlProviders[s.EntityID]
		if !ok {
			p.Add(Change{Action: "create", Kind: "saml_provider", Name: s.EntityID})
			continue
		}
		if d := samlDiff(have, s); d != "" {
			p.Add(Change{Action: "update", Kind: "saml_provider", Name: s.EntityID, Detail: d})
		}
	}

	for _, r := range f.RADIUSClients {
		// Keyed on the network, which is what the database makes unique and what
		// actually identifies a device. The name is a label somebody renames.
		have, ok := cur.radiusClients[r.Network]
		if !ok {
			// Created without a secret, which the engine refuses to serve until one
			// is set. Reported here so it is not a surprise later.
			p.Add(Change{Action: "create", Kind: "radius_client", Name: r.Network,
				Detail: r.Name + " — needs `signari radius add-client` to set its secret"})
			continue
		}
		if have.Name != r.Name {
			p.Add(Change{Action: "update", Kind: "radius_client", Name: r.Network,
				Detail: have.Name + " → " + r.Name})
		}
	}

	if !prune {
		sortPlan(p)
		return p, nil
	}

	inFile := func(names map[string]bool, n string) bool { return names[n] }
	fileGroups, fileClients := map[string]bool{}, map[string]bool{}
	fileSPs, fileRadius := map[string]bool{}, map[string]bool{}
	for _, g := range f.Groups {
		fileGroups[g.Name] = true
	}
	for _, c := range f.Clients {
		fileClients[c.ClientID] = true
	}
	for _, s := range f.SAMLProviders {
		fileSPs[s.EntityID] = true
	}
	for _, r := range f.RADIUSClients {
		fileRadius[r.Network] = true
	}

	for name := range cur.groups {
		if !inFile(fileGroups, name) {
			p.Add(Change{Action: "delete", Kind: "group", Name: name, Destructive: true,
				Detail: "every policy naming this group stops matching"})
		}
	}
	for name := range cur.clients {
		if !inFile(fileClients, name) {
			p.Add(Change{Action: "delete", Kind: "client", Name: name, Destructive: true,
				Detail: "this application stops working immediately"})
		}
	}
	for name := range cur.samlProviders {
		if !inFile(fileSPs, name) {
			p.Add(Change{Action: "delete", Kind: "saml_provider", Name: name,
				Destructive: true, Detail: "this application stops working immediately"})
		}
	}
	for name := range cur.radiusClients {
		if !inFile(fileRadius, name) {
			p.Add(Change{Action: "delete", Kind: "radius_client", Name: name,
				Destructive: true, Detail: "this network device stops authenticating"})
		}
	}

	sortPlan(p)
	return p, nil
}

func sortPlan(p *Plan) {
	// Creates, then updates, then deletes; alphabetical within each. A plan in
	// map order is a plan that reads differently every run, and a diff nobody
	// can compare against last time is a diff nobody reads.
	rank := map[string]int{"create": 0, "update": 1, "delete": 2}
	sort.SliceStable(p.Changes, func(i, j int) bool {
		a, b := p.Changes[i], p.Changes[j]
		if rank[a.Action] != rank[b.Action] {
			return rank[a.Action] < rank[b.Action]
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
}

func clientDiff(have, want Client) string {
	var d []string
	if want.Name != "" && have.Name != want.Name {
		d = append(d, "name")
	}
	if !sameSet(have.RedirectURIs, want.RedirectURIs) {
		d = append(d, "redirect_uris")
	}
	if len(want.Scopes) > 0 && !sameSet(have.Scopes, want.Scopes) {
		d = append(d, "scopes")
	}
	if have.LaunchURL != want.LaunchURL {
		d = append(d, "launch_url")
	}
	if have.LogoURL != want.LogoURL {
		d = append(d, "logo_url")
	}
	if have.PortalHidden != want.PortalHidden {
		d = append(d, "portal_hidden")
	}
	if want.Enabled != nil && have.Enabled != nil && *have.Enabled != *want.Enabled {
		d = append(d, "enabled")
	}
	return strings.Join(d, ", ")
}

func samlDiff(have, want SAMLProvider) string {
	var d []string
	if want.Name != "" && have.Name != want.Name {
		d = append(d, "name")
	}
	if !sameSet(have.ACSURLs, want.ACSURLs) {
		d = append(d, "acs_urls")
	}
	if want.NameID != "" && have.NameID != want.NameID {
		d = append(d, "name_id_format")
	}
	if want.Enabled != nil && have.Enabled != nil && *have.Enabled != *want.Enabled {
		d = append(d, "enabled")
	}
	return strings.Join(d, ", ")
}

// sameSet compares two lists as sets.
//
// Order in a YAML list is how a human grouped things and carries no meaning to
// the engine. Comparing order would report a change every time somebody sorted
// their redirect URIs, and a diff that cries wolf is a diff nobody reads.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Apply performs a plan.
//
// One transaction. A configuration that is half applied looks like it worked
// and fails somewhere in the middle, which is the hardest state to diagnose and
// the easiest to avoid.
func Apply(ctx context.Context, tx pgx.Tx, orgID string, f *File, plan *Plan) error {
	byName := map[string]Change{}
	for _, c := range plan.Changes {
		byName[c.Kind+"/"+c.Name] = c
	}
	planned := func(kind, name string) (Change, bool) {
		c, ok := byName[kind+"/"+name]
		return c, ok
	}

	for _, g := range f.Groups {
		c, ok := planned("group", g.Name)
		if !ok || c.Action == "delete" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.groups (org_id, name, display_name, description)
			VALUES ($1::uuid, $2, NULLIF($3,''), NULLIF($4,''))
			ON CONFLICT (org_id, name) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				description = EXCLUDED.description,
				updated_at = now()`,
			orgID, g.Name, g.DisplayName, g.Description); err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
	}

	for _, cl := range f.Clients {
		c, ok := planned("client", cl.ClientID)
		if !ok || c.Action == "delete" {
			continue
		}
		kind := "confidential"
		if cl.Public {
			kind = "public"
		}
		scopes := cl.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email", "offline_access"}
		}
		enabled := true
		if cl.Enabled != nil {
			enabled = *cl.Enabled
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          scopes, enabled, initiate_login_uri, logo_uri,
			                          portal_hidden, client_secret_hash)
			VALUES ($1, $2::uuid, $3, $4, $5, $6, NULLIF($7,''), NULLIF($8,''), $9,
			        CASE WHEN $4 = 'confidential' THEN 'unset' ELSE NULL END)
			ON CONFLICT (client_id) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				scopes = EXCLUDED.scopes,
				enabled = EXCLUDED.enabled,
				initiate_login_uri = EXCLUDED.initiate_login_uri,
				logo_uri = EXCLUDED.logo_uri,
				portal_hidden = EXCLUDED.portal_hidden,
				updated_at = now()`,
			cl.ClientID, orgID, firstNonEmpty(cl.Name, cl.ClientID), kind, scopes,
			enabled, cl.LaunchURL, cl.LogoURL, cl.PortalHidden); err != nil {
			return fmt.Errorf("client %q: %w", cl.ClientID, err)
		}
		// Redirect URIs are replaced wholesale: the file is the list, and merging
		// would leave a removed URI still accepted.
		if _, err := tx.Exec(ctx,
			`DELETE FROM core.client_redirect_uris WHERE client_id = $1`, cl.ClientID); err != nil {
			return err
		}
		for _, u := range cl.RedirectURIs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
				 VALUES ($1, $2)`, cl.ClientID, u); err != nil {
				return fmt.Errorf("client %q redirect_uri %q: %w", cl.ClientID, u, err)
			}
		}
	}

	for _, sp := range f.SAMLProviders {
		c, ok := planned("saml_provider", sp.EntityID)
		if !ok || c.Action == "delete" {
			continue
		}
		nameID := sp.NameID
		if nameID == "" {
			nameID = "persistent"
		}
		enabled := true
		if sp.Enabled != nil {
			enabled = *sp.Enabled
		}
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO core.saml_providers (org_id, entity_id, display_name,
			                                 name_id_format, enabled)
			VALUES ($1::uuid, $2, $3, $4, $5)
			ON CONFLICT (org_id, entity_id) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				name_id_format = EXCLUDED.name_id_format,
				enabled = EXCLUDED.enabled,
				updated_at = now()
			RETURNING id::text`,
			orgID, sp.EntityID, firstNonEmpty(sp.Name, sp.EntityID), nameID,
			enabled).Scan(&id); err != nil {
			return fmt.Errorf("saml provider %q: %w", sp.EntityID, err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM core.saml_acs_urls WHERE provider_id = $1::uuid`, id); err != nil {
			return err
		}
		for i, u := range sp.ACSURLs {
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
				VALUES ($1::uuid, $2, 'HTTP-POST', $3)`, id, u, i == 0); err != nil {
				return fmt.Errorf("saml provider %q acs %q: %w", sp.EntityID, u, err)
			}
		}
	}

	for _, r := range f.RADIUSClients {
		c, ok := planned("radius_client", r.Network)
		if !ok || c.Action == "delete" {
			continue
		}
		// A client with no secret cannot answer, and the engine refuses to serve
		// one rather than answering with a secret nobody chose.
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.radius_clients (org_id, name, network, secret_enc, enabled)
			VALUES ($1::uuid, $2, $3::cidr, ''::bytea, false)
			ON CONFLICT (org_id, network) DO UPDATE SET
				name = EXCLUDED.name, updated_at = now()`,
			orgID, r.Name, r.Network); err != nil {
			return fmt.Errorf("radius client %q: %w", r.Name, err)
		}
	}

	// Deletions last, so a plan that both creates and deletes never leaves a gap
	// where neither exists.
	for _, c := range plan.Changes {
		if c.Action != "delete" {
			continue
		}
		var err error
		switch c.Kind {
		case "group":
			_, err = tx.Exec(ctx,
				`DELETE FROM core.groups WHERE org_id = $1::uuid AND name = $2`, orgID, c.Name)
		case "client":
			_, err = tx.Exec(ctx,
				`DELETE FROM core.clients WHERE org_id = $1::uuid AND client_id = $2`, orgID, c.Name)
		case "saml_provider":
			_, err = tx.Exec(ctx,
				`DELETE FROM core.saml_providers WHERE org_id = $1::uuid AND entity_id = $2`,
				orgID, c.Name)
		case "radius_client":
			_, err = tx.Exec(ctx,
				`DELETE FROM core.radius_clients WHERE org_id = $1::uuid AND network = $2::cidr`,
				orgID, c.Name)
		}
		if err != nil {
			return fmt.Errorf("deleting %s %q: %w", c.Kind, c.Name, err)
		}
	}
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
