package config

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
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
	proxyHosts    map[string]ProxyHost
}

// read loads the current state for one organisation.
func read(ctx context.Context, tx pgx.Tx, orgID string) (*current, error) {
	c := &current{
		groups:        map[string]Group{},
		clients:       map[string]Client{},
		samlProviders: map[string]SAMLProvider{},
		radiusClients: map[string]RADIUSClient{},
		proxyHosts:    map[string]ProxyHost{},
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
		       c.portal_hidden, c.may_exchange, c.exchange_audiences,
		       COALESCE(array_agg(r.redirect_uri) FILTER (WHERE r.redirect_uri IS NOT NULL),
		                '{}') AS uris
		  FROM core.clients c
		  LEFT JOIN core.client_redirect_uris r ON r.client_id = c.client_id
		 WHERE c.org_id = $1::uuid
		 GROUP BY c.client_id, c.display_name, c.client_type, c.scopes, c.enabled,
		          c.initiate_login_uri, c.logo_uri, c.portal_hidden, c.may_exchange,
		          c.exchange_audiences`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cl Client
		var kind string
		var enabled bool
		x := &TokenExchange{}
		if err := rows.Scan(&cl.ClientID, &cl.Name, &kind, &cl.Scopes, &enabled,
			&cl.LaunchURL, &cl.LogoURL, &cl.PortalHidden, &x.Enabled, &x.Audiences,
			&cl.RedirectURIs); err != nil {
			rows.Close()
			return nil, err
		}
		cl.Public = kind == "public"
		cl.Enabled = &enabled
		cl.TokenExchange = x
		c.clients[cl.ClientID] = cl
	}
	rows.Close()
	for id, cl := range c.clients {
		uris, fc, sid, err := store.ClientLogoutOf(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		cl.PostLogoutRedirectURIs, cl.FrontchannelLogoutURI, cl.FrontchannelSessionRequired = &uris, &fc, &sid
		st, err := store.ClientSettingsOf(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		cl.AccessTokenTTL, cl.RefreshTokenTTL, cl.IDTokenAlg = &st.AccessTokenTTL, &st.RefreshTokenTTL, &st.IDTokenAlg
		cl.RequirePAR, cl.FirstParty, cl.IssuerAlias = &st.RequirePAR, &st.FirstParty, &st.IssuerAlias
		cl.MinimumACR = &st.MinimumACR
		c.clients[id] = cl
	}

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

	rows, err = tx.Query(ctx, `
		SELECT host, enabled FROM core.proxy_hosts WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h ProxyHost
		var enabled bool
		if err := rows.Scan(&h.Host, &enabled); err != nil {
			rows.Close()
			return nil, err
		}
		h.Enabled = &enabled
		c.proxyHosts[h.Host] = h
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

	for _, h := range f.ProxyHosts {
		want := h.Enabled == nil || *h.Enabled
		have, ok := cur.proxyHosts[h.Host]
		if !ok {
			p.Add(Change{Action: "create", Kind: "proxy_host", Name: h.Host})
			continue
		}
		if *have.Enabled != want {
			p.Add(Change{Action: "update", Kind: "proxy_host", Name: h.Host,
				Detail: fmt.Sprintf("enabled %v → %v", *have.Enabled, want)})
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
	fileHosts := map[string]bool{}
	for _, h := range f.ProxyHosts {
		fileHosts[h.Host] = true
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
	for name := range cur.proxyHosts {
		if !inFile(fileHosts, name) {
			p.Add(Change{Action: "delete", Kind: "proxy_host", Name: name, Destructive: true,
				Detail: "sign-in stops returning people to this application"})
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
	if w, h := want.TokenExchange, have.TokenExchange; w != nil && h != nil {
		wantAud, _ := store.CleanExchangeAudiences(w.Audiences)
		if !w.Enabled {
			wantAud = nil
		}
		if w.Enabled != h.Enabled || !sameSet(wantAud, h.Audiences) {
			d = append(d, "token_exchange")
		}
	}
	if w, h := want.PostLogoutRedirectURIs, have.PostLogoutRedirectURIs; w != nil && h != nil && !sameSet(*w, *h) {
		d = append(d, "post_logout_redirect_uris")
	}
	if w, h := want.FrontchannelLogoutURI, have.FrontchannelLogoutURI; w != nil && h != nil && *w != *h {
		d = append(d, "frontchannel_logout_uri")
	}
	if w, h := want.FrontchannelSessionRequired, have.FrontchannelSessionRequired; w != nil && h != nil && *w != *h {
		d = append(d, "frontchannel_logout_session_required")
	}
	if w, h := want.AccessTokenTTL, have.AccessTokenTTL; w != nil && h != nil && *w != *h {
		d = append(d, "access_token_ttl")
	}
	if w, h := want.RefreshTokenTTL, have.RefreshTokenTTL; w != nil && h != nil && *w != *h {
		d = append(d, "refresh_token_ttl")
	}
	if w, h := want.IDTokenAlg, have.IDTokenAlg; w != nil && h != nil && *w != *h {
		d = append(d, "id_token_signed_response_alg")
	}
	if w, h := want.RequirePAR, have.RequirePAR; w != nil && h != nil && *w != *h {
		d = append(d, "require_pushed_authorization_requests")
	}
	if w, h := want.FirstParty, have.FirstParty; w != nil && h != nil && *w != *h {
		d = append(d, "first_party")
	}
	if w, h := want.IssuerAlias, have.IssuerAlias; w != nil && h != nil && strings.TrimSpace(*w) != *h {
		d = append(d, "issuer_alias")
	}
	if w, h := want.MinimumACR, have.MinimumACR; w != nil && h != nil && *w != *h {
		d = append(d, "minimum_acr")
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
		// What the file leaves out keeps its value on an update, as the plan
		// reported, and takes the default only for a new client. This wrote the
		// defaults every time: an apply that moved one redirect URI re-enabled a
		// client an operator had switched off, renamed it to its identifier and
		// reset its scopes, while the plan said none of that would happen.
		var scopes any // NULL keeps the current scopes
		if len(cl.Scopes) > 0 {
			scopes = cl.Scopes
		}

		// Every non-standard scope must be one the organisation declared.
		//
		// This is where a typo is worth catching, and the only place it can be:
		// `signari plan` runs without a database on purpose, so it cannot know
		// which scopes exist, and by request time it is far too late — a client
		// registered for "hr_recrods" simply never receives the claim that a
		// mapper gated on "hr_records", and the configuration looks correct at
		// both ends.
		//
		// Refused rather than warned. A warning during apply is read by nobody
		// at 2am, and the failure it predicts is silent for months.
		if undeclared, uerr := store.UndeclaredScopes(ctx, tx, orgID, cl.Scopes); uerr != nil {
			return fmt.Errorf("checking the scopes for client %q: %w", cl.ClientID, uerr)
		} else if len(undeclared) > 0 {
			return fmt.Errorf("client %q is registered for scope(s) %s, which this "+
				"organisation has not declared. Declare them first, or correct the "+
				"spelling: a client registered for a scope nobody declared can ask "+
				"for it and receive nothing, and any claim mapper gated on the "+
				"intended spelling silently never fires",
				cl.ClientID, strings.Join(undeclared, ", "))
		}
		// The update is confined to this organisation's row. client_id is unique
		// across the deployment and the plan reads only this organisation's
		// clients, so another tenant's identifier was planned as a create and
		// then rewrote that tenant's client, redirect URIs included.
		var written string
		err := tx.QueryRow(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          scopes, enabled, initiate_login_uri, logo_uri,
			                          portal_hidden, client_secret_hash)
			VALUES ($1, $2::uuid, COALESCE(NULLIF($3, ''), $1), $4,
			        COALESCE($5::text[], ARRAY['openid','profile','email','offline_access']),
			        COALESCE($6::boolean, true), NULLIF($7,''), NULLIF($8,''), $9,
			        CASE WHEN $4 = 'confidential' THEN 'unset' ELSE NULL END)
			ON CONFLICT (client_id) DO UPDATE SET
				display_name = COALESCE(NULLIF($3, ''), core.clients.display_name),
				scopes = COALESCE($5::text[], core.clients.scopes),
				enabled = COALESCE($6::boolean, core.clients.enabled),
				initiate_login_uri = EXCLUDED.initiate_login_uri,
				logo_uri = EXCLUDED.logo_uri,
				portal_hidden = EXCLUDED.portal_hidden,
				updated_at = now()
			 WHERE core.clients.org_id = EXCLUDED.org_id
			RETURNING client_id`,
			cl.ClientID, orgID, cl.Name, kind, scopes,
			cl.Enabled, cl.LaunchURL, cl.LogoURL, cl.PortalHidden).Scan(&written)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("client %q is registered by another organisation; a client_id "+
				"is unique across the deployment, so it cannot be declared here", cl.ClientID)
		}
		if err != nil {
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
		// Through the one writer the CLI and the Admin API use, so a grant means
		// the same thing whichever surface made it.
		if x := cl.TokenExchange; x != nil {
			if _, err := store.SetClientExchange(ctx, tx, cl.ClientID, x.Enabled, x.Audiences); err != nil {
				return fmt.Errorf("client %q token_exchange: %w", cl.ClientID, err)
			}
		}
		if err := store.SetClientLogout(ctx, tx, cl.ClientID, store.ClientLogout{
			PostLogoutRedirectURIs: cl.PostLogoutRedirectURIs, FrontchannelURI: cl.FrontchannelLogoutURI,
			FrontchannelSessionRequired: cl.FrontchannelSessionRequired,
		}); err != nil {
			return fmt.Errorf("client %q logout: %w", cl.ClientID, err)
		}
		if err := store.SetClientSettings(ctx, tx, cl.ClientID, cl.settings()); err != nil {
			return fmt.Errorf("client %q: %w", cl.ClientID, err)
		}
	}

	for _, sp := range f.SAMLProviders {
		c, ok := planned("saml_provider", sp.EntityID)
		if !ok || c.Action == "delete" {
			continue
		}
		// As for clients: an omitted name, name-ID format or `enabled` keeps its
		// value on an update and takes the default only on create.
		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO core.saml_providers (org_id, entity_id, display_name,
			                                 name_id_format, enabled)
			VALUES ($1::uuid, $2, COALESCE(NULLIF($3, ''), $2),
			        COALESCE(NULLIF($4, ''), 'persistent'), COALESCE($5::boolean, true))
			ON CONFLICT (org_id, entity_id) DO UPDATE SET
				display_name = COALESCE(NULLIF($3, ''), core.saml_providers.display_name),
				name_id_format = COALESCE(NULLIF($4, ''), core.saml_providers.name_id_format),
				enabled = COALESCE($5::boolean, core.saml_providers.enabled),
				updated_at = now()
			RETURNING id::text`,
			orgID, sp.EntityID, sp.Name, sp.NameID, sp.Enabled).Scan(&id); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.ConstraintName == "saml_providers_entity_id_key" {
				return fmt.Errorf("saml provider %q is registered by another organisation; "+
					"entity IDs are unique across the deployment, because an AuthnRequest "+
					"names only its entity ID and the SSO endpoint names no organisation", sp.EntityID)
			}
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

	for _, h := range f.ProxyHosts {
		c, ok := planned("proxy_host", h.Host)
		if !ok || c.Action == "delete" {
			continue
		}
		enabled := h.Enabled == nil || *h.Enabled
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.proxy_hosts (org_id, host, enabled) VALUES ($1::uuid, $2, $3)
			ON CONFLICT (org_id, host) DO UPDATE SET enabled = EXCLUDED.enabled`,
			orgID, h.Host, enabled); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.ConstraintName == "proxy_hosts_host_key" {
				return fmt.Errorf("proxy host %q is registered by another organisation; a "+
					"protected host is unique across the deployment, because verify admits "+
					"whoever's organisation registered it", h.Host)
			}
			return fmt.Errorf("proxy host %q: %w", h.Host, err)
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
		case "proxy_host":
			_, err = tx.Exec(ctx,
				`DELETE FROM core.proxy_hosts WHERE org_id = $1::uuid AND host = $2`, orgID, c.Name)
		}
		if err != nil {
			return fmt.Errorf("deleting %s %q: %w", c.Kind, c.Name, err)
		}
	}

	return recordApply(ctx, tx, orgID, plan)
}

// recordApply leaves the two records every other write path leaves.
//
// # What was missing
//
// This path wrote clients, groups, SAML providers and RADIUS clients straight
// into the transaction and committed. It bumped no configuration version and
// wrote no audit event, so two of the three invariants this project states as
// non-negotiable did not hold on its own declarative path:
//
//   - ADR-008 requires every configuration mutation to bump `core.config_version`
//     in the SAME transaction as the write. Without it, a caller holding an
//     If-Match precondition from a read taken before an apply is told nothing
//     changed, and overwrites it. That is precisely the lost update the
//     precondition exists to refuse, reachable from the product's own CLI.
//   - Every mutation through the admin API writes an audit event. A change made
//     with `signari apply` left no record at all, so "who changed this client"
//     had no answer for the path most likely to be used in production.
//
// Both go in this function rather than at the CLI call site, because a second
// caller of Apply would otherwise inherit neither.
func recordApply(ctx context.Context, tx pgx.Tx, orgID string, plan *Plan) error {
	// One event per change, matching the granularity the admin API produces for
	// the same edits made individually. A single "config applied" row would make
	// the trail for fifty changes indistinguishable from the trail for one.
	for _, c := range plan.Changes {
		if err := audit.Write(ctx, tx, audit.Event{
			Type:  "config.applied",
			OrgID: orgID,
			Detail: map[string]any{
				"kind":   c.Kind,
				"name":   c.Name,
				"action": c.Action,
				"source": "config-as-code",
			},
		}); err != nil {
			return fmt.Errorf("auditing %s %q: %w", c.Kind, c.Name, err)
		}
	}

	// The bump, in the same transaction as the writes, exactly as
	// internal/adminapi/server.go does it. A write that commits without this is
	// durable and invisible.
	if _, err := tx.Exec(ctx, `
		UPDATE core.config_version
		SET version = version + 1, bumped_at = now()
		WHERE id = true`); err != nil {
		return fmt.Errorf("bumping the configuration version: %w", err)
	}
	return nil
}
