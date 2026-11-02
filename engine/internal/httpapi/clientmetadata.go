package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/cimd"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
)

// Client ID Metadata Documents: a client_id that is an https URL, and the document there
// standing in for a registration. The fetch is the row's whole risk, so it comes last: a
// URL no operator's rule covers is never fetched, and an unknown client stays one.
//
// What a document said is kept on the client's own row until it expires, so there is no
// cache to declare, and nothing is kept when a fetch fails (§5.2's "MUST NOT cache error
// responses"). A client past its expiry is refused at the authorization endpoint unless
// this has just brought it up to date.

// clientMetadataFetchesPerAddress bounds the outbound requests one address can cause.
const clientMetadataFetchesPerAddress = 30

// clientMetadataNameLimit is as much of a stranger's chosen name as goes on a consent page.
const clientMetadataNameLimit = 80

// admitMetadataClient registers or refreshes the client a request names, if it is one
// that has to be and can be. It answers nothing: the caller looks the client up next, and
// either it is there or it is the unknown client it was.
func (s *Server) admitMetadataClient(r *http.Request, clientID string) {
	ctx := r.Context()
	if !strings.HasPrefix(clientID, "https://") {
		return
	}
	c, err := clients.Lookup(ctx, s.db, clientID)
	switch {
	case err == nil && (c.FederationExpiry == nil || time.Now().Before(*c.FederationExpiry)):
		return
	case err != nil && !errors.Is(err, clients.ErrNotFound):
		s.log.ErrorContext(ctx, "looking for a client by its URL", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	rules, err := store.ClientMetadataRules(ctx, s.db, s.instanceID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the client metadata rules", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	rule, covered := store.MatchClientMetadataRule(rules, clientID)
	if !covered {
		return
	}
	rate, err := store.AllowRate(ctx, s.db, "client-metadata:"+clientIP(r), clientMetadataFetchesPerAddress, time.Minute)
	if err != nil || !rate.Allowed {
		s.log.InfoContext(ctx, "a client metadata fetch was paced", "err", err, "correlation_id", correlationID(ctx))
		return
	}
	if err := s.registerMetadataClient(ctx, clientID, rule); err != nil {
		s.log.InfoContext(ctx, "a client was not admitted from its document", "client_id", clientID, "err", err,
			"correlation_id", correlationID(ctx))
	}
}

func (s *Server) registerMetadataClient(ctx context.Context, clientID string, rule store.ClientMetadataRule) error {
	outbound := s.outboundClient(cimd.FetchTimeout)
	doc, keep, err := cimd.Fetch(ctx, outbound, clientID)
	if err != nil {
		return err
	}
	scopes, err := metadataClientScopes(doc.Scope, rule.Scopes)
	if err != nil {
		return err
	}
	keys, err := doc.Keys(ctx, outbound)
	if err != nil {
		return err
	}
	client := store.MetadataClient{ClientID: clientID, OrgID: rule.OrgID, Name: metadataClientName(doc.Name, clientID),
		Prefix: rule.URLPrefix, Public: doc.AuthMethod == cimd.AuthNone, RedirectURIs: doc.RedirectURIs, Scopes: scopes,
		GrantTypes: doc.GrantTypes, JWKS: keys, Expiry: time.Now().Add(keep)}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.RegisterMetadataClient(ctx, tx, client); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "client_metadata.client_registered", OrgID: rule.OrgID,
		ClientID: clientID, Detail: map[string]any{"url_prefix": rule.URLPrefix}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// metadataClientScopes is what a client gets: what it asks for of what the rule allows,
// and with no rule's list, a sign-in and nothing more.
func metadataClientScopes(asked string, allowed []string) ([]string, error) {
	if len(allowed) == 0 {
		allowed = []string{"openid"}
	}
	wanted := strings.Fields(asked)
	if len(wanted) == 0 {
		return allowed, nil
	}
	given := slices.DeleteFunc(slices.Clone(wanted), func(scope string) bool { return !slices.Contains(allowed, scope) })
	if len(given) == 0 {
		return nil, fmt.Errorf("none of the scopes %q is allowed", asked)
	}
	return given, nil
}

// metadataClientName is §8.5's "SHOULD display the hostname of the client_id": the name
// is anybody's to choose, and the host is the part that cannot be faked, so it goes
// wherever the name does.
func metadataClientName(name, clientID string) string {
	host := clientID
	if u, err := url.Parse(clientID); err == nil {
		host = u.Host
	}
	name = strings.Join(strings.Fields(strings.ToValidUTF8(name, "")), " ")
	if runes := []rune(name); len(runes) > clientMetadataNameLimit {
		name = string(runes[:clientMetadataNameLimit])
	}
	if name == "" {
		return host
	}
	return name + " (" + host + ")"
}
