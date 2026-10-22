package httpapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// # Several instances in one process (6.12)
//
// An instance is an issuer: its own URL, its own signing keys, its own
// organisations. One process serves several by building one Server for each,
// with that instance's issuer, keys and id, and choosing between them by the
// Host a request names (HostRouter). A token one signs is refused by the
// other, because it verifies only its own keys and its own issuer; that much
// came free.
//
// What did not is everything a server finds without a token: a client by its
// id, a session by its cookie, an account by its name, a provider by its slug,
// a link or an invitation by its hash. Each is asked whether it belongs to the
// server's instance (serves, servesOrg, store.InInstance) where it is found,
// and one that does not is answered as one that does not exist.

// lookupRecovery is store.LookupRecovery among this instance's requests: a
// link another issuer sent is not one this one honours.
func (s *Server) lookupRecovery(ctx context.Context, tx pgx.Tx, hash []byte) (*store.RecoveryRequest, error) {
	req, err := store.LookupRecovery(ctx, tx, hash, time.Now())
	if req != nil && !s.ownedBy(ctx, tx, req.OrgID, "recovery link") {
		return nil, store.ErrRecoveryNotFound
	}
	return req, err
}

// peekInvitation is store.PeekInvitation among this instance's invitations,
// for every read of one and before the claim that spends it.
func (s *Server) peekInvitation(ctx context.Context, token string) (*store.Invitation, error) {
	inv, err := store.PeekInvitation(ctx, s.db, token)
	if err != nil {
		return nil, err
	}
	if !s.ownedBy(ctx, s.db, inv.OrgID, "invitation") {
		return nil, store.ErrInvitationNotUsable
	}
	return inv, nil
}

// findPasskeyLink is store.FindPasskeyLink among this instance's links. The
// ceremony it begins is signed with this server's keys, so the rest of it
// cannot be finished at another.
func (s *Server) findPasskeyLink(ctx context.Context, token string) (store.PasskeyLink, error) {
	link, err := store.FindPasskeyLink(ctx, s.db, token)
	if err == nil && !s.ownedBy(ctx, s.db, link.OrgID, "passkey link") {
		return store.PasskeyLink{}, store.ErrPasskeyLinkInvalid
	}
	return link, err
}

// loadIdentityProvider is store.LoadIdentityProvider among this instance's
// providers. Slugs are unique across the deployment, so without this a
// provider of another instance began and finished its sign-in here.
func (s *Server) loadIdentityProvider(ctx context.Context, slug string) (*federation.Config, error) {
	p, err := store.LoadIdentityProvider(ctx, s.db, s.cfg.Root, slug)
	if err == nil && !s.ownedBy(ctx, s.db, p.OrgID, "identity provider") {
		return nil, store.ErrProviderUnknown
	}
	return p, err
}

// loadSAMLSource is store.LoadSAMLSource among this instance's sources.
func (s *Server) loadSAMLSource(ctx context.Context, slug string) (*store.SAMLSource, error) {
	src, err := store.LoadSAMLSource(ctx, s.db, slug, s.cfg.Issuer)
	if err == nil && !s.ownedBy(ctx, s.db, src.OrgID, "saml source") {
		return nil, store.ErrProviderUnknown
	}
	return src, err
}

// loadSAMLProvider is store.LoadSAMLProvider among this instance's service
// providers. Entity ids are unique across the deployment, so another
// instance's was found by its id here, its metadata shown and its sessions
// ended.
func (s *Server) loadSAMLProvider(ctx context.Context, entityID string) (*saml.Provider, error) {
	p, err := store.LoadSAMLProvider(ctx, s.db, entityID)
	if err == nil && !s.ownedBy(ctx, s.db, p.OrgID, "saml service provider") {
		return nil, store.ErrSAMLProviderUnknown
	}
	return p, err
}

// serves reports whether an object of instanceID is this server's. A Server
// that was not told its instance -- a test's -- serves every one.
func (s *Server) serves(instanceID string) bool {
	return s.instanceID == "" || instanceID == s.instanceID
}

// ownedBy reports whether an organisation belongs to this server's instance,
// read through q, the transaction a caller holds or the pool: false for one of
// another instance and for one whose instance could not be read, logged.
func (s *Server) ownedBy(ctx context.Context, q dbReader, orgID, what string) bool {
	if s.instanceID == "" {
		return true
	}
	ok, err := store.OrgInInstance(ctx, q, orgID, s.instanceID)
	if err != nil {
		s.log.Error("reading which instance an organisation belongs to", "what", what,
			"org_id", orgID, "err", err)
		return false
	}
	if !ok {
		s.log.Info("an object of another instance was refused", "what", what, "org_id", orgID,
			"correlation_id", correlationID(ctx))
	}
	return ok
}

// HostRouter sends each request to the server whose issuer names the host it
// was made to, and any other host to the first server, the one a deployment
// with a single instance has always served whatever it was called.
//
// By host alone, so issuers must differ in their host: two on one host would
// differ only in a path, and the protocol paths here are fixed at the root.
// Refused at construction, as two servers with one issuer are.
func HostRouter(servers []*Server, handlers []http.Handler) (http.Handler, error) {
	if len(servers) == 0 || len(servers) != len(handlers) {
		return nil, fmt.Errorf("a host router needs one handler per server")
	}
	if len(servers) == 1 {
		return handlers[0], nil
	}
	byHost := map[string]http.Handler{}
	for i, s := range servers {
		host, err := issuerHost(s.cfg.Issuer)
		if err != nil {
			return nil, err
		}
		if _, dup := byHost[host]; dup {
			return nil, fmt.Errorf("two instances are served on %s: an instance is chosen by "+
				"the host a request names, so each needs a host of its own", host)
		}
		byHost[host] = handlers[i]
	}
	primary := handlers[0]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := byHost[requestHost(r.Host)]; ok {
			h.ServeHTTP(w, r)
			return
		}
		primary.ServeHTTP(w, r)
	}), nil
}

// issuerHost is the host an issuer is reached at, in the form requestHost
// reduces a Host header to.
func issuerHost(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("issuer %q has no host", issuer)
	}
	return requestHost(u.Host), nil
}

// requestHost reduces a host to one spelling: lower-case, no trailing dot, and
// no port 80 or 443, which a client may or may not write and a terminating
// proxy may or may not pass on.
func requestHost(host string) string {
	host = strings.ToLower(host)
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		return strings.TrimSuffix(host, ".")
	}
	name = strings.TrimSuffix(name, ".")
	if port == "80" || port == "443" {
		if strings.Contains(name, ":") {
			return "[" + name + "]"
		}
		return name
	}
	return net.JoinHostPort(name, port)
}
