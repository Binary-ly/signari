package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// UMA resource registration (11.12, Federated Authorization §3): the protection API
// at which a resource server puts its resources under this server's protection.
//
//	POST   /uma2/resource_set        create  201 + Location, {"_id"}
//	GET    /uma2/resource_set        list    200 ["_id", ...]
//	GET    /uma2/resource_set/{id}   read    200 description + _id
//	PUT    /uma2/resource_set/{id}   update  200 {"_id"}
//	DELETE /uma2/resource_set/{id}   delete  204
//
// Each needs a protection API access token, a PAT: an access token with the scope
// uma_protection issued to the resource server (specs/uma-fedauthz.txt:118-122). Who
// granted it is the resource owner: a person who signed in and agreed, or, by the
// client credentials grant, the organisation. A resource server sees and changes only
// what it registered for that owner, and anything else is a 404, as a resource that
// is not there is (:261).

const (
	umaResourcePath = "/uma2/resource_set"
	// umaProtectionScope is the PAT's scope (specs/uma-fedauthz.txt:118).
	umaProtectionScope = "uma_protection"
	// umaResourcePage is where a person shares what they own: the
	// user_access_policy_uri a registration answers (:258).
	umaResourcePage = "/account/resources"
)

// protectionCaller is who a PAT stands for: the resource server it was issued to,
// and the person it is about, "" when the organisation granted it.
type protectionCaller struct {
	client *clients.Client
	owner  string
}

// protectionToken admits a PAT and answers for itself when it will not. Every
// question an access token is asked here is acceptedToken's; this adds that the
// holder is a resource server, and finds the owner.
func (s *Server) protectionToken(w http.ResponseWriter, r *http.Request, where string) (protectionCaller, bool) {
	ctx := r.Context()
	claims, ok := s.acceptedToken(w, r, umaProtectionScope, where)
	if !ok {
		return protectionCaller{}, false
	}
	c, err := s.lookupClient(ctx, claims.ClientID)
	if err != nil || c == nil || c.Type != "confidential" {
		// A resource server holds client credentials (:139); a public client is a
		// browser or an app, and a PAT in one is nobody's resource server.
		writeUMAError(w, &uma.Error{Code: "invalid_client", Status: http.StatusForbidden,
			Description: "the protection API token was not issued to a confidential client"})
		return protectionCaller{}, false
	}
	return s.protectionOwner(ctx, w, c, claims)
}

// protectionOwner is who granted the PAT: the organisation by the client
// credentials grant, whose token is about the client itself, or a person of the
// client's organisation. Somebody deactivated since is refused before this, by
// acceptedToken's standing, which reads them on every request.
func (s *Server) protectionOwner(ctx context.Context, w http.ResponseWriter, c *clients.Client,
	claims *tokens.AccessTokenClaims) (protectionCaller, bool) {
	if claims.Subject == c.ClientID {
		return protectionCaller{client: c}, true
	}
	var member bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users
		WHERE id = $1::uuid AND org_id = $2::uuid)`, store.ExactUUIDOrNil(claims.Subject), c.OrgID).Scan(&member); err != nil {
		s.log.ErrorContext(ctx, "reading a resource owner", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return protectionCaller{}, false
	}
	if !member {
		writeUMAError(w, &uma.Error{Code: "invalid_token", Status: http.StatusUnauthorized,
			Description: "the protection API token does not stand for a person of the resource server's organisation"})
		return protectionCaller{}, false
	}
	return protectionCaller{client: c, owner: claims.Subject}, true
}

// fitsTheModel refuses a description the organisation's authorization model could
// not decide about: a type it has not got, or a scope that is none of its actions,
// which every request would be refused for and nothing would say why.
func (s *Server) fitsTheModel(ctx context.Context, orgID string, d uma.ResourceDescription) *uma.Error {
	m, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil {
		return &uma.Error{Code: "server_error", Status: http.StatusInternalServerError, Description: "unavailable"}
	}
	if m == nil {
		return uma.InvalidRequest("this organisation has no authorization model, so nothing registered here " +
			"could be decided about; an administrator sets one with `signari authz set-model`")
	}
	t, ok := m.Types[d.Type]
	if !ok {
		return uma.InvalidRequest(fmt.Sprintf("type %q is not a type of this organisation's authorization model", d.Type))
	}
	for _, sc := range d.ResourceScopes {
		if _, ok := t.Permissions[sc]; !ok {
			return uma.InvalidRequest(fmt.Sprintf("scope %q is not an action the model defines for %q, so no "+
				"permission on it could ever be given", sc, d.Type))
		}
	}
	return nil
}

func (s *Server) readResourceDescription(w http.ResponseWriter, r *http.Request) (uma.ResourceDescription, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeUMAError(w, uma.InvalidRequest("the request body could not be read"))
		return uma.ResourceDescription{}, false
	}
	d, uerr := uma.ParseResourceDescription(body)
	if uerr != nil {
		writeUMAError(w, uerr)
		return uma.ResourceDescription{}, false
	}
	return d, true
}

func (s *Server) umaResourceURL(id string) string {
	return strings.TrimRight(s.cfg.Issuer, "/") + umaResourcePath + "/" + id
}

// handleUMAResources answers the collection: create and list.
func (s *Server) handleUMAResources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodPost:
		s.createUMAResource(w, r)
	case http.MethodGet:
		s.listUMAResources(w, r)
	default:
		unsupportedUMAMethod(w, "GET, POST")
	}
}

// handleUMAResource answers one: read, update, delete.
func (s *Server) handleUMAResource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
		s.readUMAResource(w, r)
	case http.MethodPut:
		s.updateUMAResource(w, r)
	case http.MethodDelete:
		s.deleteUMAResource(w, r)
	default:
		unsupportedUMAMethod(w, "GET, PUT, DELETE")
	}
}

// unsupportedUMAMethod is §3.2's 405 (specs/uma-fedauthz.txt:262).
func unsupportedUMAMethod(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeUMAError(w, &uma.Error{Code: "unsupported_method_type", Status: http.StatusMethodNotAllowed,
		Description: "the resource registration API takes " + allow + " here"})
}

func writeUMANotFound(w http.ResponseWriter) {
	writeUMAError(w, &uma.Error{Code: "not_found", Status: http.StatusNotFound,
		Description: "no resource of that id is registered by this resource server for this owner"})
}

func (s *Server) createUMAResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	caller, ok := s.protectionToken(w, r, "uma resource registration")
	if !ok {
		return
	}
	d, ok := s.readResourceDescription(w, r)
	if !ok {
		return
	}
	if uerr := s.fitsTheModel(ctx, caller.client.OrgID, d); uerr != nil {
		writeUMAError(w, uerr)
		return
	}
	var id string
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var err error
		if id, err = store.CreateUMAResource(ctx, tx, store.UMAResource{OrgID: caller.client.OrgID,
			ClientID: caller.client.ClientID, OwnerID: caller.owner, Type: d.Type, Scopes: d.ResourceScopes,
			Name: d.Name, Description: d.Description, IconURI: d.IconURI}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "uma.resource_registered", OrgID: caller.client.OrgID,
			SubjectID: caller.owner, ClientID: caller.client.ClientID, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"resource_id": id, "type": d.Type, "scopes": d.ResourceScopes}})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "registering a UMA resource", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	body := map[string]any{"_id": id}
	if caller.owner != "" {
		// Where the person this belongs to decides who may reach it (§3.2).
		body["user_access_policy_uri"] = strings.TrimRight(s.cfg.Issuer, "/") + umaResourcePage + "#" + id
	}
	w.Header().Set("Location", s.umaResourceURL(id))
	writeJSON(w, http.StatusCreated, body)
}

func (s *Server) listUMAResources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	caller, ok := s.protectionToken(w, r, "uma resource registration")
	if !ok {
		return
	}
	ids, err := store.ListUMAResources(ctx, s.db, caller.client.ClientID, caller.owner)
	if err != nil {
		s.log.ErrorContext(ctx, "listing UMA resources", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	// §3.2.5: "a JSON array of _id string values".
	writeJSON(w, http.StatusOK, ids)
}

func (s *Server) readUMAResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	caller, ok := s.protectionToken(w, r, "uma resource registration")
	if !ok {
		return
	}
	res, err := store.UMAResourceOf(ctx, s.db, r.PathValue("id"), caller.client.ClientID, caller.owner)
	if errors.Is(err, store.ErrUMAResourceUnknown) {
		writeUMANotFound(w)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "reading a UMA resource", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	body := map[string]any{"_id": res.ID, "resource_scopes": res.Scopes, "type": res.Type}
	for k, v := range map[string]string{"name": res.Name, "description": res.Description, "icon_uri": res.IconURI} {
		if v != "" {
			body[k] = v
		}
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) updateUMAResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	caller, ok := s.protectionToken(w, r, "uma resource registration")
	if !ok {
		return
	}
	id := r.PathValue("id")
	held, err := store.UMAResourceOf(ctx, s.db, id, caller.client.ClientID, caller.owner)
	if errors.Is(err, store.ErrUMAResourceUnknown) {
		writeUMANotFound(w)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "reading a UMA resource", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	d, ok := s.readResourceDescription(w, r)
	if !ok {
		return
	}
	if d.Type != held.Type {
		// What has been shared is relations on an object of the registered type, and
		// a new type would leave every one of them on an object that is not there.
		writeUMAError(w, uma.InvalidRequest(fmt.Sprintf("a registered resource keeps its type, %q: what it has "+
			"been shared as is relations on an object of that type; register a new resource instead", held.Type)))
		return
	}
	if uerr := s.fitsTheModel(ctx, caller.client.OrgID, d); uerr != nil {
		writeUMAError(w, uerr)
		return
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := store.ReplaceUMAResource(ctx, tx, store.UMAResource{ID: id, ClientID: caller.client.ClientID,
			OwnerID: caller.owner, Scopes: d.ResourceScopes, Name: d.Name, Description: d.Description,
			IconURI: d.IconURI}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "uma.resource_updated", OrgID: caller.client.OrgID,
			SubjectID: caller.owner, ClientID: caller.client.ClientID, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"resource_id": id, "scopes": d.ResourceScopes,
				"scopes_withdrawn": withdrawnScopes(held.Scopes, d.ResourceScopes)}})
	})
	if errors.Is(err, store.ErrUMAResourceUnknown) {
		writeUMANotFound(w)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "updating a UMA resource", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"_id": id})
}

// withdrawnScopes is what an update took away, for the record.
func withdrawnScopes(was, now []string) []string {
	out := []string{}
	for _, s := range was {
		if !slices.Contains(now, s) {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) deleteUMAResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	caller, ok := s.protectionToken(w, r, "uma resource registration")
	if !ok {
		return
	}
	id := r.PathValue("id")
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := store.DeleteUMAResource(ctx, tx, id, caller.client.ClientID, caller.owner); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "uma.resource_deregistered", OrgID: caller.client.OrgID,
			SubjectID: caller.owner, ClientID: caller.client.ClientID, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"resource_id": id}})
	})
	if errors.Is(err, store.ErrUMAResourceUnknown) {
		writeUMANotFound(w)
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "deregistering a UMA resource", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolveRegistered gives each permission that names no type the type of the
// resource it names, which must be one this resource server registered, for the
// owner the request speaks for, with each scope one it registered (Federated
// Authorization §4.1, §4.3). A request names one owner's resources (:386): with a PAT
// the owner it stands for, and with the client's own credentials whichever owner
// the first registered resource has, "" being the organisation.
func (s *Server) resolveRegistered(ctx context.Context, perms []uma.Permission, clientID, patOwner string,
	pat bool) *uma.Error {
	owner, decided := patOwner, pat
	for i := range perms {
		p := &perms[i]
		if p.ResourceType != "" {
			continue
		}
		res, err := store.RegisteredUMAResource(ctx, s.db, p.ResourceID)
		switch {
		case errors.Is(err, store.ErrUMAResourceUnknown), err == nil && res.ClientID != clientID:
			// Another resource server's is not found, as one that never was.
			return uma.InvalidResourceID(fmt.Sprintf("resource %q is not registered by this resource server", p.ResourceID))
		case err != nil:
			return &uma.Error{Code: "server_error", Status: http.StatusInternalServerError, Description: "unavailable"}
		case decided && res.OwnerID != owner:
			return uma.InvalidResourceID(fmt.Sprintf("resource %q belongs to another resource owner: one request "+
				"names one owner's resources", p.ResourceID))
		}
		for _, sc := range p.ResourceScopes {
			if !slices.Contains(res.Scopes, sc) {
				return uma.InvalidScope(fmt.Sprintf("scope %q was not registered for resource %q", sc, p.ResourceID))
			}
		}
		owner, decided = res.OwnerID, true
		p.ResourceType = res.Type
	}
	return nil
}
