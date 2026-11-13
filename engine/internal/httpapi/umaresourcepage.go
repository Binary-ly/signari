package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// /account/resources: user-managed access (11.12). A person sees what resource servers
// registered as theirs, with a PAT they granted, and shares each with somebody by
// address, as one of the relations the organisation's authorization model gives its
// type, or stops sharing it. A share is a relation on the resource's object, so the
// decision a requesting party gets at the token endpoint is the model's, as for
// anything else; the model's author decides what each relation lets a person do, and
// the owner decides who holds one. It is where a registration's user_access_policy_uri
// points.

// maxShareAddress is RFC 5321 §4.5.3.1.3's path limit, 256 octets less the brackets.
const maxShareAddress = 254

type resourceShare struct {
	Who, Relation string
}

type ownedResource struct {
	ID, Name, Description, Server string
	Scopes                        []string
	Shares                        []resourceShare
	// Relations are what it can be shared as: its type's relations in the model.
	Relations []string
}

// resourceMessages are what the page can say back after a change, each spelled out
// in the page, so that no address bar can put words on it.
var resourceMessages = map[string]bool{"shared": true, "unshared": true, "refused": true}

func (s *Server) handleResourcesPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin(umaResourcePage), http.StatusSeeOther)
		return
	}
	owned, err := s.ownedResources(ctx, orgID, userID)
	if err != nil {
		s.log.ErrorContext(ctx, "listing a person's registered resources", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.ErrorContext(ctx, "issuing a CSRF token", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	message := r.URL.Query().Get("m")
	if !resourceMessages[message] {
		message = ""
	}
	htmlPageHeaders(w)
	s.renderPage(w, r, "resources", map[string]any{
		"Resources": owned,
		"CSRF":      csrf,
		"Message":   message,
	})
}

// ownedResources is what the person owns, each with its shares and what it can be
// shared as.
func (s *Server) ownedResources(ctx context.Context, orgID, userID string) ([]ownedResource, error) {
	held, err := store.UMAResourcesOwnedBy(ctx, s.db, userID)
	if err != nil {
		return nil, err
	}
	m, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]ownedResource, 0, len(held))
	for _, h := range held {
		o := ownedResource{ID: h.ID, Name: h.Name, Description: h.Description, Scopes: h.Scopes, Server: h.ClientID}
		if o.Name == "" {
			o.Name = h.ID
		}
		if c, err := s.lookupClient(ctx, h.ClientID); err == nil && c != nil && c.DisplayName != "" {
			o.Server = c.DisplayName
		}
		if m != nil {
			for rel := range m.Types[h.Type].Relations {
				o.Relations = append(o.Relations, rel)
			}
			sort.Strings(o.Relations)
		}
		rows, _, err := store.ListRelations(ctx, s.db, orgID, "", "", h.Type, h.ID, 200)
		if err != nil {
			return nil, err
		}
		// The shares a person made, with people. A relation an administrator gave a
		// group or a client on it is theirs to manage, and not offered for removal here.
		for _, rr := range rows {
			if who, ok := strings.CutPrefix(rr.Subject, "user:"); ok {
				o.Shares = append(o.Shares, resourceShare{Who: who, Relation: rr.Relation})
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// handleResourceShare shares one of the person's resources with somebody, or stops.
func (s *Server) handleResourceShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		// Somebody else's page sharing this person's resource with whoever it likes
		// is the attack the token is for.
		http.Error(w, "that request could not be verified", http.StatusBadRequest)
		return
	}
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin(umaResourcePage), http.StatusSeeOther)
		return
	}
	if s.credentialChangeRefused(w, r, sid, umaResourcePage, false) {
		return
	}
	share := r.URL.Path == umaResourcePage+"/share"
	id := strings.TrimSpace(r.PostForm.Get("resource"))
	relation := strings.TrimSpace(r.PostForm.Get("relation"))
	who := strings.ToLower(strings.TrimSpace(r.PostForm.Get("email")))
	back := func(m string) {
		http.Redirect(w, r, umaResourcePage+"?m="+m+"#"+id, http.StatusSeeOther)
	}

	// Theirs, and only theirs: the id arrives from a form field.
	res, err := store.RegisteredUMAResource(ctx, s.db, id)
	if errors.Is(err, store.ErrUMAResourceUnknown) || (err == nil && res.OwnerID != userID) {
		back("refused")
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "reading a resource to share", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	m, err := store.LoadModel(ctx, s.db, orgID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the authorization model", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	isRelation := false
	if m != nil {
		_, isRelation = m.Types[res.Type].Relations[relation]
	}
	if !isRelation {
		// Only what the model lets this type be shared as: anything else would be a
		// relation no permission reads, and a share that does nothing.
		back("refused")
		return
	}
	if addr, perr := mail.ParseAddress(who); perr != nil || addr.Address != who || len(who) > maxShareAddress {
		back("refused")
		return
	}
	rel := store.Relation{SubjectType: "user", SubjectID: who, Relation: relation, ObjectType: res.Type, ObjectID: res.ID}
	kind := "uma.resource_unshared"
	if share {
		kind = "uma.resource_shared"
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if share {
			if err := store.GrantRelation(ctx, tx, orgID, rel, userID); err != nil {
				return err
			}
		} else if _, err := store.RevokeRelation(ctx, tx, orgID, rel); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: kind, OrgID: orgID, SubjectID: userID, ClientID: res.ClientID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"resource_id": res.ID, "relation": relation, "with": who}})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "sharing a resource", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	if share {
		back("shared")
	} else {
		back("unshared")
	}
}
