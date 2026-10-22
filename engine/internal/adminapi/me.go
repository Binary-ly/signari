package adminapi

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// GET /admin/me (6.06): who the caller is, as this API decided on this
// request. The console asks it on each of its own requests: a person signed in
// through Signari whose session ended, whose role was taken away or whose
// organisation was suspended is told so here as everywhere, and the console
// signs them out. Any authenticated caller may ask about itself, so it has no
// scope of its own; it tells a caller nothing it could not learn by trying.

type meView struct {
	// Kind is person, application, token or break_glass.
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OrgID  *string  `json:"org_id"`
	Scopes []string `json:"scopes"`
	// Delegated is each scope a role delegated over groups narrows, with the
	// groups whose members it reaches.
	Delegated map[string][]string `json:"delegated,omitempty"`
	ExpiresAt *string             `json:"expires_at"`
	User      *meUser             `json:"user,omitempty"`
	ClientID  string              `json:"client_id,omitempty"`
}

type meUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, ok := principalFrom(ctx)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	v := meView{Name: p.Name, Scopes: append([]string{}, p.Scopes...), Delegated: p.UserGroups}
	sort.Strings(v.Scopes)
	switch {
	case p.BreakGlass:
		v.Kind = "break_glass"
	case p.UserID != "":
		v.Kind = "person"
	case strings.HasPrefix(p.Name, "client:") && p.TokenID == "":
		v.Kind, v.ClientID = "application", strings.TrimPrefix(p.Name, "client:")
	default:
		v.Kind = "token"
	}
	if p.OrgID != "" {
		org := p.OrgID
		v.OrgID = &org
	}
	if p.ExpiresAt != nil {
		at := p.ExpiresAt.UTC().Format(time.RFC3339)
		v.ExpiresAt = &at
	}
	if p.UserID != "" {
		u := meUser{ID: p.UserID}
		err := s.db.QueryRow(ctx, `SELECT COALESCE(email, ''), COALESCE(display_name, '')
			FROM core.users WHERE id = $1::uuid`, p.UserID).Scan(&u.Email, &u.DisplayName)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.log.Error("reading the caller's own account", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		v.User = &u
	}
	s.writeList(w, r, v)
}
