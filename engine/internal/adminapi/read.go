package adminapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Read endpoints.
//
// # Why these are part of the conditional-write work rather than separate
//
// A precondition is only usable if a caller can read the thing it is about to
// change. Before this the only readable endpoint was `/admin/config-version`, so
// an integration wanting to edit a client had to obtain it from somewhere else --
// in practice a direct database connection, which ADR-004 exists to prevent, or
// the CLI on the box. `If-Match` with nothing to GET first is a protocol with a
// missing half.
//
// # Pagination is mandatory, not optional
//
// Every list here is bounded and cursor-paged, and there is no way to ask for all
// of them. An unbounded admin list is a memory amplifier: one request against a
// deployment with a million users allocates a million rows in the server and
// again in the client. Keyset pagination on `(created_at, id)` rather than
// OFFSET, because OFFSET re-scans everything it skips and drifts when rows are
// inserted mid-page -- an operator paging through users during a provisioning run
// would see some twice and miss others.
//
// # Every list is organisation-scoped by the caller's token
//
// The same boundary the write paths enforce (`requireOrg`). A read that ignored
// it would let a token scoped to one tenant enumerate another's users, which is
// a worse leak than a misdirected write because it is silent.

// listLimits bound a page.
const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// pageParams reads and clamps the paging query.
func pageParams(r *http.Request) (limit int, cursor string) {
	limit = defaultPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	return limit, r.URL.Query().Get("cursor")
}

// clientSummary is what a list returns per client.
//
// Deliberately NOT the whole row. `client_secret_hash` must never leave this
// process -- it is a credential verifier, and an admin API that returns it turns
// read access into write access against every application. The columns here are
// the ones an operator console needs to render a list.
type clientSummary struct {
	ClientID    string `json:"client_id"`
	OrgID       string `json:"org_id"`
	DisplayName string `json:"display_name"`
	ClientType  string `json:"client_type"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, cursor := pageParams(r)

	// One row beyond the page, so "is there more" is answered without a second
	// query and without a COUNT over the whole table.
	rows, err := s.db.Query(ctx, `
		SELECT client_id, org_id::text, display_name, client_type, enabled,
		       to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM') AS created
		  FROM core.clients
		 WHERE ($1 = '' OR client_id > $1)
		   AND ($2::uuid IS NULL OR org_id = $2::uuid)
		   AND ($4::text[] IS NULL OR client_id = ANY($4::text[]))
		 ORDER BY client_id
		 LIMIT $3`,
		cursor, orgFilter(ctx), limit+1, clientFilter(ctx))
	if err != nil {
		s.log.Error("listing clients", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := make([]clientSummary, 0, limit)
	for rows.Next() {
		var c clientSummary
		if err := rows.Scan(&c.ClientID, &c.OrgID, &c.DisplayName, &c.ClientType,
			&c.Enabled, &c.CreatedAt); err != nil {
			s.log.Error("scanning a client row", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing clients", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ClientID
	}
	s.writeList(w, r, map[string]any{"clients": out, "next_cursor": next})
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")

	// Reads are narrowed too. A token restricted to one application must not be
	// able to enumerate another's configuration -- a read boundary that does not
	// match the write boundary is one an integrator will find and use.
	// Reads are narrowed too. A token restricted to one application must not be
	// able to enumerate another's configuration -- a read boundary that does not
	// match the write boundary is one an integrator will find and use.
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	// The whole configuration (6.03): every column but the two secret hashes,
	// with the redirect URIs sorted as the set they are, so a caller holding a
	// desired configuration can compare all of it with the server's. This
	// returned six fields, and the Terraform provider once reported a
	// redirect-URI change as applied while it sent nothing, for want of one.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.log.Error("reading a client", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := clientState(ctx, tx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	}
	var created string
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')
			FROM core.clients WHERE client_id = $1`, clientID).Scan(&created)
	}
	if err != nil {
		s.log.Error("reading a client", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	c["created_at"] = created
	// Read, so released before anything else takes a connection.
	_ = tx.Rollback(ctx)
	// The boundary applies to reads exactly as to writes. Answering 403 rather
	// than 404 matches the write paths: the record exists, this credential may
	// not see it, and pretending otherwise sends an operator hunting.
	orgID, _ := c["org_id"].(string)
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	s.writeList(w, r, c)
}

// userSummary is what a user read returns.
//
// No credential material of any kind: no password hash, no TOTP secret, no
// recovery codes. A read scope must not be a slower path to the same power a
// write scope has.
type userSummary struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, cursor := pageParams(r)
	// Filters (6.08), each in the WHERE clause beside the organisation, and
	// each served by an index (0189): ?email= exactly, ?q= a prefix of the
	// address or the user name, ?status= one of the statuses. Case does not
	// matter, as it does not at sign-in. A support desk paged through every
	// person to find one.
	q := r.URL.Query()
	email := strings.ToLower(strings.TrimSpace(q.Get("email")))
	prefix := strings.ToLower(strings.TrimSpace(q.Get("q")))
	status := q.Get("status")
	switch status {
	case "", "active", "deactivated", "locked", "pending":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status",
			"detail": "status is active, deactivated, locked or pending"})
		return
	}

	sql, args := userListQuery(cursor, orgFilter(ctx), limit+1, email, prefix, status, reachFilter(ctx, ScopeUsersRead))
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		s.log.Error("listing users", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := make([]userSummary, 0, limit)
	for rows.Next() {
		var u userSummary
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Username, &u.Status,
			&u.CreatedAt); err != nil {
			s.log.Error("scanning a user row", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing users", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	s.writeList(w, r, map[string]any{"users": out, "next_cursor": next})
}

// userListQuery is the user list's query with only the filters given, each its
// own condition. A condition that also holds when its parameter is empty reads
// the same and stops using the index once the prepared statement is planned
// generically, which pgx's are after a few calls. The plan test reads the same
// text.
func userListQuery(cursor string, org any, limit int, email, prefix, status string, reach []string) (string, []any) {
	where := []string{"($1 = '' OR id::text > $1)", "($2::uuid IS NULL OR org_id = $2::uuid)"}
	args := []any{cursor, org, limit}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if email != "" {
		add("lower(email) = $?", email)
	}
	if prefix != "" {
		add("(lower(email) LIKE $? OR lower(username) LIKE $?)", likePrefix(prefix))
	}
	if status != "" {
		add("status = $?", status)
	}
	// A role delegated over groups lists their members only (6.01).
	if reach != nil {
		add("EXISTS (SELECT 1 FROM core.group_members gm WHERE gm.user_id = core.users.id AND gm.group_id = ANY($?::uuid[]))", reach)
	}
	return `
		SELECT id::text, org_id::text, coalesce(email, ''), coalesce(username, ''),
		       status, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')
		  FROM core.users
		 WHERE ` + strings.Join(where, " AND ") + `
		 ORDER BY id
		 LIMIT $3`, args
}

// likePrefix is a LIKE pattern matching what starts with p, with p's own %, _
// and \ taken literally: a name containing an underscore is not a wildcard.
func likePrefix(p string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(p) + "%"
}

// userDetail is one user read: the summary and every field PATCH sets or
// clears (6.08). The read returned the summary alone, so a caller that set a
// person's name, or asked for a new password at the next sign-in, could not
// read back what it wrote, and an address change that cleared the
// verification could not be seen to have.
type userDetail struct {
	userSummary
	DisplayName           string `json:"display_name"`
	GivenName             string `json:"given_name"`
	Surname               string `json:"surname"`
	EmailVerified         bool   `json:"email_verified"`
	RequirePasswordChange bool   `json:"require_password_change"`
	UpdatedAt             string `json:"updated_at"`
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	var u userDetail
	err := s.db.QueryRow(ctx, `
		SELECT u.id::text, u.org_id::text, coalesce(u.email, ''), coalesce(u.username, ''),
		       u.status, to_char(u.created_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM'),
		       coalesce(u.display_name, ''), coalesce(u.given_name, ''), coalesce(u.surname, ''),
		       u.email_verified_at IS NOT NULL, coalesce(pc.must_change, false),
		       to_char(u.updated_at, 'YYYY-MM-DD"T"HH24:MI:SS.USTZH:TZM')
		  FROM core.users u
		  LEFT JOIN core.password_credentials pc ON pc.user_id = u.id
		 WHERE u.id = $1::uuid`, userID).
		Scan(&u.ID, &u.OrgID, &u.Email, &u.Username, &u.Status, &u.CreatedAt,
			&u.DisplayName, &u.GivenName, &u.Surname, &u.EmailVerified, &u.RequirePasswordChange,
			&u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	if err != nil {
		// An identifier that is not a UUID reaches here as a scan error rather
		// than as no-rows, and it is a bad request rather than a fault.
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_user_id", "detail": "the user id must be a UUID",
		})
		return
	}
	if err := requireOrg(ctx, u.OrgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	s.writeList(w, r, u)
}

// writeList answers a read, carrying the configuration ETag.
//
// The tag is on READS as well as writes so a caller can do the whole
// read-modify-write cycle from responses alone: GET a client, take the ETag,
// send it back as If-Match. Without it the caller has to make an extra request
// to /admin/config-version between every read and its write, which is the kind
// of friction that ends with people not using the precondition.
//
// auth tags every GET before its handler reads, which is the order that makes
// the tag safe (0.20); this reads the version itself only for a read that came
// some other way, and then the tag can be newer than the rows.
func (s *Server) writeList(w http.ResponseWriter, r *http.Request, body any) {
	if w.Header().Get("ETag") == "" {
		var v int64
		if err := s.db.QueryRow(r.Context(),
			`SELECT version FROM core.config_version`).Scan(&v); err == nil {
			setETag(w, v)
		}
	}
	writeJSON(w, http.StatusOK, body)
}
