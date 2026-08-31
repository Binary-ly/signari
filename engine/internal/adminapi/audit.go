package adminapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Reading the audit trail over HTTP.
//
// # Why this needed to exist
//
// `core_v1.audit_events` has existed since migration 0003 with no route over it
// and no console model reading it. So the trail was reachable only by
// `signari export audit` on a host with a database credential — which means the
// people who most often need it, a support desk answering "how did this account
// authenticate on Tuesday", could not see it at all.
//
// # Its own scope
//
// `audit:read`, not folded into `users:read`. The trail says when each person
// authenticated, from what kind of client, and what an administrator did to
// them. That is a different and larger disclosure than a user list, and the
// separation matters most in the direction people forget: a token issued to a
// provisioning script so it can look up users should not thereby be able to read
// everyone's authentication history.
//
// It is deliberately NOT implied by `users:write` the way the read scopes are.
// The implication rule exists so a token that may change a thing can see that
// thing; the audit trail is not that thing, it is the record of everyone who
// touched it.
//
// # This endpoint does not verify the hash chain, and says so
//
// The chain is over the whole table: entry N's hash covers entry N-1. Verifying
// a PAGE proves nothing, because the page's first entry has a predecessor the
// page does not contain, and an attacker who removed a row would be removing it
// from a page nobody asked for.
//
// Verifying the entire chain on a request that wanted fifty rows would read the
// table — which is both a denial of service and, worse, an invitation to skip
// verification "just for this query" until nobody does it at all. So
// verification stays in `signari export audit`, which is the operation whose
// output is the evidence, and this endpoint is for looking things up. The
// distinction is stated in the response so that nobody builds a compliance
// process on a call that never claimed to check integrity.
//
// # Filters are for finding, and are all indexed or bounded
//
// A trail with no filters is one a support desk pages through until they give
// up. Every filter is applied in the WHERE clause together with the organisation
// restriction — never afterwards, because a filter applied to results is one a
// later refactor moves, and the failure is one tenant reading another's history
// while the endpoint returns a cheerful 200.

// auditEvent is one row as it leaves this process.
//
// The chain columns (prev_hash, entry_hash) are deliberately absent. Returning
// them would invite exactly the page-local verification the comment above
// explains is meaningless — a reader would hash what they received, find it
// consistent, and believe they had checked something.
type auditEvent struct {
	ID             string          `json:"id"`
	OrgID          string          `json:"org_id"`
	OccurredAt     string          `json:"occurred_at"`
	EventType      string          `json:"event_type"`
	SubjectID      string          `json:"subject_id,omitempty"`
	ActorID        string          `json:"actor_id,omitempty"`
	ClientID       string          `json:"client_id,omitempty"`
	CorrelationID  string          `json:"correlation_id,omitempty"`
	RetentionClass string          `json:"retention_class,omitempty"`
	Detail         json.RawMessage `json:"detail,omitempty"`
}

// listAuditEvents returns a page of the trail, newest first.
//
// # It reads core.audit_events, not core_v1.audit_events
//
// The first version read the view and PostgreSQL refused it: permission denied
// for schema core_v1. That error is the boundary working rather than a
// misconfiguration.
//
// The core_v1 views exist for the CONSOLE, which has no privilege on schema core
// at all (ADR-004). This handler is the engine, which owns core. Reading its own
// data through a compatibility view built for a different consumer would make
// the engine depend on a surface whose whole purpose is to be a stable contract
// for somebody else -- so a change made for the console's benefit would silently
// become a change to the engine. The view looked like the more careful choice
// and is the opposite of one.
func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, cursor := pageParams(r)
	q := r.URL.Query()

	// Newest first, because the question that brings somebody here is almost
	// always about something that just happened. The cursor is therefore
	// descending, and composite: `occurred_at` alone is not unique — a
	// fan-out writes several events in one transaction with the same timestamp,
	// and paging on a non-unique column silently skips rows at every page
	// boundary. The pair (occurred_at, id) is unique because id is.
	//
	// Typed as `any` and left nil when absent, so the parameters bind as SQL
	// NULL. Passing "" instead looks safe because the guard `$2 = '' OR ...`
	// appears to short-circuit, and does not: PostgreSQL binds and casts every
	// parameter before any row is evaluated, so the empty string reaches the
	// cast and every unpaged request fails.
	var cursorTime, cursorID any
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_cursor",
				"detail": "a cursor is the value returned by the previous page, " +
					"not a value to construct",
			})
			return
		}
		t, id, ok := strings.Cut(string(raw), "_")
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_cursor",
				"detail": "a cursor is the value returned by the previous page, " +
					"not a value to construct",
			})
			return
		}
		cursorTime, cursorID = t, id
	}

	// Time bounds. Parsed here so a malformed one is a 400 rather than a
	// database error surfaced as a 500.
	since, ok := timeParam(w, q.Get("since"), "since")
	if !ok {
		return
	}
	until, ok := timeParam(w, q.Get("until"), "until")
	if !ok {
		return
	}

	rows, err := s.db.Query(ctx, `
		SELECT id::text,
		       org_id::text,
		       to_char(occurred_at, 'YYYY-MM-DD"T"HH24:MI:SS.USOF'),
		       event_type,
		       coalesce(subject_id::text, ''),
		       coalesce(actor_id::text, ''),
		       coalesce(client_id, ''),
		       -- ::text before the coalesce. correlation_id is a uuid, so
		       -- coalesce(correlation_id, '') asks PostgreSQL to read '' as a
		       -- uuid and fails the whole query -- with an error that names the
		       -- uuid type and points at a column list, which reads like a
		       -- parameter problem and is not.
		       coalesce(correlation_id::text, ''),
		       coalesce(retention_class, ''),
		       detail
		  FROM core.audit_events
		 WHERE ($1::uuid IS NULL OR org_id = $1::uuid)
		   -- id is BIGINT here, not uuid -- the only identifier in this schema
		   -- that is not. Assuming otherwise cost an hour: it fails as
		   -- "operator does not exist: bigint < uuid", which reads as a
		   -- parameter problem.
		   AND ($2::timestamptz IS NULL OR
		        (occurred_at, id) < ($2::timestamptz, $3::bigint))
		   AND ($4 = '' OR event_type = $4)
		   AND ($5 = '' OR subject_id::text = $5)
		   AND ($6 = '' OR client_id = $6)
		   AND ($7::timestamptz IS NULL OR occurred_at >= $7::timestamptz)
		   AND ($8::timestamptz IS NULL OR occurred_at <= $8::timestamptz)
		 ORDER BY occurred_at DESC, id DESC
		 LIMIT $9`,
		orgFilter(ctx), cursorTime, cursorID,
		q.Get("event_type"), q.Get("subject_id"), q.Get("client_id"),
		since, until, limit+1)
	if err != nil {
		s.log.Error("listing audit events", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer rows.Close()

	out := []auditEvent{}
	for rows.Next() {
		var e auditEvent
		var detail []byte
		if err := rows.Scan(&e.ID, &e.OrgID, &e.OccurredAt, &e.EventType,
			&e.SubjectID, &e.ActorID, &e.ClientID, &e.CorrelationID,
			&e.RetentionClass, &detail); err != nil {
			s.log.Error("scanning an audit event", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		e.Detail = json.RawMessage(detail)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		s.log.Error("listing audit events", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Base64url, and that is a correctness requirement rather than tidiness.
	//
	// The cursor carries a timestamp, whose timezone offset is written `+02:00`.
	// A bare `+` in a query string means SPACE, so a caller pasting the cursor
	// back sends `2026-08-31T03:17:41.443309 02:00` and the next page is a 500 --
	// on a deployment east of Greenwich, and never on one running UTC, which is
	// exactly the bug that ships.
	//
	// Encoding also makes the cursor opaque, which the error text above already
	// claims it is: a caller who cannot read it will not try to construct one,
	// and the format stays ours to change.
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = base64.RawURLEncoding.EncodeToString([]byte(last.OccurredAt + "_" + last.ID))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events":      out,
		"next_cursor": next,
		// Stated in every response rather than only in the documentation.
		// Somebody will build a compliance process on this endpoint, and they
		// should find out here that it did not check the chain.
		"chain_verified": false,
		"chain_note": "the hash chain is not verified by this endpoint; a page " +
			"cannot be verified in isolation. Use `signari export audit`.",
	})
}

// timeParam parses an optional RFC 3339 bound.
func timeParam(w http.ResponseWriter, raw, name string) (any, bool) {
	if raw == "" {
		return nil, true
	}
	if _, err := time.Parse(time.RFC3339, raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "invalid_" + name,
			"detail": name + " must be an RFC 3339 timestamp, e.g. 2026-08-31T00:00:00Z",
		})
		return nil, false
	}
	return raw, true
}
