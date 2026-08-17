package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// asOutpostIdentity is the wire form of what the directory publishes.
//
// The same shape the in-process LDAP server exposes, and no more: an outpost
// must not learn anything about a person that a client binding to the local
// listener could not.
func asOutpostIdentity(i *ldapd.Identity) outpostIdentity {
	return outpostIdentity{
		Username: i.Username, Email: i.Email, DisplayName: i.DisplayName,
		Active: i.Active, Groups: i.Groups,
	}
}

// What an outpost is allowed to ask.
//
// An outpost token is a password-verification oracle: whoever holds one can ask
// "is this password correct for this user" as fast as this endpoint answers.
// That is unavoidable -- it is the whole function -- so the job here is to make
// it worth as little as possible beyond that.
//
//   - The token is bound to ONE protocol. A token issued for an LDAP outpost is
//     refused for RADIUS, so a leak costs one protocol rather than all of them.
//   - Every call is rate limited per outpost, on top of the per-user limits the
//     credential path already applies.
//   - Every use updates last_seen, with the address. A token being exercised
//     from somewhere new is then visible rather than inferred.
//
// It is deliberately not enough to change anything, mint a session, or read the
// directory in bulk beyond what a bound LDAP client could already read.

// outpostCallsPerMinute bounds one outpost.
//
// Generous for a directory serving an office and far below what makes a useful
// password-guessing engine. The per-user throttle still applies underneath;
// this is the limit that exists because the caller is remote and trusted only
// as far as its token.
const outpostCallsPerMinute = 600

// pdpCallsPerMinute is the limit for a policy decision point.
//
// Far higher than the others, because the traffic shape is completely
// different: an LDAP outpost binds when somebody signs in, a PDP is asked on
// EVERY request an application serves. 600/minute is ten decisions a second,
// which one moderately busy application exhausts on its own -- and a rate-
// limited PDP does not degrade gracefully, it denies.
//
// Measured rather than guessed: a 200-request benchmark against the evaluation
// endpoint tripped the outpost limit, which is how this was found.
const pdpCallsPerMinute = 120_000

type outpostIdentity struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Active      bool     `json:"active"`
	Groups      []string `json:"groups"`
}

// outpostAuth resolves the bearer token to an enabled outpost.
//
// Returns the org and the protocol the token was issued for. The protocol is
// checked by each handler rather than here, so the refusal names the mismatch.
func (s *Server) outpostAuth(w http.ResponseWriter, r *http.Request) (orgID, kind, name string, ok bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		writeError(w, http.StatusUnauthorized, "unauthorized", "outpost token required")
		return "", "", "", false
	}
	sum := sha256.Sum256([]byte(h[len(prefix):]))

	var id string
	err := s.db.QueryRow(r.Context(), `
		SELECT id::text, org_id::text, kind, name
		  FROM core.outposts WHERE token_hash = $1 AND enabled`, sum[:]).
		Scan(&id, &orgID, &kind, &name)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.Error("looking up an outpost token", "err", err)
		}
		writeError(w, http.StatusUnauthorized, "unauthorized", "that outpost token is not valid")
		return "", "", "", false
	}

	limit := outpostCallsPerMinute
	if kind == "pdp" {
		limit = pdpCallsPerMinute
	}
	if res, rerr := store.AllowRate(r.Context(), s.db, "outpost:"+id,
		limit, time.Minute); rerr == nil && !res.Allowed {
		writeError(w, http.StatusTooManyRequests, "slow_down",
			"this outpost is asking faster than the core will answer")
		return "", "", "", false
	}

	// Recorded on every call, not on a heartbeat. An outpost that stops asking
	// is an outage nobody is told about otherwise: the protocol simply stops
	// answering somewhere the operator is not looking.
	go func(ip string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.db.Exec(ctx, `
			UPDATE core.outposts SET last_seen_at = now(), last_seen_ip = $2
			 WHERE id = $1::uuid`, id, ip); err != nil {
			s.log.Debug("recording outpost activity", "err", err)
		}
	}(clientIP(r))

	return orgID, kind, name, true
}

// handleOutpostHello lets an outpost check its token before opening a listener.
func (s *Server) handleOutpostHello(w http.ResponseWriter, r *http.Request) {
	_, kind, name, ok := s.outpostAuth(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "kind": kind})
}

// handleOutpostAuthenticate verifies a password on an outpost's behalf.
func (s *Server) handleOutpostAuthenticate(w http.ResponseWriter, r *http.Request) {
	orgID, kind, name, ok := s.outpostAuth(w, r)
	if !ok {
		return
	}
	if kind != "ldap" && kind != "radius" {
		writeError(w, http.StatusForbidden, "wrong_kind",
			"this token was issued for a "+kind+" outpost, which does not verify passwords")
		return
	}

	var body struct{ Username, Password string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}

	auth := NewLDAPAuthenticator(s.db, passwords.NewHasher(passwords.MemoryBudgetMiB), orgID)
	ident, err := auth.Authenticate(r.Context(), body.Username, body.Password)
	if err != nil {
		// One answer for every reason. An outpost sits somewhere less trusted by
		// definition, and a response that distinguished "no such user" from
		// "wrong password" would make it a user-enumeration endpoint there.
		s.auditDetached(r.Context(), audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID,
			CorrelationID: correlationID(r.Context()),
			Detail:        map[string]any{"via": "outpost", "outpost": name},
		})
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication refused")
		return
	}
	writeJSON(w, http.StatusOK, asOutpostIdentity(ident))
}

// handleOutpostLookup answers an LDAP search without verifying a credential.
func (s *Server) handleOutpostLookup(w http.ResponseWriter, r *http.Request) {
	orgID, kind, _, ok := s.outpostAuth(w, r)
	if !ok {
		return
	}
	if kind != "ldap" {
		writeError(w, http.StatusForbidden, "wrong_kind",
			"only an LDAP outpost searches the directory")
		return
	}
	var body struct{ Username string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	auth := NewLDAPAuthenticator(s.db, passwords.NewHasher(passwords.MemoryBudgetMiB), orgID)
	ident, err := auth.Lookup(r.Context(), body.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such user")
		return
	}
	writeJSON(w, http.StatusOK, asOutpostIdentity(ident))
}

// handleOutpostList answers a subtree search.
func (s *Server) handleOutpostList(w http.ResponseWriter, r *http.Request) {
	orgID, kind, _, ok := s.outpostAuth(w, r)
	if !ok {
		return
	}
	if kind != "ldap" {
		writeError(w, http.StatusForbidden, "wrong_kind",
			"only an LDAP outpost searches the directory")
		return
	}
	var body struct{ Limit int }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	auth := NewLDAPAuthenticator(s.db, passwords.NewHasher(passwords.MemoryBudgetMiB), orgID)
	found, err := auth.List(r.Context(), body.Limit)
	if err != nil {
		s.log.Error("listing the directory for an outpost", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	out := make([]outpostIdentity, 0, len(found))
	for _, u := range found {
		out = append(out, asOutpostIdentity(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}
