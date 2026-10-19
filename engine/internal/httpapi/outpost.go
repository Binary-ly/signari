package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
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
		// sn and givenName travel too, so an outpost-served entry is as
		// schema-valid as an in-process one. `sn` is a MUST attribute of
		// `person`; without it here the outpost would fall back to guessing one
		// from the display name for every account, including the ones where we
		// know the real answer.
		Surname: i.Surname, GivenName: i.GivenName,
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
// directory beyond what the person who bound through the outpost may read. That
// last part is decided here, not by the outpost: a lookup or a list carries the
// bind proof issued when that person's password was verified, and is answered
// for them -- their own entry, or the directory when they are, as they stand
// now, in the search group recorded on the outpost's registration. Until
// migration 0142 the outpost enforced its group and the token alone listed the
// whole organisation.

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
	// omitempty on both, so an outpost built before these existed sees the same
	// bytes it saw before and keeps working. They are optional in the schema and
	// optional on the wire.
	Surname   string `json:"sn,omitempty"`
	GivenName string `json:"given_name,omitempty"`
	// BindProof is set on an LDAP outpost's authenticate answer only.
	BindProof string `json:"bind_proof,omitempty"`
}

// outpostCaller is the registration an outpost token resolved to.
type outpostCaller struct {
	ID, OrgID, Kind, Name string
	// SearchGroup is whose members behind this outpost may read the whole
	// directory. Empty: nobody's but their own.
	SearchGroup string
}

// outpostAuth resolves the bearer token to an enabled outpost.
//
// Returns the org and the protocol the token was issued for. The protocol is
// checked by each handler rather than here, so the refusal names the mismatch.
func (s *Server) outpostAuth(w http.ResponseWriter, r *http.Request) (orgID, kind, name string, ok bool) {
	c, ok := s.outpostCall(w, r)
	if !ok {
		return "", "", "", false
	}
	return c.OrgID, c.Kind, c.Name, true
}

// outpostCall is outpostAuth with the whole registration, for the handlers
// that answer by it.
func (s *Server) outpostCall(w http.ResponseWriter, r *http.Request) (*outpostCaller, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		writeError(w, http.StatusUnauthorized, "unauthorized", "outpost token required")
		return nil, false
	}
	sum := sha256.Sum256([]byte(h[len(prefix):]))

	var c outpostCaller
	err := s.db.QueryRow(r.Context(), `
		SELECT id::text, org_id::text, kind, name, COALESCE(search_group, '')
		  FROM core.outposts WHERE token_hash = $1 AND enabled`, sum[:]).
		Scan(&c.ID, &c.OrgID, &c.Kind, &c.Name, &c.SearchGroup)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.log.Error("looking up an outpost token", "err", err)
		}
		writeError(w, http.StatusUnauthorized, "unauthorized", "that outpost token is not valid")
		return nil, false
	}
	id, kind := c.ID, c.Kind

	limit := outpostCallsPerMinute
	if kind == "pdp" {
		limit = pdpCallsPerMinute
	}
	// A database error refuses, as every other limiter here does. It used to
	// let the call through, so a fault in the limiter unthrottled every outpost.
	res, rerr := store.AllowRate(r.Context(), s.db, "outpost:"+id, limit, time.Minute)
	if rerr != nil {
		s.log.Error("checking the outpost rate limit", "err", rerr)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "please try again shortly")
		return nil, false
	}
	if !res.Allowed {
		writeError(w, http.StatusTooManyRequests, "slow_down",
			"this outpost is asking faster than the core will answer")
		return nil, false
	}

	// Recorded on every call, not on a heartbeat. An outpost that stops asking
	// is an outage nobody is told about otherwise: the protocol simply stops
	// answering somewhere the operator is not looking.
	// context.Background, not r.Context(), and that is the point rather than an
	// oversight: this write must OUTLIVE the request. Using the request context
	// would cancel it the instant the response is written, so the recording would
	// land only when the database happened to be faster than the handler's
	// return -- which is the kind of intermittent that gets diagnosed as "the
	// outpost stopped reporting".
	//
	// Bounded at five seconds so a detached goroutine cannot accumulate.
	//
	// #nosec G118 -- deliberate detachment, bounded above.
	go func(ip string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.db.Exec(ctx, `
			UPDATE core.outposts SET last_seen_at = now(), last_seen_ip = $2
			 WHERE id = $1::uuid`, id, ip); err != nil {
			s.log.Debug("recording outpost activity", "err", err)
		}
	}(clientIP(r))

	return &c, true
}

// handleOutpostHello lets an outpost check its token before opening a listener.
//
// It also tells the outpost its search group, which the core enforces whatever
// the outpost does, so the outpost decides with the same value rather than one
// from its own environment that could say something else.
func (s *Server) handleOutpostHello(w http.ResponseWriter, r *http.Request) {
	c, ok := s.outpostCall(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": c.Name, "kind": c.Kind, "search_group": c.SearchGroup,
	})
}

const typOutpostBind = "outpost-bind+jwt"

// outpostBindTTL bounds how long one bind answers lookups and lists.
//
// Not a strong control, and not meant as one: the person it names is read
// again, status and groups, on every use, so a long life does not let a
// deactivated account or a removed member keep reading. What the proof
// prevents is the token alone reading anything, and it does that at any
// lifetime. Long enough for a pooled connection that binds once in the
// morning; when it lapses the outpost's searches fail and the client binds
// again.
const outpostBindTTL = 8 * time.Hour

// outpostBindClaims record that a person's password was verified through one
// outpost. Signed rather than stored: there is nothing to revoke that is not
// already read fresh, and an outpost serving an office would otherwise write a
// row per bind.
type outpostBindClaims struct {
	Issuer  string `json:"iss"`
	Outpost string `json:"out"`
	OrgID   string `json:"org"`
	// Subject is the username the bind resolved to, read again on each use.
	Subject string `json:"sub"`
	Expiry  int64  `json:"exp"`
}

func (s *Server) outpostBindProof(c *outpostCaller, username string) (string, error) {
	key, err := s.anySigningKey()
	if err != nil {
		return "", err
	}
	return tokens.NewSigner(key).SignJSON(outpostBindClaims{
		Issuer: s.cfg.Issuer, Outpost: c.ID, OrgID: c.OrgID, Subject: username,
		Expiry: time.Now().Add(outpostBindTTL).Unix(),
	}, typOutpostBind)
}

// outpostAsker is the person a lookup or list is answered for: the one whose
// bind through THIS outpost the proof records, as they stand now. No proof, a
// proof from another outpost or organisation, an expired one, or a person no
// longer active, and there is nobody asking.
func (s *Server) outpostAsker(r *http.Request, c *outpostCaller, auth *LDAPAuthenticator,
	proof string) *ldapd.Identity {

	if proof == "" {
		return nil
	}
	payload, err := tokens.VerifyTyped(s.cfg.Keys, s.cfg.Issuer, proof, typOutpostBind)
	if err != nil {
		return nil
	}
	var cl outpostBindClaims
	if err := json.Unmarshal(payload, &cl); err != nil ||
		cl.Outpost != c.ID || cl.OrgID != c.OrgID || time.Now().After(time.Unix(cl.Expiry, 0)) {
		return nil
	}
	id, err := auth.Lookup(r.Context(), cl.Subject)
	if err != nil || id == nil || !id.Active {
		return nil
	}
	return id
}

// mayReadDirectory reports whether the asker may read entries other than their
// own: only as a member, now, of the group recorded on this outpost.
func (c *outpostCaller) mayReadDirectory(asker *ldapd.Identity) bool {
	return c.SearchGroup != "" && slices.Contains(asker.Groups, c.SearchGroup)
}

func refuseOutpostAsker(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "bind_required",
		"this request carries no valid proof of a bind through this outpost; bind again")
}

// handleOutpostAuthenticate verifies a password on an outpost's behalf.
func (s *Server) handleOutpostAuthenticate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.outpostCall(w, r)
	if !ok {
		return
	}
	orgID, kind, name := c.OrgID, c.Kind, c.Name
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

	auth := NewLDAPAuthenticator(s.db, passwords.Shared(), orgID, s.log).
		WithMFAGate(s.BindDemandsMFA)
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
	resp := asOutpostIdentity(ident)
	// Only an LDAP outpost searches, so only it is handed what searching takes.
	if kind == "ldap" {
		proof, perr := s.outpostBindProof(c, ident.Username)
		if perr != nil {
			s.log.Error("signing an outpost bind proof", "err", perr)
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		resp.BindProof = proof
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleOutpostLookup answers an LDAP search without verifying a credential,
// for the person whose bind the request proves: their own entry, or anyone's
// when they are in this outpost's search group. Somebody else's entry is the
// same 404 as an account that does not exist.
func (s *Server) handleOutpostLookup(w http.ResponseWriter, r *http.Request) {
	c, ok := s.outpostCall(w, r)
	if !ok {
		return
	}
	if c.Kind != "ldap" {
		writeError(w, http.StatusForbidden, "wrong_kind",
			"only an LDAP outpost searches the directory")
		return
	}
	var body struct {
		Username  string
		BindProof string `json:"bind_proof"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	auth := NewLDAPAuthenticator(s.db, passwords.Shared(), c.OrgID, s.log)
	asker := s.outpostAsker(r, c, auth, body.BindProof)
	if asker == nil {
		refuseOutpostAsker(w)
		return
	}
	ident, err := auth.Lookup(r.Context(), body.Username)
	if err != nil || ident == nil ||
		(ident.Username != asker.Username && !c.mayReadDirectory(asker)) {
		writeError(w, http.StatusNotFound, "not_found", "no such user")
		return
	}
	writeJSON(w, http.StatusOK, asOutpostIdentity(ident))
}

// handleOutpostList answers a subtree search: the directory for a member of
// this outpost's search group, the asker's own entry for anyone else.
func (s *Server) handleOutpostList(w http.ResponseWriter, r *http.Request) {
	c, ok := s.outpostCall(w, r)
	if !ok {
		return
	}
	if c.Kind != "ldap" {
		writeError(w, http.StatusForbidden, "wrong_kind",
			"only an LDAP outpost searches the directory")
		return
	}
	var body struct {
		Limit     int
		BindProof string `json:"bind_proof"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable body")
		return
	}
	auth := NewLDAPAuthenticator(s.db, passwords.Shared(), c.OrgID, s.log)
	asker := s.outpostAsker(r, c, auth, body.BindProof)
	if asker == nil {
		refuseOutpostAsker(w)
		return
	}
	if !c.mayReadDirectory(asker) {
		writeJSON(w, http.StatusOK, map[string]any{"users": []outpostIdentity{asOutpostIdentity(asker)}})
		return
	}
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
