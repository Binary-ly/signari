package httpapi

import (
	"net/http"
	"strings"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"signari.dev/engine/internal/audit"
)

// SPNEGO sign-in, for domain-joined machines.
//
// A user already signed in to a Windows domain or a FreeIPA realm holds a
// Kerberos ticket. The browser presents it here and the sign-in is no
// interaction at all.
//
// # None of Kerberos is implemented here
//
// gokrb5 validates the service ticket: keytabs, encryption types, the replay
// cache, clock skew. What is ours is the mapping from a principal to a person,
// and the refusals in kerberos.UsernameFor are the security of this endpoint --
// every one of them would be a bypass if it were permissive.
//
// # Why this is a separate path rather than the login page
//
// A browser that cannot produce a ticket must fall back to a password, and the
// fallback has to be quiet. Answering 401 with `WWW-Authenticate: Negotiate` on
// the ordinary login page would make every non-domain browser show a native
// credential dialog before it ever sees the form -- so SPNEGO lives at its own
// path, and the login page links to it.

// handleKerberosLogin is wrapped by the SPNEGO middleware; by the time it runs,
// the ticket has been validated.
func (s *Server) handleKerberosLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := goidentity.FromHTTPRequestContext(r)
	if id == nil {
		// Reached only if the middleware let an unauthenticated request through,
		// which would be a library change rather than a configuration error.
		writeError(w, http.StatusUnauthorized, "unauthorized",
			"the Kerberos ticket was not validated")
		return
	}

	principal := id.UserName()
	if d := id.Domain(); d != "" && !strings.Contains(principal, "@") {
		principal = principal + "@" + d
	}

	username, err := s.krbConfig.UsernameFor(principal)
	if err != nil {
		// Logged with the principal, answered without it. The reason a mapping
		// was refused is an operator's business; telling the browser which
		// realms are trusted is not.
		s.log.Info("kerberos principal refused", "principal", principal, "err", err,
			"correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"via": "kerberos", "reason": "principal not mapped"},
		})
		writeError(w, http.StatusForbidden, "access_denied",
			"that Kerberos identity cannot sign in here. Reference: "+
				shortCode(correlationID(ctx)))
		return
	}

	// From here it is an ordinary sign-in. The session, the policy, the audit
	// entry and the amr are the same as every other route, because a second
	// notion of "signed in" is how one of them ends up missing a check.
	s.completeKerberosSignIn(w, r, username, principal)
}

// completeKerberosSignIn establishes a session for an already-validated ticket.
//
// # No account is created
//
// A valid ticket proves the realm knows this principal. It does not decide that
// the principal should have an account HERE, and creating one on the strength of
// a ticket means every principal in the realm is a user the moment they visit.
//
// Accounts come from the directory sync, which is a deliberate act by an
// administrator. An unmatched principal is refused and told to ask for one.
func (s *Server) completeKerberosSignIn(w http.ResponseWriter, r *http.Request,
	username, principal string) {

	ctx := r.Context()
	orgID, err := s.defaultOrg(ctx)
	if err != nil || orgID == "" {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx, `
		SELECT id::text FROM core.users
		 WHERE org_id = $1::uuid AND lower(email) = lower($2) AND status = 'active'`,
		orgID, username).Scan(&userID)
	if err != nil {
		s.log.Info("kerberos principal has no account", "principal", principal,
			"looked_for", username, "correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"via": "kerberos", "reason": "no account"},
		})
		writeError(w, http.StatusForbidden, "access_denied",
			"your Kerberos identity is valid but has no account here. An "+
				"administrator adds one; a ticket alone does not. Reference: "+
				shortCode(correlationID(ctx)))
		return
	}

	// amr "krb" per RFC 8176. A policy can then require or refuse it -- Kerberos
	// is single-factor and a deployment that demands a second one should be able
	// to say so.
	s.completeSignIn(w, r, tx, userID, orgID, []string{"krb"},
		r.URL.Query().Get("authz"))
}

// wrapKerberos installs the SPNEGO middleware in front of the handler.
//
// Returns nil when Kerberos is not configured, so the route is simply not
// registered rather than registered and always failing.
func (s *Server) wrapKerberos(h http.Handler) http.Handler {
	if s.krbKeytab == nil {
		return nil
	}
	return spnego.SPNEGOKRB5Authenticate(h, s.krbKeytab)
}
