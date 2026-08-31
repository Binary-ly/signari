package httpapi

import (
	"net/http"
	"strings"

	"signari.dev/engine/internal/dpop"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	raw, scheme := bearerTokenAndScheme(r)
	if raw == "" {
		// RFC 9449 §7.2: a resource supporting both schemes should advertise
		// both, and a challenge with no authentication attempted carries no
		// error code (RFC 6750 §3.1). `algs` tells a client which signature
		// algorithms a proof may use before it constructs one.
		// RFC 9728 §5.1: the 401 names where to find this resource's metadata,
		// which is how a client that was never configured for us discovers
		// which authorization server to use. It is the first step of MCP's
		// discovery flow.
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", `+s.resourceMetadataChallenge()+
				`, DPoP realm="signari", algs="`+dpop.SupportedAlgs()+`"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(), raw)
	if err != nil {
		// Logged with the reason, returned without it.
		s.log.Info("userinfo token rejected", "err", err)
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", `+s.resourceMetadataChallenge()+
				`, error="invalid_token", error_description="The access token is invalid"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// RFC 9700 §2.3: a resource server "MUST refuse to serve the respective
	// request" when the access token was not meant for it. We are the resource
	// server here, and the mint path honours RFC 8707 `resource`, so a token
	// audience-restricted to a downstream API must not also open this endpoint.
	if !tokens.AudienceAccepted(claims, s.cfg.Issuer) {
		s.log.Info("userinfo refused a token audienced elsewhere",
			"aud", claims.Audience, "correlation_id", correlationID(ctx))
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", error_description="`+
				`The access token was issued for a different resource"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !tokens.HasScope(claims.Scope, "openid") {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="insufficient_scope", scope="openid"`)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// An explicitly revoked token must stop working here immediately. This is the
	// endpoint where /revoke earns its 200: we are the resource server, so there
	// is no excuse for honouring a token the client told us to drop.
	if revoked, err := store.GrantRevoked(ctx, s.db, claims.GrantID); err != nil || revoked {
		// RFC 7009 §2.1: revoking the refresh token invalidates the access tokens
		// from the same grant. Checked alongside the per-jti denylist because a
		// client revokes the refresh token far more often than each access token.
		if err != nil {
			s.log.Error("userinfo grant revocation check failed", "err", err)
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", error_description="The authorization behind this token has been revoked"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if revoked, err := store.JTIRevoked(ctx, s.db, claims.JTI); err != nil || revoked {
		if err != nil {
			s.log.Error("userinfo revocation check failed", "err", err)
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", error_description="The access token has been revoked"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// The session must still be live. See (1) above.
	if claims.SessionID != "" {
		live, err := store.IsSessionLive(ctx, s.db, claims.SessionID)
		if err != nil || !live {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="signari", error="invalid_token", error_description="The session has ended"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// # Enforcement
	//
	// A token carrying `cnf.jkt` is sender-constrained, and holding it is not
	// enough. Without this check the claim would be a decoration: relying parties
	// reading `cnf` would believe the token was bound while a thief used it
	// freely -- which is worse than an honest bearer token.
	bound := claims.Cnf != nil && claims.Cnf.JKT != ""

	// How the token was PRESENTED, before any proof is examined. Both rules key
	// on the scheme rather than on the token, which is why checking `cnf` alone
	// missed them. See dpop.CheckPresentation.
	if perr := dpop.CheckPresentation(bound, scheme); perr != nil {
		s.log.Info("a token was presented under the wrong scheme", "err", perr,
			"correlation_id", correlationID(ctx))
		w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token", perr.Error()))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if bound {
		jkt, derr := s.verifyDPoPForRequest(r, raw)
		if derr != nil || jkt == "" {
			reason := "a DPoP proof is required for this token"
			if derr != nil {
				reason = derr.Error()
			}
			s.log.Info("DPoP enforcement refused a userinfo request", "reason", reason,
				"correlation_id", correlationID(ctx))
			w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token",
				"the access token is sender-constrained and the DPoP proof did not match"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := dpop.BoundTo(&dpop.Confirmation{JKT: claims.Cnf.JKT},
			&dpop.Proof{JKT: jkt}); err != nil {
			s.log.Info("DPoP binding mismatch", "err", err,
				"correlation_id", correlationID(ctx))
			w.Header().Set("WWW-Authenticate", dpopChallenge("invalid_token",
				"this access token is bound to a different key"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	out := map[string]any{"sub": claims.Subject}

	// Claims are released strictly by granted scope. `profile` and `email` are
	// separate grants and must not leak into each other.
	var email, username string
	var verified *bool
	if err := s.db.QueryRow(ctx,
		`SELECT COALESCE(email,''), COALESCE(username,''), email_verified_at IS NOT NULL
		 FROM core.users WHERE id = $1 AND status = 'active'`,
		claims.Subject).Scan(&email, &username, &verified); err != nil {
		// A token for a user who no longer exists or is deactivated.
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="signari", error="invalid_token", error_description="The subject is not active"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if tokens.HasScope(claims.Scope, "email") && email != "" {
		out["email"] = email
		out["email_verified"] = verified != nil && *verified
	}
	if tokens.HasScope(claims.Scope, "profile") && username != "" {
		out["preferred_username"] = username
	}
	// Same two gates as the ID token, and read fresh for the same reason: a
	// long-lived access token must not keep asserting a group after the
	// membership is gone.
	if tokens.HasScope(claims.Scope, "groups") {
		groups, err := store.GroupsForUser(ctx, s.db, claims.Subject, claims.ClientID)
		if err != nil {
			s.log.Error("loading group membership for userinfo", "err", err)
		} else if len(groups) > 0 {
			out["groups"] = groups
		}
	}

	// Operator-defined claims, resolved LAST and merged without overwriting.
	//
	// The order is the safety property. A mapper cannot replace `sub`, `email`
	// or `email_verified` with an attribute value: the database refuses the
	// protocol claims outright (claim_mappers_not_a_protocol_claim), and this
	// loop refuses to overwrite anything already released above. Between them a
	// mapper can only ADD, which means no configuration change can alter the
	// meaning of a claim a relying party already trusts.
	if s.root != nil {
		if tx, err := s.db.Begin(ctx); err == nil {
			var orgID string
			if err := tx.QueryRow(ctx,
				`SELECT org_id::text FROM core.users WHERE id = $1::uuid`,
				claims.Subject).Scan(&orgID); err == nil {
				mapped, merr := store.MappedClaims(ctx, tx, claims.Subject, orgID,
					claims.ClientID, store.ClaimInUserInfo, claims.Scope, s.root)
				if merr != nil {
					s.log.Error("resolving mapped claims", "err", merr)
				}
				for name, value := range mapped {
					if _, taken := out[name]; !taken {
						out[name] = value
					}
				}
			}
			_ = tx.Rollback(ctx)
		}
	}

	writeJSON(w, http.StatusOK, out)
}

// bearerToken reads the access token from the Authorization header (RFC 6750
// §2.1) or, on a POST, from the form body (§2.2).
//
// Never from the query string (§2.3), which OIDC also permits: a token there
// lands in access logs, browser history and Referer headers, and RFC 9700
// advises against accepting it. The body form has none of those properties.
//
// OIDC Core §5.3.1 requires the endpoint to accept POST with the token as an
// `access_token` form field, which is what clients that cannot set headers (and
// several SDKs) actually use. Supporting only the header made this endpoint
// unusable for them.
//
// Presenting the token in BOTH places is rejected rather than resolved by
// precedence: two different token values in one request is either a broken
// client or an attempt to have the check read one and the logic use the other.
func bearerToken(r *http.Request) string {
	tok, _ := bearerTokenAndScheme(r)
	return tok
}

// bearerTokenAndScheme also reports WHICH scheme carried the token.
//
// The scheme is not decoration. RFC 9449 §7.1 and §7.2 both attach MUST-level
// requirements to it, and both are downgrade defences:
//
//   - §7.1, of a token sent with the DPoP scheme: "a resource server MUST check
//     that a DPoP proof was also received in the DPoP header field... MUST NOT
//     grant access to the resource unless all checks are successful." That is a
//     property of the scheme, not of the token. A client presenting an unbound
//     token under the DPoP scheme believes it is proving possession; granting
//     the request tells it so while nothing was proven.
//
//   - §7.2, of a bound token sent with Bearer: "such a protected resource MUST
//     reject a DPoP-bound access token received as a bearer token." Accepting
//     it is the "downgraded usage" the section exists to prevent.
//
// A token in the request body is a Bearer presentation (RFC 6750 §2.2), so it
// is reported as such and falls under the second rule.
func bearerTokenAndScheme(r *http.Request) (token, scheme string) {
	var header string
	h := r.Header.Get("Authorization")
	// Both schemes. RFC 9449 §7.1: a sender-constrained token is presented as
	// `Authorization: DPoP <token>`, not Bearer. Accepting only Bearer would
	// make every DPoP-bound token unusable at the very endpoint that enforces
	// the binding -- the feature would appear to work at issuance and fail at
	// use, which is the most confusing possible split.
	//
	// Accepting the DPoP scheme is not itself an authorisation decision: the
	// binding is checked by the caller, against the token's own cnf claim.
	for _, prefix := range []string{"Bearer ", "DPoP "} {
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			header = strings.TrimSpace(h[len(prefix):])
			scheme = strings.TrimSpace(prefix)
			break
		}
	}

	if r.Method != http.MethodPost {
		return header, scheme
	}
	// Only application/x-www-form-urlencoded, per the spec. Parsing any body
	// type here would let a token arrive somewhere nothing else expects it.
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return header, scheme
	}
	if err := r.ParseForm(); err != nil {
		return "", ""
	}
	body := strings.TrimSpace(r.PostForm.Get("access_token"))
	switch {
	case body == "":
		return header, scheme
	case header == "":
		return body, "Bearer" // RFC 6750 §2.2 is a Bearer presentation.
	default:
		// Both present. Ambiguous by construction.
		return "", ""
	}
}
