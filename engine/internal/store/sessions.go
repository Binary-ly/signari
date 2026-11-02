package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// TerminationReason is why a session ended. Every reason routes through the same
// function; there is no "quick path" that skips notification.
type TerminationReason string

const (
	ReasonLogout          TerminationReason = "logout"
	ReasonAdminRevoke     TerminationReason = "admin_revoke"
	ReasonUserDeleted     TerminationReason = "user_deleted"
	ReasonUserDeactivated TerminationReason = "user_deactivated"
	ReasonPasswordChange  TerminationReason = "password_change"
	ReasonMFAReset        TerminationReason = "mfa_reset"
	ReasonExpired         TerminationReason = "expired"
	ReasonReuseDetected   TerminationReason = "reuse_detected"
	// ReasonSessionLimit is the oldest session ended to make room for a new one,
	// under an organisation's concurrent-session cap. Distinct from
	// ReasonAdminRevoke because nobody decided this about this session in
	// particular -- a policy did, and the person will want to know which.
	ReasonSessionLimit TerminationReason = "session_limit"
	// ReasonReauthenticated is the session replaced when its holder authenticates
	// again. ASVS V7.2.4 requires the previous token to be terminated, not merely
	// replaced in the browser.
	ReasonReauthenticated TerminationReason = "reauthenticated"
	// Support access ended -- by an administrator stopping it, or by it running
	// out. Distinct from logout so an audit reader can tell the two apart.
	ReasonImpersonationEnded TerminationReason = "impersonation_ended"
	ReasonSharedSignal       TerminationReason = "shared_signal"
	// ReasonUserRevoke is a session the user ended themselves from the
	// self-service account console (ASVS V7.5.2). Distinct from ReasonLogout
	// because the session being ended is usually not the one making the request.
	ReasonUserRevoke TerminationReason = "user_revoke"
	// ReasonRestored: the database was restored from a backup, which brought
	// back sessions ended after it was taken (3.10).
	ReasonRestored TerminationReason = "restored"
)

// LogoutNotice is one queued back-channel logout delivery.
type LogoutNotice struct {
	ClientID  string `json:"client_id"`
	Endpoint  string `json:"endpoint"`
	SessionID string `json:"sid,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Reason    string `json:"reason"`
}

// Terminated reports what one termination did.
type Terminated struct {
	Sessions int
	Notices  int
}

func TerminateSessions(ctx context.Context, tx pgx.Tx, sid, userID string, reason TerminationReason) (*Terminated, error) {
	if (sid == "") == (userID == "") {
		return nil, fmt.Errorf("TerminateSessions needs exactly one of sid or userID")
	}
	var sids []string
	if sid != "" {
		sids = []string{sid}
	}
	return terminate(ctx, tx, sids, userID, reason)
}

// TerminateEachSession ends the sessions named, each addressed by its sid, in as
// many statements as ending one takes. The sweep ends thousands at a time, and a
// statement per session is what kept it to 500 a minute.
func TerminateEachSession(ctx context.Context, tx pgx.Tx, sids []string, reason TerminationReason) (*Terminated, error) {
	if len(sids) == 0 {
		return &Terminated{}, nil
	}
	return terminate(ctx, tx, sids, "", reason)
}

// terminate is the one path a session ends by: the sessions named, or every one
// a person holds.
func terminate(ctx context.Context, tx pgx.Tx, sids []string, userID string, reason TerminationReason) (*Terminated, error) {
	// Everything of a person's ending ends what speaks for them with no session
	// behind it, as it ends their refresh tokens: signed out everywhere is a thing
	// they are told happened, and a PCT left over would make it untrue.
	if userID != "" {
		if _, err := tx.Exec(ctx, `DELETE FROM core.uma_persisted_claims WHERE user_id = $1::uuid`, userID); err != nil {
			return nil, fmt.Errorf("ending persisted claims: %w", err)
		}
	}

	// 1. Snapshot. Only live sessions: re-revoking an already-revoked session
	// must not re-notify, or an expiry sweep would replay logout storms.
	rows, err := tx.Query(ctx, `
		SELECT s.sid, s.user_id::text, sc.client_id, c.backchannel_logout_uri
		FROM core.sessions s
		JOIN core.session_clients sc ON sc.sid = s.sid
		JOIN core.clients c          ON c.client_id = sc.client_id
		WHERE s.revoked_at IS NULL
		  AND ($1::text[] IS NULL OR s.sid = ANY($1))
		  AND ($2::uuid IS NULL OR s.user_id = $2)
		  AND c.backchannel_logout_uri IS NOT NULL`,
		sids, nullIf(userID))
	if err != nil {
		return nil, fmt.Errorf("snapshotting sessions: %w", err)
	}

	var notices []LogoutNotice
	for rows.Next() {
		var gotSID, gotUser, clientID, endpoint string
		if err := rows.Scan(&gotSID, &gotUser, &clientID, &endpoint); err != nil {
			rows.Close()
			return nil, err
		}
		n := LogoutNotice{ClientID: clientID, Endpoint: endpoint, Reason: string(reason)}
		if userID == "" {
			n.SessionID = gotSID // a session named: address it by sid
		} else {
			n.Subject = gotUser // all sessions: address them by sub
		}
		notices = append(notices, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 2. Queue. Deduplicated: ending all of a user's sessions must send one
	// sub-addressed notice per relying party, not one per session.
	seen := map[string]bool{}
	var payloads []string
	for _, n := range notices {
		key := n.ClientID + "|" + n.SessionID + "|" + n.Subject
		if seen[key] {
			continue
		}
		seen[key] = true
		// The receiver is told as it knows them, here because signing has no database.
		if n.Subject != "" {
			var err error
			if n.Subject, err = ClientSubject(ctx, tx, n.ClientID, n.Subject); err != nil {
				return nil, err
			}
		}
		payload, err := json.Marshal(n)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, string(payload))
	}
	if len(payloads) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.outbox (topic, payload)
			SELECT 'backchannel_logout', p::jsonb FROM unnest($1::text[]) AS p`, payloads); err != nil {
			return nil, fmt.Errorf("queuing logout notices: %w", err)
		}
	}

	// 2b. CAEP security events, queued INDEPENDENTLY of back-channel logout.
	//
	// The first version emitted these inside the loop above -- and that loop only
	// visits clients with a registered `backchannel_logout_uri`. A receiver that
	// subscribed to security events but does not implement back-channel logout
	// got nothing at all, silently. The two are different features for different
	// audiences and neither should be a prerequisite for the other.
	//
	// Queued only for streams that are enabled or paused, asked for THIS event
	// type, and whose client actually participated in the session: a stream is
	// not a licence to learn about every user in the directory. A paused
	// stream's events are queued and held, not sent, because a paused
	// transmitter "SHOULD hold any events it would have transmitted while
	// paused, and SHOULD transmit them when the stream's status becomes
	// enabled" (specs/ssf-1_0.txt:2592-2598); delivery holds them. A disabled
	// one holds nothing.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload)
		SELECT DISTINCT 'ssf_event', jsonb_build_object(
			'stream_id', st.id::text,
			'client_id', st.client_id,
			'endpoint',  st.endpoint_url,
			'event',     $3::text,
			'subject',   s.user_id::text,
			'sid',       s.sid,
			'reason',    $4::text)
		FROM core.sessions s
		JOIN core.session_clients sc ON sc.sid = s.sid
		JOIN core.ssf_streams st     ON st.client_id = sc.client_id
		WHERE s.revoked_at IS NULL
		  AND ($1::text[] IS NULL OR s.sid = ANY($1))
		  AND ($2::uuid IS NULL OR s.user_id = $2)
		  AND st.status IN ('enabled', 'paused')
		  AND st.delivery_method = 'push'
		  AND $3::text = ANY(st.events_requested)
		  AND NOT EXISTS (SELECT 1 FROM core.ssf_removed_subjects r
		                   WHERE r.stream_id = st.id AND r.user_id = s.user_id)`,
		sids, nullIf(userID),
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		string(reason)); err != nil {
		return nil, fmt.Errorf("queuing CAEP session-revoked events: %w", err)
	}

	// 2c. The same events, for POLL streams (RFC 8936), into the poll queue rather
	// than the push outbox: a poll receiver pulls these instead of us POSTing them.
	// A jti is assigned here so the value the receiver acknowledges is stable
	// across redeliveries, and the SET is minted from the payload at poll time.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.ssf_poll_queue (stream_id, jti, event_type, payload)
		SELECT d.stream_id, gen_random_uuid()::text, $3::text, d.payload
		FROM (
			SELECT DISTINCT st.id AS stream_id,
				jsonb_build_object(
					'client_id', st.client_id,
					'subject',   s.user_id::text,
					'sid',       s.sid,
					'reason',    $4::text) AS payload
			FROM core.sessions s
			JOIN core.session_clients sc ON sc.sid = s.sid
			JOIN core.ssf_streams st     ON st.client_id = sc.client_id
			WHERE s.revoked_at IS NULL
			  AND ($1::text[] IS NULL OR s.sid = ANY($1))
			  AND ($2::uuid IS NULL OR s.user_id = $2)
			  AND st.status IN ('enabled', 'paused')
			  AND st.delivery_method = 'poll'
			  AND $3::text = ANY(st.events_requested)
			  AND NOT EXISTS (SELECT 1 FROM core.ssf_removed_subjects r
			                   WHERE r.stream_id = st.id AND r.user_id = s.user_id)
		) d`,
		sids, nullIf(userID),
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		string(reason)); err != nil {
		return nil, fmt.Errorf("queuing CAEP session-revoked events for poll: %w", err)
	}

	// 2d. Service providers that take a logout with no browser. The redirect chain
	// reaches a provider only when a person signs out by hand; this is every other
	// way a session ends, and that way as well. A provider told twice has nothing
	// left to end the second time.
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload)
		SELECT DISTINCT $3::text, jsonb_build_object('sid', s.sid, 'provider_id', p.provider_id::text)
		  FROM core.sessions s
		  JOIN core.saml_session_participants p ON p.sid = s.sid
		  JOIN core.saml_slo_urls u ON u.provider_id = p.provider_id AND u.binding = 'SOAP'
		 WHERE s.revoked_at IS NULL
		   AND ($1::text[] IS NULL OR s.sid = ANY($1))
		   AND ($2::uuid IS NULL OR s.user_id = $2)`,
		sids, nullIf(userID), SAMLLogoutTopic); err != nil {
		return nil, fmt.Errorf("queuing SAML logouts: %w", err)
	}

	// 3. Destroy. Only now, once delivery is durably queued in the same
	// transaction: if this rolls back, the notices roll back with it.
	tag, err := tx.Exec(ctx, `
		UPDATE core.sessions
		SET revoked_at = now(), revocation_reason = $3
		WHERE revoked_at IS NULL
		  AND ($1::text[] IS NULL OR sid = ANY($1))
		  AND ($2::uuid IS NULL OR user_id = $2)`,
		sids, nullIf(userID), string(reason))
	if err != nil {
		return nil, fmt.Errorf("revoking sessions: %w", err)
	}

	// Refresh families follow their session, except an offline grant (5.10),
	// which outlives the one session it was given in -- that is what offline
	// means -- and ends with all of them: ending every session somebody has is
	// what is done when the account may be in the wrong hands (a password
	// changed or reset, a factor reset, deactivation, "sign out everywhere"),
	// for the same reason it forgets their remembered devices below. Ending
	// one session is a logout, an expiry, an eviction.
	if _, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families f
		SET revoked_at = now(), revocation_reason = $3
		FROM core.sessions s
		WHERE f.sid = s.sid AND f.revoked_at IS NULL
		  AND ($1::text[] IS NULL OR s.sid = ANY($1))
		  AND ($2::uuid IS NULL OR s.user_id = $2)
		  AND (f.offline_not_after IS NULL OR $2::uuid IS NOT NULL)`,
		sids, nullIf(userID), string(reason)); err != nil {
		return nil, fmt.Errorf("revoking refresh families: %w", err)
	}

	// Ending all of somebody's sessions forgets their remembered devices as
	// well: it is what is done when an account may be in the wrong hands, and
	// a device that skips the second factor is the one thing that would let a
	// stolen password straight back in.
	if userID != "" {
		if _, err := ForgetDevices(ctx, tx, userID, ""); err != nil {
			return nil, err
		}
	}

	return &Terminated{Sessions: int(tag.RowsAffected()), Notices: len(payloads)}, nil
}

func IsSessionLive(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, sid string) (bool, error) {
	var live bool
	err := q.QueryRow(ctx, `
		SELECT s.revoked_at IS NULL
		   AND s.not_after > now()
		   AND u.status = 'active'
		   AND `+OrgInService("u.org_id")+`
		FROM core.sessions s
		JOIN core.users u ON u.id = s.user_id
		WHERE s.sid = $1`, sid).Scan(&live)
	if err != nil {
		return false, err
	}
	return live, nil
}

// SessionInfo is one live session as the account owner sees it.
//
// No IP address and no raw fingerprint: ASVS V7.5.2 asks that a user can see and
// end their sessions, not that the console builds a location dossier on them.
// The user agent is shown because "Firefox on macOS" is what lets somebody
// recognise which session is which; the acr/amr say how it signed in.
type SessionInfo struct {
	SID       string
	UserAgent string
	ACR       string
	AMR       []string
	AuthTime  time.Time
	CreatedAt time.Time
	NotAfter  time.Time
	Current   bool
}

// ListUserSessions returns a user's live sessions, newest first, marking the one
// that owns currentSID as the current session so the console never offers to end
// the browser the person is looking at without saying so.
func ListUserSessions(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, userID, currentSID string) ([]SessionInfo, error) {
	rows, err := q.Query(ctx, `
		SELECT sid, COALESCE(user_agent,''), acr, amr, auth_time, created_at, not_after
		FROM core.sessions
		WHERE user_id = $1::uuid AND revoked_at IS NULL AND not_after > now()
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	defer rows.Close()

	var out []SessionInfo
	for rows.Next() {
		var s SessionInfo
		if err := rows.Scan(&s.SID, &s.UserAgent, &s.ACR, &s.AMR,
			&s.AuthTime, &s.CreatedAt, &s.NotAfter); err != nil {
			return nil, err
		}
		s.Current = s.SID == currentSID
		out = append(out, s)
	}
	return out, rows.Err()
}

// BrowserSession is the session a browser's cookie names, with what the pages
// after it ask of one, so that they need not each go back for it.
type BrowserSession struct {
	SID, UserID, OrgID string
	// Live is whether it can be used. A session that cannot is still described:
	// to a page it is not the same as there being none.
	Live     bool
	AuthTime time.Time
	AMR      []string
}

// ResolveBrowserSession finds the session a browser's cookie names, among the
// sessions of instanceID's organisations (6.12): another instance's session is
// no session here, as its cookie is never sent here by a browser that was not
// handed it by someone else. No such session is the zero value and no error.
func ResolveBrowserSession(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, cookieHash []byte, instanceID string) (BrowserSession, error) {
	// A browser presenting its cookie is a use of the session, recorded in the
	// same statement (see sessionlifetime.go): liveness is decided from the
	// row as it was, and the deadline moves for a live one only.
	var found BrowserSession
	err := q.QueryRow(ctx, `
		WITH found AS (
			SELECT s.sid, s.user_id, s.org_id, s.auth_time, s.amr,
			       s.revoked_at IS NULL AND s.not_after > now() AND u.status = 'active'
			       AND `+OrgInService("u.org_id")+` AS live
			FROM core.sessions s
			JOIN core.users u ON u.id = s.user_id
			WHERE s.cookie_hash = $1 AND `+InInstance("s.org_id", "$2")+`),
		touched AS (
			UPDATE core.sessions t SET `+touchSet+`
			  FROM core.organizations o, found f
			 WHERE t.sid = f.sid AND f.live AND o.id = t.org_id AND `+touchDue+`)
		SELECT sid, user_id::text, org_id::text, auth_time, amr, live FROM found`, cookieHash, instanceID).
		Scan(&found.SID, &found.UserID, &found.OrgID, &found.AuthTime, &found.AMR, &found.Live)
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserSession{}, nil
	}
	if err != nil {
		return BrowserSession{}, err
	}
	return found, nil
}

// ResolveSessionCookie is ResolveBrowserSession for a caller that wants only
// which session it is and whether it can be used.
func ResolveSessionCookie(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, cookieHash []byte, instanceID string) (sid string, live bool, err error) {
	found, err := ResolveBrowserSession(ctx, q, cookieHash, instanceID)
	return found.SID, found.Live, err
}

// TouchSessionClient records that a relying party saw this session, so logout can
// enumerate it later. Idempotent.
func TouchSessionClient(ctx context.Context, tx pgx.Tx, sid, clientID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)
		ON CONFLICT (sid, client_id) DO NOTHING`, sid, clientID)
	return err
}

// SweepExpiredSessions ends sessions past not_after, through the same single
// termination path so relying parties are notified. SKIP LOCKED, so a session a
// person is signing out of at this moment waits for neither of them.
func SweepExpiredSessions(ctx context.Context, tx pgx.Tx, limit int) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT sid FROM core.sessions
		WHERE revoked_at IS NULL AND not_after <= now()
		ORDER BY not_after LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return 0, err
	}
	sids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	if _, err := TerminateEachSession(ctx, tx, sids, ReasonExpired); err != nil {
		return 0, err
	}
	return len(sids), nil
}

func nullIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var _ = time.Now
