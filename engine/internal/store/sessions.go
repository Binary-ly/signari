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

	// 1. Snapshot. Only live sessions: re-revoking an already-revoked session
	// must not re-notify, or an expiry sweep would replay logout storms.
	rows, err := tx.Query(ctx, `
		SELECT s.sid, s.user_id::text, sc.client_id, c.backchannel_logout_uri
		FROM core.sessions s
		JOIN core.session_clients sc ON sc.sid = s.sid
		JOIN core.clients c          ON c.client_id = sc.client_id
		WHERE s.revoked_at IS NULL
		  AND ($1::text IS NULL OR s.sid = $1)
		  AND ($2::uuid IS NULL OR s.user_id = $2)
		  AND c.backchannel_logout_uri IS NOT NULL`,
		nullIf(sid), nullIf(userID))
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
		if sid != "" {
			n.SessionID = gotSID // one session: address it by sid
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
	queued := 0
	for _, n := range notices {
		key := n.ClientID + "|" + n.SessionID + "|" + n.Subject
		if seen[key] {
			continue
		}
		seen[key] = true
		payload, err := json.Marshal(n)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO core.outbox (topic, payload) VALUES ('backchannel_logout', $1)`,
			payload); err != nil {
			return nil, fmt.Errorf("queuing logout notice: %w", err)
		}
		queued++

	}

	// 2b. CAEP security events, queued INDEPENDENTLY of back-channel logout.
	//
	// The first version emitted these inside the loop above -- and that loop only
	// visits clients with a registered `backchannel_logout_uri`. A receiver that
	// subscribed to security events but does not implement back-channel logout
	// got nothing at all, silently. The two are different features for different
	// audiences and neither should be a prerequisite for the other.
	//
	// Queued only for streams that are enabled, asked for THIS event type, and
	// whose client actually participated in the session: a stream is not a
	// licence to learn about every user in the directory.
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
		  AND ($1::text IS NULL OR s.sid = $1)
		  AND ($2::uuid IS NULL OR s.user_id = $2)
		  AND st.status = 'enabled'
		  AND st.delivery_method = 'push'
		  AND $3::text = ANY(st.events_requested)`,
		nullIf(sid), nullIf(userID),
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
			  AND ($1::text IS NULL OR s.sid = $1)
			  AND ($2::uuid IS NULL OR s.user_id = $2)
			  AND st.status = 'enabled'
			  AND st.delivery_method = 'poll'
			  AND $3::text = ANY(st.events_requested)
		) d`,
		nullIf(sid), nullIf(userID),
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		string(reason)); err != nil {
		return nil, fmt.Errorf("queuing CAEP session-revoked events for poll: %w", err)
	}

	// 3. Destroy. Only now, once delivery is durably queued in the same
	// transaction: if this rolls back, the notices roll back with it.
	tag, err := tx.Exec(ctx, `
		UPDATE core.sessions
		SET revoked_at = now(), revocation_reason = $3
		WHERE revoked_at IS NULL
		  AND ($1::text IS NULL OR sid = $1)
		  AND ($2::uuid IS NULL OR user_id = $2)`,
		nullIf(sid), nullIf(userID), string(reason))
	if err != nil {
		return nil, fmt.Errorf("revoking sessions: %w", err)
	}

	// Refresh families follow their session. Leaving them live would let a
	// refresh token outlive the session it was minted under.
	if _, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families f
		SET revoked_at = now(), revocation_reason = $3
		FROM core.sessions s
		WHERE f.sid = s.sid AND f.revoked_at IS NULL
		  AND ($1::text IS NULL OR s.sid = $1)
		  AND ($2::uuid IS NULL OR s.user_id = $2)`,
		nullIf(sid), nullIf(userID), string(reason)); err != nil {
		return nil, fmt.Errorf("revoking refresh families: %w", err)
	}

	return &Terminated{Sessions: int(tag.RowsAffected()), Notices: queued}, nil
}

func IsSessionLive(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, sid string) (bool, error) {
	var live bool
	err := q.QueryRow(ctx, `
		SELECT s.revoked_at IS NULL
		   AND s.not_after > now()
		   AND u.status = 'active'
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

func ResolveSessionCookie(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, cookieHash []byte) (sid string, live bool, err error) {
	err = q.QueryRow(ctx, `
		SELECT s.sid,
		       s.revoked_at IS NULL AND s.not_after > now() AND u.status = 'active'
		FROM core.sessions s
		JOIN core.users u ON u.id = s.user_id
		WHERE s.cookie_hash = $1`, cookieHash).Scan(&sid, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return sid, live, nil
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
// termination path so relying parties are notified.
func SweepExpiredSessions(ctx context.Context, tx pgx.Tx, limit int) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT sid FROM core.sessions
		WHERE revoked_at IS NULL AND not_after <= now()
		ORDER BY not_after LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	var sids []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return 0, err
		}
		sids = append(sids, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, s := range sids {
		if _, err := TerminateSessions(ctx, tx, s, "", ReasonExpired); err != nil {
			return 0, err
		}
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
