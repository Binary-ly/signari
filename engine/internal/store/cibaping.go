package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CIBAPing is one notification owed to a client registered for ping delivery.
//
// CIBA Core 1.0 §10: once the authentication result exists, the OP notifies the
// client, which then collects the token from the token endpoint exactly as in
// poll mode. The body carries the `auth_req_id` and **not** the token — that is
// what separates ping from push, and why the client must still authenticate to
// redeem it.
type CIBAPing struct {
	Endpoint  string `json:"endpoint"`
	Token     string `json:"token"`
	AuthReqID string `json:"auth_req_id"`
	ClientID  string `json:"client_id"`
}

// QueueCIBAPing parks a notification for a request that has not been decided yet.
//
// # Why it is queued at creation rather than at approval
//
// The notification body must carry the `auth_req_id` the client holds, and this
// server stores only its HASH — deliberately, because it is a bearer credential
// and a stolen database should not yield working ones. So at approval time the
// value no longer exists to send.
//
// Writing it onto the request row instead would undo that: a long-lived row would
// carry a usable credential in plaintext for the whole lifetime of the request.
// Parking it in the outbox keeps the exposure to the delivery attempt — the row
// is deleted when the notification succeeds, and expires with the request when it
// does not — and confines it to ping clients, who are the only ones for whom the
// value has to survive at all.
//
// `next_attempt_at = 'infinity'` is what parks it: the drain claims rows with
// `next_attempt_at <= now()`, so nothing is sent until ReleaseCIBAPing moves it.
func QueueCIBAPing(ctx context.Context, db *pgxpool.Pool, requestID, clientID,
	endpoint, notificationToken, authReqID string) error {

	if endpoint == "" || notificationToken == "" {
		return fmt.Errorf("client %q is registered for ping delivery but the request "+
			"carries no endpoint or notification token", clientID)
	}
	payload, err := json.Marshal(CIBAPing{
		Endpoint: endpoint, Token: notificationToken,
		AuthReqID: authReqID, ClientID: clientID,
	})
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload, next_attempt_at, subject_key)
		VALUES ('ciba_ping', $1, 'infinity', $2)`, payload, requestID); err != nil {
		return fmt.Errorf("parking a CIBA ping: %w", err)
	}
	return nil
}

// ReleaseCIBAPing makes a parked notification eligible for delivery.
//
// Called once the person has decided, whichever way they decided: §10 has the OP
// notify on the result, not on approval, and a client left polling after a denial
// is exactly the wait ping mode exists to remove.
//
// Returns whether a row was released, so a caller can distinguish "poll client,
// nothing parked" from "released".
func ReleaseCIBAPing(ctx context.Context, db *pgxpool.Pool, requestID string) (bool, error) {
	tag, err := db.Exec(ctx, `
		UPDATE core.outbox SET next_attempt_at = now()
		WHERE topic = 'ciba_ping' AND subject_key = $1 AND delivered_at IS NULL`,
		requestID)
	if err != nil {
		return false, fmt.Errorf("releasing a CIBA ping: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
