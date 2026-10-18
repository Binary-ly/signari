package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
)

// CIBAPing is one notification owed to a client registered for ping delivery.
//
// CIBA Core 1.0 §10: once the authentication result exists, the OP notifies the
// client, which then collects the token from the token endpoint exactly as in
// poll mode. The body carries the `auth_req_id` and **not** the token — that is
// what separates ping from push, and why the client must still authenticate to
// redeem it.
type CIBAPing struct {
	Endpoint string `json:"endpoint"`
	ClientID string `json:"client_id"`
	// Credentials is the notification token and the auth_req_id, sealed under
	// the root key. See SealContextCIBACredentials.
	Credentials []byte `json:"credentials,omitempty"`
	// Token and AuthReqID are filled by Open. A row parked by a build before
	// migration 0132 carries them here in the clear, and still delivers.
	Token     string `json:"token,omitempty"`
	AuthReqID string `json:"auth_req_id,omitempty"`
}

// Open unseals Credentials into Token and AuthReqID.
func (p *CIBAPing) Open(root *keys.RootKey) error {
	return openCIBACredentials(root, p.Credentials, &p.Token, &p.AuthReqID)
}

// SealContextCIBACredentials binds the two credentials a parked CIBA delivery
// carries to their purpose.
//
// They are sealed because both are live until the delivery happens: the
// notification token is the client's own bearer credential, which it accepts
// from whoever presents it, and the auth_req_id is the one value this server
// otherwise keeps only as a hash. A queue row is short-lived, and a database
// backup is not. The endpoint and client id stay readable, for the log line a
// failed delivery writes and for an operator looking at the queue.
const SealContextCIBACredentials = "ciba_delivery_credentials"

type cibaCredentials struct {
	Token     string `json:"token"`
	AuthReqID string `json:"auth_req_id"`
}

func sealCIBACredentials(root *keys.RootKey, token, authReqID string) ([]byte, error) {
	if root == nil {
		// Refused rather than written in the clear, as for the push tokens.
		return nil, fmt.Errorf("no root key is configured, so the notification " +
			"token cannot be sealed for delivery")
	}
	raw, err := json.Marshal(cibaCredentials{Token: token, AuthReqID: authReqID})
	if err != nil {
		return nil, err
	}
	return root.Seal(raw, SealContextCIBACredentials)
}

func openCIBACredentials(root *keys.RootKey, sealed []byte, token, authReqID *string) error {
	if len(sealed) == 0 {
		if *token == "" || *authReqID == "" {
			return fmt.Errorf("a parked CIBA delivery carries no credentials")
		}
		return nil // parked before 0132, in the clear
	}
	if root == nil {
		return fmt.Errorf("no root key is configured, so a sealed CIBA delivery cannot be opened")
	}
	raw, err := root.Open(sealed, SealContextCIBACredentials)
	if err != nil {
		return fmt.Errorf("unsealing CIBA delivery credentials: %w", err)
	}
	var c cibaCredentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("decoding CIBA delivery credentials: %w", err)
	}
	*token, *authReqID = c.Token, c.AuthReqID
	return nil
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
// value has to survive at all. It is sealed there too (SealContextCIBACredentials),
// because a backup of the queue outlives the row.
//
// `next_attempt_at = 'infinity'` is what parks it: the drain claims rows with
// `next_attempt_at <= now()`, so nothing is sent until ReleaseCIBAPing moves it.
func QueueCIBAPing(ctx context.Context, db *pgxpool.Pool, root *keys.RootKey, requestID,
	clientID, endpoint, notificationToken, authReqID string) error {

	if endpoint == "" || notificationToken == "" {
		return fmt.Errorf("client %q is registered for ping delivery but the request "+
			"carries no endpoint or notification token", clientID)
	}
	sealed, err := sealCIBACredentials(root, notificationToken, authReqID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(CIBAPing{
		Endpoint: endpoint, ClientID: clientID, Credentials: sealed,
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
