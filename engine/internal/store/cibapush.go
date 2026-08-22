package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
)

// CIBAPushTopicName is the outbox topic. Kept here as well as in the outbox
// package so the store can park a row without importing the worker.
const CIBAPushTopicName = "ciba_push"

// SealContextCIBAPush binds the sealed payload to its purpose, so a blob lifted
// from this topic cannot be opened as anything else.
const SealContextCIBAPush = "ciba_push_payload"

// CIBAPush is one token delivery owed to a client registered for push.
//
// CIBA Core 1.0 §10.3: the OP sends the TOKENS themselves to the notification
// endpoint, and §11 forbids the client from calling the token endpoint at all. So
// unlike ping, this payload is a credential in its own right.
type CIBAPush struct {
	Endpoint  string `json:"endpoint"`
	Token     string `json:"token"`
	AuthReqID string `json:"auth_req_id"`
	ClientID  string `json:"client_id"`
	// Sealed is the token response, encrypted under the root key.
	//
	// # Why it is sealed and why it is here at all
	//
	// It has to persist: delivery is retried, and minting per attempt would issue
	// a DIFFERENT token set each time -- so a client that received the third
	// attempt would hold tokens while the first two sets were live, valid and
	// unreachable by anybody. Minting once and keeping the result is the only
	// version of retry that is correct.
	//
	// Keeping it means an access token and possibly a refresh token sit in a
	// queue table between approval and delivery. The worker's own comment already
	// argues against exactly that for somebody else's bearer token: "a queue
	// table is the last place a third party's credential should sit, and rows
	// there outlive the delivery by design". It applies at least as strongly to
	// ours.
	//
	// So it is sealed with the root key -- which is not in the database -- and the
	// worker, which holds that key for the same reason, opens it at delivery.
	Sealed []byte `json:"sealed,omitempty"`
}

// QueueCIBAPush parks a delivery for a request nobody has decided yet.
//
// Queued at creation for the same reason as ping: the notification carries the
// `auth_req_id` the client holds, and this server stores only its hash, so at
// approval time the plaintext no longer exists.
func QueueCIBAPush(ctx context.Context, db *pgxpool.Pool, requestID, clientID,
	endpoint, notificationToken, authReqID string) error {

	if endpoint == "" || notificationToken == "" {
		return fmt.Errorf("client %q is registered for push delivery but the request "+
			"carries no endpoint or notification token", clientID)
	}
	payload, err := json.Marshal(CIBAPush{
		Endpoint: endpoint, Token: notificationToken,
		AuthReqID: authReqID, ClientID: clientID,
	})
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload, next_attempt_at, subject_key)
		VALUES ($1, $2, 'infinity', $3)`, CIBAPushTopicName, payload, requestID); err != nil {
		return fmt.Errorf("parking a CIBA push: %w", err)
	}
	return nil
}

// ReleaseCIBAPush seals a token response into the parked row and makes it
// deliverable.
//
// The two happen in ONE statement. Written as a read, a seal and a write, a
// crash between them would leave a row that is either releasable with no tokens
// -- delivering an empty body to a client that will never ask again -- or sealed
// and parked forever.
func ReleaseCIBAPush(ctx context.Context, db *pgxpool.Pool, root *keys.RootKey,
	requestID string, tokenResponse any) (bool, error) {

	if root == nil {
		// Refused rather than stored in the clear. Push is the one topic whose
		// payload is a live credential, and "we could not seal it so we wrote it
		// down anyway" is not a degraded mode worth having.
		return false, fmt.Errorf("no root key is configured, so the token response " +
			"cannot be sealed for delivery")
	}
	body, err := json.Marshal(tokenResponse)
	if err != nil {
		return false, fmt.Errorf("encoding the push token response: %w", err)
	}
	sealed, err := root.Seal(body, SealContextCIBAPush)
	if err != nil {
		return false, fmt.Errorf("sealing the push token response: %w", err)
	}

	// jsonb_set rather than rewriting the payload: the endpoint, notification
	// token and auth_req_id were captured at request time and must survive.
	tag, err := db.Exec(ctx, `
		UPDATE core.outbox
		SET payload = jsonb_set(payload::jsonb, '{sealed}', to_jsonb($3::text))::json,
		    next_attempt_at = now()
		WHERE topic = $1 AND subject_key = $2 AND delivered_at IS NULL`,
		CIBAPushTopicName, requestID, encodeSealed(sealed))
	if err != nil {
		return false, fmt.Errorf("releasing a CIBA push: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DiscardCIBAPush drops a parked delivery.
//
// Used when the request was denied or expired: §10.3 defines the push callback as
// a TOKEN delivery, and there are no tokens to send. A ping client is notified of
// a refusal because it would otherwise poll forever; a push client has nothing to
// wait for and nothing to stop doing.
func DiscardCIBAPush(ctx context.Context, db *pgxpool.Pool, requestID string) error {
	_, err := db.Exec(ctx, `
		DELETE FROM core.outbox
		WHERE topic = $1 AND subject_key = $2 AND delivered_at IS NULL`,
		CIBAPushTopicName, requestID)
	return err
}

// encodeSealed renders sealed bytes for storage in a JSON payload.
//
// base64 rather than raw: the payload column is JSON, and ciphertext is not
// valid UTF-8. Go's encoding/json would replace the invalid bytes with U+FFFD
// on the way in, and the value would fail to decrypt on the way out with an
// authentication error that names nothing.
func encodeSealed(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
