package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/safedial"
)

// Event subscriptions: telling other systems what happened here.
//
// # Why an event is enqueued rather than posted
//
// Posting from the request path makes every sign-in as slow and as reliable as
// the slowest subscriber, and an event whose subscriber was down is simply lost.
// The outbox already has attempts, capped backoff and parking, because
// back-channel logout needed them. Events use the same machinery, so an
// undelivered event is a row somebody can see rather than a log line nobody read.
//
// # Why the fan-out happens at enqueue time
//
// One outbox row per (event, subscriber), not one per event. A slow subscriber
// must not hold up a fast one, and a permanently failing one must be able to be
// parked without parking the event for everybody else.

// Subscription is one place events are sent.
type Subscription struct {
	ID          string
	OrgID       string
	DisplayName string
	URL         string
	EventTypes  []string
	Secret      string // only populated when freshly created
}

// EventEnvelope is the wire format. Versioned, because a shape that changes
// without saying so breaks every subscriber at once and none of them know why.
type EventEnvelope struct {
	Version       int            `json:"version"`
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	OccurredAt    string         `json:"occurred_at"`
	OrgID         string         `json:"org_id"`
	SubjectID     string         `json:"subject_id,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Detail        map[string]any `json:"detail,omitempty"`
}

// webhookJob is what the outbox carries.
type webhookJob struct {
	SubscriptionID string        `json:"subscription_id"`
	DeliveryID     int64         `json:"delivery_id"`
	URL            string        `json:"url"`
	OrgID          string        `json:"org_id"`
	Envelope       EventEnvelope `json:"envelope"`
}

// WebhookTopic is the outbox topic events use.
const WebhookTopic = "event"

// CreateSubscription registers a subscriber and returns its signing secret.
//
// The secret is returned ONCE, here. Storing it sealed and never showing it
// again means a database copy is not a licence to forge events -- and an
// operator who loses it rotates rather than reads.
func CreateSubscription(ctx context.Context, tx pgx.Tx, root *keys.RootKey,
	orgID, name, url string, eventTypes []string) (Subscription, error) {

	var sub Subscription
	if err := safedial.CheckURL(url); err != nil {
		return sub, err
	}
	if err := CheckEventTypes(eventTypes); err != nil {
		return sub, err
	}

	secret, sealed, err := newSubscriptionSecret(root)
	if err != nil {
		return sub, err
	}
	if eventTypes == nil {
		eventTypes = []string{}
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO core.event_subscriptions
			(org_id, display_name, url, secret_sealed, event_types)
		VALUES ($1::uuid, $2, $3, $4, $5)
		RETURNING id::text`, orgID, name, url, sealed, eventTypes).Scan(&sub.ID)
	if err != nil {
		return sub, err
	}
	sub.OrgID, sub.DisplayName, sub.URL = orgID, name, url
	sub.EventTypes, sub.Secret = eventTypes, secret
	return sub, nil
}

// ErrUnknownEventType is a name no recorded event carries, so a subscription to
// it would receive nothing, ever, and look configured.
var ErrUnknownEventType = errors.New("no event of that type is recorded")

// CheckEventTypes refuses a name that is not in audit.EventTypes, suggesting
// the one it was most likely meant to be.
func CheckEventTypes(types []string) error {
	for _, t := range types {
		if slices.Contains(audit.InstanceEventTypes, t) {
			return fmt.Errorf("%w for an organisation: %q concerns the instance and is delivered "+
				"to no subscription; read it from the audit trail", ErrUnknownEventType, t)
		}
		if audit.IsEventType(t) {
			continue
		}
		best, bestLen := "", 0
		for _, known := range audit.EventTypes {
			n := 0
			for n < len(t) && n < len(known) && t[n] == known[n] {
				n++
			}
			if n > bestLen {
				best, bestLen = known, n
			}
		}
		if strings.Contains(t[:bestLen], ".") {
			return fmt.Errorf("%w: %q; did you mean %q? docs/events.md lists every type",
				ErrUnknownEventType, t, best)
		}
		return fmt.Errorf("%w: %q; docs/events.md lists every type", ErrUnknownEventType, t)
	}
	return nil
}

func newSubscriptionSecret(root *keys.RootKey) (secret string, sealed []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret = "whsec_" + base64.RawURLEncoding.EncodeToString(raw)
	sealed, err = root.Seal([]byte(secret), sealContextSubscriptionSecret)
	if err != nil {
		return "", nil, fmt.Errorf("sealing the signing secret: %w", err)
	}
	return secret, sealed, nil
}

// RemoveSubscription deletes one by name, and with it its delivery history. A
// delivery already queued is closed as delivered when the worker finds its
// subscription gone (ClaimWebhooks).
// SubscriptionStatus is one subscription as an operator sees it: never its
// secret, and how its deliveries are going.
type SubscriptionStatus struct {
	ID, Name, URL  string
	EventTypes     []string
	Enabled        bool
	DisabledReason string
	Delivered      int
	Outstanding    int
}

// OrgSubscriptions lists an organisation's subscriptions, oldest first.
func OrgSubscriptions(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]SubscriptionStatus, error) {
	rows, err := q.Query(ctx, `
		SELECT s.id::text, s.display_name, s.url, s.event_types, s.enabled, COALESCE(s.disabled_reason, ''),
		       (SELECT count(*) FROM core.event_deliveries d
		         WHERE d.subscription_id = s.id AND d.delivered_at IS NOT NULL),
		       (SELECT count(*) FROM core.event_deliveries d
		         WHERE d.subscription_id = s.id AND d.delivered_at IS NULL)
		  FROM core.event_subscriptions s
		 WHERE s.org_id = $1::uuid
		 ORDER BY s.created_at, s.id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubscriptionStatus{}
	for rows.Next() {
		var s SubscriptionStatus
		if err := rows.Scan(&s.ID, &s.Name, &s.URL, &s.EventTypes, &s.Enabled, &s.DisabledReason,
			&s.Delivered, &s.Outstanding); err != nil {
			return nil, err
		}
		if s.EventTypes == nil {
			s.EventTypes = []string{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ErrSubscriptionUnknown is a subscription name the organisation does not
// have; each change below answers it as subscriptionNamed, which says which.
var ErrSubscriptionUnknown = errors.New("no such subscription")

type subscriptionNamed struct{ name string }

func (e subscriptionNamed) Error() string {
	return fmt.Sprintf("no subscription named %q in this organisation", e.name)
}

func (e subscriptionNamed) Is(target error) bool { return target == ErrSubscriptionUnknown }

func RemoveSubscription(ctx context.Context, tx pgx.Tx, orgID, name string) (bool, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.event_subscriptions
		WHERE org_id = $1::uuid AND display_name = $2`, orgID, name)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RotateSubscriptionSecret replaces a subscription's signing secret and returns
// the new one, the one time it is shown. Deliveries signed from now on use it,
// including retries of ones already queued: the secret is read at delivery.
func RotateSubscriptionSecret(ctx context.Context, tx pgx.Tx, root *keys.RootKey,
	orgID, name string) (string, error) {
	secret, sealed, err := newSubscriptionSecret(root)
	if err != nil {
		return "", err
	}
	tag, err := tx.Exec(ctx, `UPDATE core.event_subscriptions SET secret_sealed = $3
		WHERE org_id = $1::uuid AND display_name = $2`, orgID, name, sealed)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", subscriptionNamed{name}
	}
	return secret, nil
}

// EnableSubscription switches one back on after DisableSubscription gave up on
// it, clearing the reason. Events recorded while it was off are not replayed.
func EnableSubscription(ctx context.Context, tx pgx.Tx, orgID, name string) error {
	tag, err := tx.Exec(ctx, `UPDATE core.event_subscriptions
		   SET enabled = true, disabled_at = NULL, disabled_reason = NULL
		 WHERE org_id = $1::uuid AND display_name = $2`, orgID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return subscriptionNamed{name}
	}
	return nil
}

// TestEventType is what `signari events test` sends. Not an audited type, so no
// subscription filter selects it: it goes to the one subscription named.
const TestEventType = "signari.test"

// SendTestEvent queues one signed delivery of TestEventType to a subscription,
// through the outbox as every delivery goes, so it tests the path real events
// take, including the worker.
func SendTestEvent(ctx context.Context, tx pgx.Tx, orgID, name string) (string, error) {
	var id, url string
	if err := tx.QueryRow(ctx, `SELECT id::text, url FROM core.event_subscriptions
		WHERE org_id = $1::uuid AND display_name = $2`, orgID, name).Scan(&id, &url); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", subscriptionNamed{name}
		}
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	env := EventEnvelope{Version: 1, ID: "ev_" + hex.EncodeToString(raw), Type: TestEventType,
		OccurredAt: time.Now().UTC().Format(time.RFC3339), OrgID: orgID,
		Detail: map[string]any{"subscription": name}}
	return env.ID, queueDelivery(ctx, tx, id, url, env)
}

// queueDelivery writes one delivery and its outbox row, in the caller's
// transaction.
func queueDelivery(ctx context.Context, tx pgx.Tx, subscriptionID, url string, env EventEnvelope) error {
	var deliveryID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.event_deliveries (subscription_id, org_id, event_type)
		VALUES ($1::uuid, $2::uuid, $3) RETURNING id`,
		subscriptionID, env.OrgID, env.Type).Scan(&deliveryID); err != nil {
		return err
	}
	payload, err := json.Marshal(webhookJob{
		SubscriptionID: subscriptionID, DeliveryID: deliveryID,
		URL: url, OrgID: env.OrgID, Envelope: env,
	})
	if err != nil {
		return err
	}
	var outboxID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.outbox (topic, payload) VALUES ($1, $2) RETURNING id`,
		WebhookTopic, payload).Scan(&outboxID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE core.event_deliveries SET outbox_id = $2 WHERE id = $1`, deliveryID, outboxID)
	return err
}

// PublishEvent fans an event out to every subscriber that wants it.
//
// Takes the transaction the event itself was written in. That is the whole point
// of an outbox: the event and the intent to deliver it commit together, so there
// is no window where one exists without the other.
func PublishEvent(ctx context.Context, tx pgx.Tx, env EventEnvelope) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, url
		  FROM core.event_subscriptions
		 WHERE org_id = $1::uuid AND enabled AND disabled_at IS NULL
		   -- An empty list means every event. Matching is exact rather than by
		   -- prefix: "login" must not quietly subscribe somebody to
		   -- "login.failed" as well.
		   AND (cardinality(event_types) = 0 OR $2 = ANY (event_types))`,
		env.OrgID, env.Type)
	if err != nil {
		return 0, err
	}
	type target struct{ id, url string }
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.url); err != nil {
			rows.Close()
			return 0, err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, t := range targets {
		if err := queueDelivery(ctx, tx, t.id, t.url, env); err != nil {
			return 0, err
		}
	}
	return len(targets), nil
}

// PendingWebhook is one delivery the worker should attempt.
type PendingWebhook struct {
	OutboxID       int64
	Attempts       int
	SubscriptionID string
	DeliveryID     int64
	URL            string
	OrgID          string
	Envelope       EventEnvelope
	Secret         string
	Body           []byte
}

// ClaimWebhooks takes a batch, locking them against other workers.
func ClaimWebhooks(ctx context.Context, tx pgx.Tx, root *keys.RootKey, limit int) (
	[]PendingWebhook, error) {

	rows, err := tx.Query(ctx, `
		SELECT o.id, o.attempts, o.payload
		  FROM core.outbox o
		 WHERE o.topic = $1 AND o.delivered_at IS NULL AND o.next_attempt_at <= now()
		 ORDER BY o.next_attempt_at
		 -- SKIP LOCKED, so two engines draining at once take different rows
		 -- rather than one waiting behind the other.
		 FOR UPDATE SKIP LOCKED
		 LIMIT $2`, WebhookTopic, limit)
	if err != nil {
		return nil, err
	}
	type claimed struct {
		id       int64
		attempts int
		job      webhookJob
	}
	var found []claimed
	for rows.Next() {
		var c claimed
		var raw []byte
		if err := rows.Scan(&c.id, &c.attempts, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &c.job); err != nil {
			rows.Close()
			return nil, err
		}
		found = append(found, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]PendingWebhook, 0, len(found))
	for _, c := range found {
		var sealed []byte
		var enabled bool
		if err := tx.QueryRow(ctx, `
			SELECT secret_sealed, enabled AND disabled_at IS NULL
			  FROM core.event_subscriptions WHERE id = $1::uuid`,
			c.job.SubscriptionID).Scan(&sealed, &enabled); err != nil {
			if err == pgx.ErrNoRows {
				// The subscription was deleted while the event was queued. Mark
				// it delivered rather than retrying forever against nothing.
				if _, derr := tx.Exec(ctx,
					`UPDATE core.outbox SET delivered_at = now(),
					        last_error = 'subscription deleted' WHERE id = $1`,
					c.id); derr != nil {
					return nil, derr
				}
				continue
			}
			return nil, err
		}
		if !enabled {
			if _, derr := tx.Exec(ctx,
				`UPDATE core.outbox SET delivered_at = now(),
				        last_error = 'subscription disabled' WHERE id = $1`, c.id); derr != nil {
				return nil, derr
			}
			continue
		}
		secret, err := root.Open(sealed, sealContextSubscriptionSecret)
		if err != nil {
			return nil, fmt.Errorf("unsealing a subscription secret: %w", err)
		}
		body, err := json.Marshal(c.job.Envelope)
		if err != nil {
			return nil, err
		}
		out = append(out, PendingWebhook{
			OutboxID: c.id, Attempts: c.attempts,
			SubscriptionID: c.job.SubscriptionID, DeliveryID: c.job.DeliveryID,
			URL: c.job.URL, OrgID: c.job.OrgID, Envelope: c.job.Envelope,
			Secret: string(secret), Body: body,
		})
	}
	return out, nil
}

// MarkWebhookDelivered closes it out.
func MarkWebhookDelivered(ctx context.Context, tx pgx.Tx, w PendingWebhook, status int) error {
	if _, err := tx.Exec(ctx,
		`UPDATE core.outbox SET delivered_at = now(), attempts = attempts + 1
		  WHERE id = $1`, w.OutboxID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		UPDATE core.event_deliveries
		   SET delivered_at = now(), attempts = attempts + 1, status_code = $2,
		       last_error = NULL
		 WHERE id = $1`, w.DeliveryID, status)
	return err
}

// MarkWebhookFailed schedules a retry, or parks it.
func MarkWebhookFailed(ctx context.Context, tx pgx.Tx, w PendingWebhook,
	status int, reason string, backoff string, giveUp bool) error {

	if giveUp {
		// Parked, not deleted. A delivery that was given up on is an
		// operational fact somebody has to be able to see.
		if _, err := tx.Exec(ctx,
			`UPDATE core.outbox SET attempts = attempts + 1, last_error = $2,
			        next_attempt_at = now() + interval '100 years'
			  WHERE id = $1`, w.OutboxID, reason); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx,
		`UPDATE core.outbox SET attempts = attempts + 1, last_error = $2,
		        next_attempt_at = now() + $3::interval
		  WHERE id = $1`, w.OutboxID, reason, backoff); err != nil {
		return err
	}

	var st *int
	if status > 0 {
		st = &status
	}
	_, err := tx.Exec(ctx, `
		UPDATE core.event_deliveries
		   SET attempts = attempts + 1, status_code = $2, last_error = $3
		 WHERE id = $1`, w.DeliveryID, st, reason)
	return err
}

// DisableSubscription switches one off, with a reason.
//
// Used when deliveries have failed long enough to give up. Visible rather than
// silent: a subscription that stopped working is a fact, and the alternative is
// an operator who believes events are flowing and cannot tell that they are not.
func DisableSubscription(ctx context.Context, e Execer, id, reason string) error {
	_, err := e.Exec(ctx, `
		UPDATE core.event_subscriptions
		   SET enabled = false, disabled_at = now(), disabled_reason = $2
		 WHERE id = $1::uuid AND disabled_at IS NULL`, id, reason)
	return err
}
