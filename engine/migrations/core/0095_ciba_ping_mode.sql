ALTER TABLE core.clients
    ADD COLUMN backchannel_token_delivery_mode text NOT NULL DEFAULT 'poll',
    ADD COLUMN backchannel_client_notification_endpoint text;

ALTER TABLE core.clients
    ADD CONSTRAINT clients_delivery_mode_known
    CHECK (backchannel_token_delivery_mode IN ('poll', 'ping'));

-- §7.3: ping mode is meaningless without somewhere to ping. Enforced in the
-- schema rather than only in the handler, because a client configured for ping
-- with no endpoint would accept a backchannel request and then have nowhere to
-- deliver the result -- the same silent-success shape the logout notice code
-- refuses to mint.
ALTER TABLE core.clients
    ADD CONSTRAINT clients_ping_needs_an_endpoint
    CHECK (
        backchannel_token_delivery_mode <> 'ping'
        OR backchannel_client_notification_endpoint IS NOT NULL
    );

-- The notification token belongs to the REQUEST, not the client: §7.1 has the
-- client supply a fresh one per backchannel request, and it is the credential we
-- present when calling back, so reusing one across requests would let a client
-- that saw one notification authenticate every later one.
ALTER TABLE core.device_authorizations
    ADD COLUMN client_notification_token text;

-- A correlation key for outbox rows that must be found again before delivery.
--
-- Back-channel logout has never needed one: a logout notice is queued ready to
-- send and never looked up again. A CIBA ping is parked at creation and released
-- when the person decides, so it has to be findable in between. Nullable, because
-- every existing topic leaves it empty.
ALTER TABLE core.outbox ADD COLUMN subject_key text;

CREATE INDEX outbox_subject_key_idx ON core.outbox (topic, subject_key)
    WHERE subject_key IS NOT NULL AND delivered_at IS NULL;
