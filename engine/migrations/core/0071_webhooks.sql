-- Event subscriptions: telling other systems what happened here.
--
-- # Why this reuses the outbox rather than posting inline
--
-- An event that fires an HTTP request from the request path makes every sign-in
-- as slow and as reliable as the slowest subscriber. Worse, a subscriber that is
-- down loses the event entirely, and nobody finds out -- which is the failure
-- mode of every "notification webhook" that is really a goroutine and a hope.
--
-- The outbox already has attempts, capped backoff, and parking for deliveries
-- that gave up, because back-channel logout needed exactly that. Events go
-- through the same machinery, so an undelivered event is a row somebody can see
-- rather than a log line nobody read.
--
-- # Why deliveries are signed
--
-- A webhook is an instruction arriving at another system claiming to come from
-- the identity provider. Unsigned, it is an instruction from whoever can reach
-- that URL. Each delivery carries an HMAC over the timestamp AND the body, so a
-- subscriber can verify both origin and freshness.

CREATE TABLE core.event_subscriptions (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    display_name text       NOT NULL,
    url          text       NOT NULL,
    -- https only, and not a bare host: an event carries the shape of the
    -- organisation, and sending it in clear to be read on the wire undoes the
    -- reason for signing it.
    CONSTRAINT event_subscription_url_is_https CHECK (url LIKE 'https://%'),

    -- The signing secret, sealed with the root key. Stored so it can be sent to
    -- the subscriber's verifier, which is what makes verification possible; the
    -- sealing is what stops a database copy becoming a licence to forge events.
    secret_sealed bytea     NOT NULL,

    -- Which events. Empty means all of them, which is a choice an operator makes
    -- deliberately rather than a default they inherit.
    event_types text[]      NOT NULL DEFAULT '{}',

    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Set when deliveries have been failing long enough to give up. Visible, so
    -- a subscription that stopped working is a fact rather than a silence.
    disabled_at timestamptz,
    disabled_reason text,

    UNIQUE (org_id, display_name)
);

CREATE INDEX event_subscriptions_live ON core.event_subscriptions (org_id)
    WHERE enabled AND disabled_at IS NULL;

ALTER TABLE core.event_subscriptions ENABLE ROW LEVEL SECURITY;

-- The engine hatch. Without core.is_engine() the engine reads zero rows, and a
-- superuser development DSN bypasses RLS entirely, so the failure is invisible
-- until deployment. See 0058.
CREATE POLICY event_subscriptions_org ON core.event_subscriptions
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON core.event_subscriptions TO signari_engine;

-- Delivery history, so "did they get it" has an answer.
CREATE TABLE core.event_deliveries (
    id              bigserial   PRIMARY KEY,
    subscription_id uuid        NOT NULL REFERENCES core.event_subscriptions(id) ON DELETE CASCADE,
    org_id          uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    event_type      text        NOT NULL,
    outbox_id       bigint,
    attempts        integer     NOT NULL DEFAULT 0,
    status_code     integer,
    last_error      text,
    delivered_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX event_deliveries_recent
    ON core.event_deliveries (org_id, created_at DESC);
CREATE INDEX event_deliveries_failed
    ON core.event_deliveries (subscription_id, created_at DESC)
    WHERE delivered_at IS NULL;

ALTER TABLE core.event_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY event_deliveries_org ON core.event_deliveries
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT, UPDATE ON core.event_deliveries TO signari_engine;
GRANT USAGE, SELECT ON SEQUENCE core.event_deliveries_id_seq TO signari_engine;
