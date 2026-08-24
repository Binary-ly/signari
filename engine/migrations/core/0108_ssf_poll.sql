-- Poll-based delivery of Security Event Tokens (RFC 8936).
--
-- Push delivery (RFC 8935, already here) POSTs each SET to an endpoint the
-- receiver exposes. That fails a receiver that cannot accept inbound HTTPS -- one
-- behind a firewall, or an agent with no public address -- which is most of the
-- receivers that most want continuous signals. Poll inverts it: the receiver
-- makes an authenticated request TO us and pulls the SETs waiting for it, then
-- acknowledges the ones it has stored so we can drop them.
--
-- The two are per-stream, not per-deployment: a stream is push or poll, and a
-- push stream never has a row in the queue below.

-- delivery_method distinguishes the two. Default 'push' so every existing stream
-- keeps behaving exactly as it did.
ALTER TABLE core.ssf_streams
    ADD COLUMN delivery_method text NOT NULL DEFAULT 'push'
        CHECK (delivery_method IN ('push', 'poll'));

-- endpoint_url was NOT NULL with an https-only CHECK, which silently assumed
-- push. A poll stream has no push endpoint at all, so the column becomes optional
-- and the rule moves onto delivery_method: a push stream MUST carry an https
-- endpoint, a poll stream MUST NOT carry one (an endpoint nobody reads is a
-- misconfiguration waiting to look like a delivery bug).
ALTER TABLE core.ssf_streams ALTER COLUMN endpoint_url DROP NOT NULL;
ALTER TABLE core.ssf_streams DROP CONSTRAINT ssf_streams_https;
ALTER TABLE core.ssf_streams
    ADD CONSTRAINT ssf_streams_delivery CHECK (
        (delivery_method = 'push' AND endpoint_url LIKE 'https://%')
        OR (delivery_method = 'poll' AND endpoint_url IS NULL));

-- The SETs waiting for a poll stream. One row per event until the receiver polls
-- and acknowledges it; a push stream never writes here.
CREATE TABLE core.ssf_poll_queue (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    stream_id  uuid        NOT NULL REFERENCES core.ssf_streams(id) ON DELETE CASCADE,

    -- The SET's jti, assigned when the event is queued rather than when it is
    -- minted, so the identifier a receiver acknowledges is stable across every
    -- redelivery of the same undelivered event. Unique per stream so an ack names
    -- exactly one queued SET.
    jti        text        NOT NULL,
    event_type text        NOT NULL,

    -- What the SET is minted from -- subject, sid, reason. Minting happens at poll
    -- time (the signing key lives in the request path, as it does for push at
    -- delivery time), so the payload here is the event, not the signed token.
    payload    jsonb       NOT NULL,

    queued_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (stream_id, jti)
);

-- Poll and ack both scan a single stream oldest-first.
CREATE INDEX ssf_poll_queue_stream ON core.ssf_poll_queue (stream_id, id);

ALTER TABLE core.ssf_poll_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.ssf_poll_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY ssf_poll_queue_org_isolation ON core.ssf_poll_queue
    USING (core.is_engine() OR EXISTS (
        SELECT 1 FROM core.ssf_streams st
        WHERE st.id = ssf_poll_queue.stream_id AND st.org_id = core.current_org_id()))
    WITH CHECK (core.is_engine() OR EXISTS (
        SELECT 1 FROM core.ssf_streams st
        WHERE st.id = ssf_poll_queue.stream_id AND st.org_id = core.current_org_id()));

-- The janitor purges events that were queued but never polled, so an abandoned
-- receiver cannot grow the table without bound.
GRANT SELECT, DELETE ON core.ssf_poll_queue TO signari_maintenance;
