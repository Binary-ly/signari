-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0257_sweeps_have_indexes.sql
--
-- What a janitor pass and a sign-in stand on at scale (0.74). A million sessions and five million
-- audit events showed retention reading every session on every pass and the audit head reading
-- the trail, and running a real pass past the planner showed five more sweeps with no index, on
-- tables only empty because nothing had been seeded into them. Each only grows, and a pass runs
-- every minute for as long as the deployment lives. The first organisation of an instance was
-- read and sorted twice per sign-in, a cost in the number of tenants. Partial where the sweep only
-- wants rows already finished with, so that a live row costs no write to any of these.
--
-- Built concurrently, outside a transaction, as 0222's were, so people go on signing in while
-- these build.

CREATE INDEX CONCURRENTLY IF NOT EXISTS sessions_ended_idx
    ON core.sessions (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_token_families_ended_idx
    ON core.refresh_token_families (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_token_families_live_age_idx
    ON core.refresh_token_families (created_at) WHERE revoked_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_delivered_idx
    ON core.outbox (delivered_at) WHERE delivered_at IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS event_deliveries_settled_idx
    ON core.event_deliveries ((COALESCE(delivered_at, created_at)));
CREATE INDEX CONCURRENTLY IF NOT EXISTS ssf_poll_queue_queued_idx
    ON core.ssf_poll_queue (queued_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS trusted_devices_ended_idx
    ON core.trusted_devices ((COALESCE(revoked_at, expires_at)));
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_marks_idx
    ON core.audit_events (event_type, id DESC) WHERE event_type IN ('audit.head_signed', 'audit.archived');
CREATE INDEX CONCURRENTLY IF NOT EXISTS organizations_instance_age_idx
    ON core.organizations (instance_id, created_at);
