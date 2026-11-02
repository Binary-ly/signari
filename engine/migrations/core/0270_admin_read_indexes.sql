-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0270_admin_read_indexes.sql
--
-- What the Admin API's reads need to stop at the page (0.83). A page of an
-- organisation's people read and sorted all of them; a deployment-wide read of the
-- audit trail sorted the whole trail, because nothing led with its time; and the
-- list of event subscriptions and a Duo integration each counted through a table
-- with no index for what they counted.
--
-- Built concurrently, outside a transaction, as 0156's were, so a deployment with
-- many people keeps signing them in while these build.

CREATE INDEX CONCURRENTLY IF NOT EXISTS users_org_page
    ON core.users (org_id, id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS groups_org_page
    ON core.groups (org_id, id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS invitations_org_page
    ON core.invitations (org_id, id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS clients_org_page
    ON core.clients (org_id, client_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_time_idx
    ON core.audit_events (occurred_at DESC, id DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS event_deliveries_subscription_idx
    ON core.event_deliveries (subscription_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS duo_enrollments_org_idx
    ON core.duo_enrollments (org_id);
