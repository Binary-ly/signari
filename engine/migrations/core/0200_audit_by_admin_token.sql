-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0200_audit_by_admin_token.sql
--
-- The trail of one admin token (6.05, 0.53), which an investigation of a leaked
-- one starts from. Nothing served it: the search read the organisation's whole
-- trail, or the deployment's, through the column's text.
--
-- Built concurrently, outside a transaction, as 0156's were, so the trail keeps
-- being written while this builds. Partial, since most events have no token.

CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_admin_token_idx
    ON core.audit_events (admin_token_id, occurred_at DESC) WHERE admin_token_id IS NOT NULL;
