-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0218_rac_sessions_open.sql
--
-- The open sessions of a connection, which a connection with a cap counts on every
-- attempt (8.29), while holding the lock that puts attempts in order. Only the open ones
-- are indexed: the table keeps every session anybody ever had, and the count asks about
-- a handful of them.

CREATE INDEX CONCURRENTLY IF NOT EXISTS rac_sessions_open
    ON core.rac_sessions (connection_id) WHERE ended_at IS NULL;
