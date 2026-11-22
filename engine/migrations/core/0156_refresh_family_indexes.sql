-- signari:no-transaction
--
-- 0156_refresh_family_indexes.sql
--
-- refresh_token_families had only its primary key (3.30). Ending a session
-- revokes its families by sid, a consent withdrawal and a client disconnect
-- revoke a person's live families for one client, and each of those scanned
-- the whole table: store/sessions.go and store/consent.go on every sign-out
-- and withdrawal, and the cascade from core.sessions on every expired session
-- the janitor deletes.
--
-- Built concurrently, outside a transaction, so a deployment with millions of
-- families keeps issuing and refreshing tokens while they build. A failed
-- build leaves an invalid index; the next `migrate up` drops and rebuilds it.

CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_token_families_sid_idx
    ON core.refresh_token_families (sid);

CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_token_families_live_by_user_client_idx
    ON core.refresh_token_families (user_id, client_id)
    WHERE revoked_at IS NULL;
