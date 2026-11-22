-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0189_user_lookup_indexes.sql
--
-- Finding a person by address or name across organisations (6.08). The Admin
-- API's user list takes ?email= (exact) and ?q= (a prefix of the address or
-- the user name), and the only indexes on either lead with org_id, so a
-- deployment-wide token's lookup read every user. text_pattern_ops, because
-- one index then serves both the equality and the prefix match.
--
-- Built concurrently, outside a transaction, as 0156's were, so a deployment
-- with many people keeps signing them in while these build.

CREATE INDEX CONCURRENTLY IF NOT EXISTS users_lower_email_pattern_idx
    ON core.users (lower(email) text_pattern_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS users_lower_username_pattern_idx
    ON core.users (lower(username) text_pattern_ops);
