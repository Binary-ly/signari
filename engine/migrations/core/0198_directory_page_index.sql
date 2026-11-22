-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0198_directory_page_index.sql
--
-- The order an LDAP subtree search reads an organisation's people in (7.01),
-- so a page is a walk of this index from where the last one stopped however
-- far into the directory that is. Only the active, as the directory lists.
--
-- Built concurrently, outside a transaction, as 0156's were, so a deployment
-- with many people keeps signing them in while this builds.

CREATE INDEX CONCURRENTLY IF NOT EXISTS users_directory_page
    ON core.users (org_id, id) WHERE status = 'active';
