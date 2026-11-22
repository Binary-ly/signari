-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0196_scim_page_indexes.sql
--
-- The indexes behind a page of SCIM users or groups (7.13). A list is ordered
-- by when each was provisioned, and nothing served that order, so every page
-- sorted the source's whole collection. SCIM pages by index, so the offset
-- stays; with these it walks an index rather than a sort.
--
-- Built concurrently, outside a transaction, as 0156's were, so a source mid
-- sync keeps provisioning while these build.

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_source_links_page
    ON core.scim_source_links (source_id, created_at, external_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_source_group_links_page
    ON core.scim_source_group_links (source_id, created_at, external_id);
