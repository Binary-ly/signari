-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0226_relations_page.sql
--
-- A page of an organisation's relations (11.01). An application that keeps its own relations
-- reads them back through the Admin API, by id, so a page holds still while it goes on
-- writing. Both existing indexes lead with a subject or an object, so a page with neither
-- would have walked the primary key past every other organisation's rows. Built concurrently,
-- outside a transaction, as 0196's were, so decisions go on being answered.

CREATE INDEX CONCURRENTLY IF NOT EXISTS relations_page ON core.relations (org_id, id);
