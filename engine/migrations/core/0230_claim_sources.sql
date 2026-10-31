-- 0230_claim_sources.sql
--
-- What a claim can be made from (10.04). A mapper read one attribute, so a token could not
-- say which tenant it belongs to in a name a relying party already expects, or carry
-- somebody's groups under a claim of the application's choosing. source says where the value
-- comes from: attribute as before, a constant, the groups released to the client, a field of
-- the person's own record, or their roles in the application. transform is a short closed
-- list and no language: lower, a prefix, or the first thing an RE2 pattern finds.
--
-- attribute_id is NULL for every source but attribute, so the one-per-audience constraint,
-- which treats NULLs as equal, would let a client have one such mapper per destination. It
-- becomes two partial indexes: one per attribute for those that have one, one per claim name
-- for those that do not.

ALTER TABLE core.claim_mappers ALTER COLUMN attribute_id DROP NOT NULL;
ALTER TABLE core.claim_mappers ADD COLUMN source text NOT NULL DEFAULT 'attribute'
    CHECK (source IN ('attribute', 'constant', 'groups', 'user_field', 'relation'));
ALTER TABLE core.claim_mappers ADD COLUMN source_value text NOT NULL DEFAULT '';
ALTER TABLE core.claim_mappers ADD COLUMN transform text NOT NULL DEFAULT ''
    CHECK (transform IN ('', 'lower', 'prefix', 'extract'));
ALTER TABLE core.claim_mappers ADD COLUMN transform_arg text NOT NULL DEFAULT '';

ALTER TABLE core.claim_mappers ADD CONSTRAINT claim_mappers_source_shape
    CHECK ((source = 'attribute') = (attribute_id IS NOT NULL));

ALTER TABLE core.claim_mappers DROP CONSTRAINT claim_mappers_one_per_audience;
CREATE UNIQUE INDEX claim_mappers_one_per_audience
    ON core.claim_mappers (org_id, client_id, attribute_id, destination) NULLS NOT DISTINCT
    WHERE attribute_id IS NOT NULL;
CREATE UNIQUE INDEX claim_mappers_one_per_claim
    ON core.claim_mappers (org_id, client_id, claim_name, destination) NULLS NOT DISTINCT
    WHERE attribute_id IS NULL;
