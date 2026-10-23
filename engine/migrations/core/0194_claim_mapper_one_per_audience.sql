-- 0194_claim_mapper_one_per_audience.sql
--
-- One mapper per audience, attribute and destination, the every-client
-- audience included (0.39). 0113's UNIQUE (org_id, client_id, attribute_id,
-- destination) took a NULL client_id, which is what "every client" is, as
-- distinct from every other NULL, so the upsert declaring a mapper never found
-- an all-clients one to replace: declared again under a new claim name, the
-- attribute was released under both, the name meant to be retired included.
--
-- Duplicates made so far are folded into the newest, the last one declared,
-- which is what the upsert meant to keep. The constraint covers the same
-- columns, so an ON CONFLICT naming them finds it. Not declared compatible
-- with the release before: it deletes rows, which only an additive migration
-- may do and stay servable by a binary that predates it.

DELETE FROM core.claim_mappers m
 USING core.claim_mappers n
 WHERE m.client_id IS NULL AND n.client_id IS NULL
   AND m.org_id = n.org_id AND m.attribute_id = n.attribute_id AND m.destination = n.destination
   AND (m.created_at, m.id) < (n.created_at, n.id);

ALTER TABLE core.claim_mappers DROP CONSTRAINT claim_mappers_org_id_client_id_attribute_id_destination_key;
ALTER TABLE core.claim_mappers ADD CONSTRAINT claim_mappers_one_per_audience
    UNIQUE NULLS NOT DISTINCT (org_id, client_id, attribute_id, destination);
