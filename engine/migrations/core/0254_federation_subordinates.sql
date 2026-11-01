-- signari:compatible-with-previous
-- 0254_federation_subordinates.sql
--
-- Entities this one speaks for (12.11). A deployment could join a federation and could not be
-- the thing others join: it had nobody to vouch for and no endpoint to do it at. So an instance
-- keeps its Immediate Subordinates, each with the keys it was told out of band, because a Subordinate
-- Statement's whole worth is that those keys did not come from the subordinate's own say-so at
-- the moment of asking. An older binary ignores the table and publishes nothing from it.

CREATE TABLE core.federation_subordinates (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id     uuid        NOT NULL REFERENCES core.instances(id) ON DELETE CASCADE,
    entity_id       text        NOT NULL,
    jwks            jsonb       NOT NULL,
    metadata_policy jsonb,
    max_path_length integer     CHECK (max_path_length >= 0),
    intermediate    boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance_id, entity_id)
);

GRANT SELECT ON core.federation_subordinates TO signari_maintenance;

CREATE TRIGGER federation_subordinates_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.federation_subordinates
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
