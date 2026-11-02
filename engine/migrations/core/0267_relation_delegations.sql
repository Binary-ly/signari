-- 0267_relation_delegations.sql
--
-- One organisation letting another hand out a relation on what it owns (11.11): a software
-- company's application, and each customer deciding which of its own people may use it. Every
-- relation stays where the object is, in the owner's core.relations, so the owner's decisions
-- read what they always read and a decision crosses no tenant. What crosses is only who may
-- write the row, and that is the engine alone: a tenant reaches another's rows through nothing
-- but a delegation an operator made, for the people of its own organisation.
--
-- Not compatible with the release before: replacing the function a trigger on core.users
-- runs is what the declaration refuses (docs/upgrading.md).

CREATE TABLE core.relation_delegations (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Whose the object is, and whose relations these are.
    org_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- Who may hand them to their own people.
    grantee_org_id uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    object_type    text        NOT NULL,
    -- One object, or '*' for every object of the type.
    object_id      text        NOT NULL,
    relations      text[]      NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relation_delegations_once UNIQUE (org_id, grantee_org_id, object_type, object_id),
    CONSTRAINT relation_delegations_to_another CHECK (org_id <> grantee_org_id),
    CONSTRAINT relation_delegations_some CHECK (cardinality(relations) BETWEEN 1 AND 32),
    CONSTRAINT relation_delegations_type_is_plain CHECK (object_type ~ '^[a-z][a-z0-9_-]{0,63}$'),
    CONSTRAINT relation_delegations_id_is_present CHECK (length(object_id) BETWEEN 1 AND 256)
);

CREATE INDEX relation_delegations_grantee ON core.relation_delegations (grantee_org_id);

COMMENT ON TABLE core.relation_delegations IS
    'What one organisation lets another hand out to its own people. Either side may read it; '
    'only the engine writes it, for a deployment-wide caller.';

ALTER TABLE core.relation_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.relation_delegations FORCE ROW LEVEL SECURITY;
CREATE POLICY relation_delegations_either_side ON core.relation_delegations
    USING (core.is_engine() OR org_id = core.current_org_id() OR grantee_org_id = core.current_org_id())
    WITH CHECK (core.is_engine());

GRANT SELECT ON core.relation_delegations TO signari_maintenance;

CREATE TRIGGER relation_delegations_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.relation_delegations
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- Goes with the delegation: taking one away takes everything handed out under it, and no row
-- is left that nobody may any longer manage.
ALTER TABLE core.relations
    ADD COLUMN delegation_id uuid REFERENCES core.relation_delegations(id) ON DELETE CASCADE;
CREATE INDEX relations_delegation ON core.relations (delegation_id);
CREATE INDEX relations_delegated_subject ON core.relations (subject_id) WHERE delegation_id IS NOT NULL;

-- A person of one organisation holding a relation in another is one the trigger on their own
-- organisation's rows would not find.
CREATE OR REPLACE FUNCTION core.forget_deleted_user_relations() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    names text[] := array_remove(ARRAY[OLD.id::text, lower(OLD.email), lower(OLD.username)], NULL);
BEGIN
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND subject_type = 'user' AND lower(subject_id) = ANY (names);
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND object_type = 'user' AND lower(object_id) = ANY (names);
    DELETE FROM core.relations
     WHERE delegation_id IS NOT NULL AND subject_id = OLD.id::text;
    RETURN NULL;
END $$;
