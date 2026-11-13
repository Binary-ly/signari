-- signari:compatible-with-previous
--
-- 0293_uma_resources.sql
--
-- UMA resource registration (11.12, Federated Authorization §3): a resource server puts a
-- resource under this server's protection with a protection API access token, and a permission
-- may then name it by the id this server gave it alone. Each is the resource server's and, when
-- a person issued the token, that person's: the owner whose policy decides who may reach it,
-- and who shares it from their account page. Its type is a type of the organisation's
-- authorization model, so a registered resource is an object the model already knows how to
-- decide about. Compatible with the previous release, which ignores the table and goes on
-- refusing a permission that names no resource_type, as it always did.

CREATE TABLE core.uma_resources (
    id          text        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    client_id   text        NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    owner_id    uuid        REFERENCES core.users(id) ON DELETE CASCADE,
    type        text        NOT NULL CHECK (type <> ''),
    scopes      text[]      NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 64),
    name        text,
    description text,
    icon_uri    text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX uma_resources_server ON core.uma_resources (client_id, owner_id);
CREATE INDEX uma_resources_org ON core.uma_resources (org_id);
CREATE INDEX uma_resources_owner ON core.uma_resources (owner_id);

ALTER TABLE core.uma_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.uma_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY uma_resources_org_isolation ON core.uma_resources
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.uma_resources TO signari_maintenance;

CREATE TRIGGER uma_resources_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.uma_resources
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.uma_resources IS
    'resources a resource server registered for UMA protection (Federated Authorization 3), by the id given here';
COMMENT ON COLUMN core.uma_resources.owner_id IS
    'the person whose protection API token registered it; NULL when the resource server registered it for the organisation';
