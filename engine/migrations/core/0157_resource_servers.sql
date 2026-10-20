-- 0157_resource_servers.sql
--
-- The resource servers an organisation's access tokens may be audienced to.
--
-- An RFC 8707 `resource` becomes the access token's audience, and the only
-- check on it was its shape: any client could name any https URI and receive a
-- token audienced to another organisation's API, or to an internal service
-- that trusts this issuer. A requested resource must now be registered here
-- for the client's organisation, at every place one is accepted and again when
-- a token is minted, so removing one stops new tokens for it at once.
--
-- Per organisation rather than per client: the resource is the API being
-- protected, and a dynamically registered client (an MCP client, say) can then
-- ask for the server it was pointed at without an operator configuring it.

SET search_path = core, public;

CREATE TABLE resource_servers (
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The identifier exactly as requested: an absolute http(s) URI with no
    -- fragment, compared byte for byte, as the audience is compared.
    resource    text        NOT NULL CHECK (resource ~ '^https?://' AND position('#' in resource) = 0),
    name        text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, resource)
);

ALTER TABLE resource_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_servers FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_servers_org_isolation ON resource_servers
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON resource_servers TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER resource_servers_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.resource_servers
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.resource_servers IS
    'RFC 8707 resource indicators an organisation''s tokens may be audienced to. None registered means every resource is refused.';
