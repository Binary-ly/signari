-- signari:compatible-with-previous
-- 0281_client_metadata_documents.sql
--
-- A client that is an https URL and describes itself in a document there, so an
-- application nobody registered can be signed in to. Nothing does until an operator
-- writes down whose URLs to fetch: with no rows, nobody is admitted, and nothing is ever
-- fetched. Each rule names the organisation its clients land in and what they may ask for.

CREATE TABLE core.client_metadata_rules (
    instance_id uuid        NOT NULL REFERENCES core.instances(id) ON DELETE CASCADE,
    url_prefix  text        NOT NULL,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- The most such a client is given, whatever its document says. Nobody here chose it.
    scopes      text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, url_prefix),
    CONSTRAINT client_metadata_rules_https CHECK (url_prefix LIKE 'https://%/')
);

CREATE INDEX client_metadata_rules_org ON core.client_metadata_rules (org_id);

ALTER TABLE core.client_metadata_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.client_metadata_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY client_metadata_rules_org_isolation ON core.client_metadata_rules
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.client_metadata_rules TO signari_maintenance;

CREATE TRIGGER client_metadata_rules_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.client_metadata_rules
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- The rule that admitted a client, NULL on every client an operator made. When what its
-- document said stops holding is federation_expires_at, the same question with the same
-- answer at the authorization endpoint.
ALTER TABLE core.clients ADD COLUMN client_metadata_prefix text;
