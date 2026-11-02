-- signari:compatible-with-previous
-- 0282_id_jag.sql
--
-- Cross-app access: a client that signed somebody in here asks for an Identity Assertion
-- JWT Authorization Grant, and another authorization server gives it an access token for
-- that person on the strength of it, with no redirect and no consent screen. So nothing
-- is issued until an operator writes down which client may ask, for which server, and
-- what the most it may carry there is.

CREATE TABLE core.id_jag_audiences (
    client_id        text        NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    -- The issuer identifier of the Resource Authorization Server.
    audience         text        NOT NULL,
    org_id           uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- What the client is called over there, which it need not be here (§5.1).
    remote_client_id text        NOT NULL,
    resources        text[]      NOT NULL DEFAULT '{}',
    scopes           text[]      NOT NULL DEFAULT '{}',
    signing_alg      text        NOT NULL DEFAULT 'RS256',
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, audience),
    CONSTRAINT id_jag_audiences_https CHECK (audience LIKE 'https://%')
);

CREATE INDEX id_jag_audiences_org ON core.id_jag_audiences (org_id, audience);

ALTER TABLE core.id_jag_audiences ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.id_jag_audiences FORCE ROW LEVEL SECURITY;
CREATE POLICY id_jag_audiences_org_isolation ON core.id_jag_audiences
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.id_jag_audiences TO signari_maintenance;

CREATE TRIGGER id_jag_audiences_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.id_jag_audiences
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
