-- signari:compatible-with-previous
--
-- 0244_kerberos_realms.sql
--
-- A Kerberos realm of an organisation's own (8.10). One realm from the environment, and every
-- ticket landing in the first organisation, was all a deployment could have: two customers with
-- two domains could not both sign in. A browser gets a ticket for the host it is talking to, so
-- the host says which realm's key opens it and whose organisation the person is in. The keytab
-- is sealed under the root key, being the key to every ticket of that service.

CREATE TABLE core.kerberos_realms (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    realm             text        NOT NULL CHECK (realm = upper(realm)),
    host              text        NOT NULL UNIQUE CHECK (host = lower(host)),
    service_principal text        NOT NULL,
    keytab_sealed     bytea       NOT NULL,
    strip_realm       boolean     NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, realm)
);

ALTER TABLE core.kerberos_realms ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.kerberos_realms FORCE ROW LEVEL SECURITY;
CREATE POLICY kerberos_realms_org_isolation ON core.kerberos_realms
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.kerberos_realms TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER kerberos_realms_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.kerberos_realms
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
