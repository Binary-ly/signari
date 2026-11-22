-- signari:compatible-with-previous
--
-- 0240_saml_source_keys.sql
--
-- This deployment's own keys toward an upstream SAML identity provider (8.04): one to sign its
-- requests, which some providers insist on, and one the provider encrypts assertions to. Per
-- upstream and apart from the keys that sign tokens, so that one partner's certificate is
-- nobody else's and giving a partner a decryption key gives it nothing else. Several of each
-- may be live, since a rotation has to overlap: the newest signs, and any of them decrypts
-- until it is retired. Sealed under the root key.

ALTER TABLE core.saml_sources ADD COLUMN sign_requests boolean NOT NULL DEFAULT false;
ALTER TABLE core.saml_sources ADD COLUMN require_encryption boolean NOT NULL DEFAULT false;

CREATE TABLE core.saml_source_keys (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id uuid        NOT NULL REFERENCES core.saml_sources(provider_id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    purpose     text        NOT NULL CHECK (purpose IN ('signing', 'encryption')),
    key_sealed  bytea       NOT NULL,
    certificate text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz
);

CREATE INDEX saml_source_keys_provider ON core.saml_source_keys (provider_id, purpose);
CREATE INDEX saml_source_keys_org ON core.saml_source_keys (org_id);

ALTER TABLE core.saml_source_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.saml_source_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_source_keys_org_isolation ON core.saml_source_keys
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.saml_source_keys TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER saml_source_keys_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.saml_source_keys
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
