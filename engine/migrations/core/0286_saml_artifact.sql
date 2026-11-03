-- 0286_saml_artifact.sql
--
-- A service provider may take its response by artifact (8.08, SAML Bindings 2.0 §3.6): the
-- browser carries a reference, and the provider fetches the response over SOAP from the
-- artifact resolution service. An assertion consumer URL may say HTTP-Artifact again, which
-- 0147 took away until this was built. Not compatible with the previous release: it changes a
-- check on saml_acs_urls, and the previous release would POST to an artifact URL.

ALTER TABLE core.saml_acs_urls DROP CONSTRAINT saml_acs_urls_binding_check;
ALTER TABLE core.saml_acs_urls ADD CONSTRAINT saml_acs_urls_binding_check
    CHECK (binding IN ('HTTP-POST', 'HTTP-Artifact'));

-- A response waiting to be resolved. It is found by the SHA-256 of the artifact's message
-- handle and sealed under a key derived from the handle, which is not stored, so the row
-- alone opens nothing. It is taken by the first resolution, whoever asks, and is good for a
-- minute (expires_at).
CREATE TABLE core.saml_artifacts (
    handle_hash bytea       PRIMARY KEY CHECK (octet_length(handle_hash) = 32),
    provider_id uuid        NOT NULL REFERENCES core.saml_providers(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    message     bytea       NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX saml_artifacts_expiry ON core.saml_artifacts (expires_at);
CREATE INDEX saml_artifacts_org ON core.saml_artifacts (org_id);
CREATE INDEX saml_artifacts_provider ON core.saml_artifacts (provider_id);

ALTER TABLE core.saml_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.saml_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_artifacts_org_isolation ON core.saml_artifacts
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.saml_artifacts TO signari_maintenance;

CREATE TRIGGER saml_artifacts_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.saml_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
