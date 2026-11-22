-- 0288_saml_artifact_resolution.sql
--
-- A service provider may send its request by artifact (8.08, SAML Bindings 2.0 §3.6.5): the
-- browser brings a reference, and this deployment fetches the request over SOAP from the
-- provider's artifact resolution service, the one the artifact names by its index. A provider
-- with none sends no request that way. What the service answers is believed for coming from the
-- address registered here, so the address is https, as an assertion consumer URL is.

CREATE TABLE core.saml_artifact_resolution (
    provider_id    uuid    NOT NULL REFERENCES core.saml_providers(id) ON DELETE CASCADE,
    endpoint_index integer NOT NULL CHECK (endpoint_index BETWEEN 0 AND 65535),
    url            text    NOT NULL,
    PRIMARY KEY (provider_id, endpoint_index),
    CONSTRAINT saml_artifact_resolution_https CHECK (url LIKE 'https://%')
);

GRANT SELECT ON core.saml_artifact_resolution TO signari_maintenance;

CREATE TRIGGER saml_artifact_resolution_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.saml_artifact_resolution
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
