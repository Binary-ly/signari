-- 0289_saml_artifact_logout.sql
--
-- A service provider's logout endpoint may take its messages by artifact (8.08, SAML Bindings
-- 2.0 §3.6): the LogoutRequest or LogoutResponse waits here, and the provider fetches it from the
-- artifact resolution service with the artifact the browser brings. Not compatible with the
-- previous release: it changes the check on saml_slo_urls, and the previous release would send a
-- logout message to an artifact endpoint on the redirect binding.

ALTER TABLE core.saml_slo_urls DROP CONSTRAINT saml_slo_urls_binding_check;
ALTER TABLE core.saml_slo_urls ADD CONSTRAINT saml_slo_urls_binding_check
    CHECK (binding IN ('HTTP-Redirect', 'HTTP-POST', 'HTTP-Artifact', 'SOAP'));
