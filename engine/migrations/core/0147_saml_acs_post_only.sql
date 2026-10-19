-- 0147_saml_acs_post_only.sql
--
-- An assertion consumer URL's binding may be HTTP-POST only.
--
-- The CHECK from 0019 also allowed HTTP-Artifact, which nothing implements:
-- there is no artifact resolution service, and the SSO endpoint answers every
-- AuthnRequest by POSTing the Response. Every writer stores HTTP-POST. A row
-- claiming Artifact would describe a delivery that never happens, so the value
-- goes until the binding does (8.08).

SET search_path = core, public;

ALTER TABLE saml_acs_urls DROP CONSTRAINT saml_acs_urls_binding_check;
ALTER TABLE saml_acs_urls ADD CONSTRAINT saml_acs_urls_binding_check CHECK (binding = 'HTTP-POST');
