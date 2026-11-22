-- 0287_saml_ecp.sql
--
-- A service provider may take a response an ECP carries to it (8.08, SAML Profiles 2.0
-- §4.2): the client brings the provider's AuthnRequest to the sign-on service over SOAP and
-- the response goes back to the provider's PAOS endpoint. An assertion consumer URL may say
-- PAOS. A provider without one takes no ECP sign-in, which is how one opts in: the person's
-- password reaches this deployment from a client that is not a browser, and no page here can
-- ask for anything else. Not compatible with the previous release: it changes the check on
-- saml_acs_urls again.

ALTER TABLE core.saml_acs_urls DROP CONSTRAINT saml_acs_urls_binding_check;
ALTER TABLE core.saml_acs_urls ADD CONSTRAINT saml_acs_urls_binding_check
    CHECK (binding IN ('HTTP-POST', 'HTTP-Artifact', 'PAOS'));
