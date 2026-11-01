-- 0241_saml_soap_logout.sql
--
-- A service provider that takes a logout with no browser in it (8.03). The redirect chain reaches
-- a provider only when somebody signs out by hand in a browser that can still be walked through
-- it; a session ended by an administrator, a deactivation or its own expiry has no browser, and
-- the provider went on believing it. A SOAP address is what lets the outbox tell it. Not
-- compatible with the version before: an older binary reading these rows would hand a SOAP
-- address to a browser as a redirect.

ALTER TABLE core.saml_slo_urls DROP CONSTRAINT saml_slo_urls_binding_check;
ALTER TABLE core.saml_slo_urls ADD CONSTRAINT saml_slo_urls_binding_check
    CHECK (binding IN ('HTTP-Redirect', 'HTTP-POST', 'SOAP'));
