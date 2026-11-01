-- signari:compatible-with-previous
-- 0243_wsfed_saml_version.sql
--
-- Which SAML a WS-Federation application takes its token in (8.09). SAML 2.0 is what every one
-- has had and stays the default; 1.1 is for the relying parties that were built against ADFS's
-- default and read nothing else. A SAML 2.0 service provider never reads this. An older binary
-- ignores it, and goes on issuing 2.0.

ALTER TABLE core.saml_providers
    ADD COLUMN wsfed_saml_version text NOT NULL DEFAULT '2.0' CHECK (wsfed_saml_version IN ('1.1', '2.0'));
