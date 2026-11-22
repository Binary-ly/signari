-- signari:compatible-with-previous
--
-- 0206_directory_attribute_map.sql
--
-- Which LDAP attribute feeds which declared attribute (7.15), remote name to
-- local name. A sync read only what a flavour's conventions named, so a company's
-- employee number or department stayed behind in the directory, and an address
-- kept anywhere but `mail` was not found at all.

ALTER TABLE core.directory_sources
    ADD COLUMN attribute_map jsonb NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(attribute_map) = 'object');
