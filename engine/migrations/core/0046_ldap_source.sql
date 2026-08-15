-- LDAP as a directory SOURCE.
--
-- The other direction from internal/ldapd, which lets applications bind to this
-- engine. This is the inbound half: an organisation that already runs OpenLDAP,
-- Active Directory or FreeIPA can use this as its identity provider without
-- re-entering everybody.
--
-- Reuses core.directory_sources -- the same reconciler, the same dry run, the
-- same deactivation ceiling. A second table would have meant a second set of
-- safety rules, and the second set is always the one that is missing a check.
ALTER TABLE core.directory_sources
    DROP CONSTRAINT directory_sources_kind_check,
    ADD CONSTRAINT directory_sources_kind_check
        CHECK (kind IN ('google','entra','ldap'));

ALTER TABLE core.directory_sources
    -- ldap:// or ldaps://
    ADD COLUMN ldap_url text,
    ADD COLUMN ldap_bind_dn text,
    ADD COLUMN ldap_base_dn text,
    -- openldap | ad | freeipa. Decides which attribute is the immutable
    -- identifier, which is the single most consequential setting here: read the
    -- wrong one and a rename looks like a departure plus an arrival.
    ADD COLUMN ldap_flavour text
        CHECK (ldap_flavour IS NULL OR ldap_flavour IN ('openldap','ad','freeipa')),
    ADD COLUMN ldap_start_tls boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN core.directory_sources.ldap_flavour IS
    'Decides the immutable identifier attribute: entryUUID for OpenLDAP, '
    'objectGUID for Active Directory, ipaUniqueID for FreeIPA. Reading the wrong '
    'one makes every rename look like a departure and an arrival.';

COMMENT ON COLUMN core.directory_sources.ldap_start_tls IS
    'Defaults TRUE. A bind over plaintext sends the bind password in the clear, '
    'and that password can usually read the entire directory.';
