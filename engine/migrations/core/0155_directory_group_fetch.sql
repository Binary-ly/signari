-- 0155_directory_group_fetch.sql
--
-- Whether a directory source fetches group memberships, and for LDAP from
-- which attribute (2.02).
--
-- Group reconciliation was built, with mappings, a plan and a removal ceiling,
-- and fed by nothing: the LDAP source's group attribute was never assigned,
-- and the Entra and Google sources had no group code at all, so every sync
-- reported nobody in any group and reconciliation stood down. Fetching is
-- opt-in because it needs more of the upstream than reading users does
-- (GroupMember.Read.All, admin.directory.group.readonly).

SET search_path = core, public;

ALTER TABLE core.directory_sources
    ADD COLUMN fetch_groups boolean NOT NULL DEFAULT false,
    -- NULL reads memberOf. An attribute name, not a filter: it is put in the
    -- search's attribute list as given.
    ADD COLUMN ldap_group_attribute text
        CHECK (ldap_group_attribute IS NULL OR ldap_group_attribute ~ '^[A-Za-z][A-Za-z0-9-]*$');
