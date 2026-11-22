-- 0205_scim_target_scope_groups.sql
--
-- A provisioning target limited to several groups (7.11), its members being the
-- members of any of them. One column held one group, so an application used by two
-- teams took a third group kept by hand, or everybody.
--
-- Empty means everybody, as a NULL column did. The group is held by NO ACTION,
-- checked as the statement ends, where the column had RESTRICT, checked at once:
-- deleting a group a target is limited to is refused either way, since widening a
-- target as a side effect of deleting something else is not a change anybody would
-- look for, and deleting an organisation is not at the mercy of which cascade runs
-- first.

CREATE TABLE core.scim_target_scope_groups (
    target_id uuid NOT NULL REFERENCES core.scim_targets(id) ON DELETE CASCADE,
    group_id  uuid NOT NULL REFERENCES core.groups(id),
    org_id    uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    PRIMARY KEY (target_id, group_id)
);

CREATE INDEX scim_target_scope_groups_group ON core.scim_target_scope_groups (group_id);
CREATE INDEX scim_target_scope_groups_org ON core.scim_target_scope_groups (org_id);

ALTER TABLE core.scim_target_scope_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.scim_target_scope_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY scim_target_scope_groups_org_isolation ON core.scim_target_scope_groups
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.scim_target_scope_groups TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER scim_target_scope_groups_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.scim_target_scope_groups
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

INSERT INTO core.scim_target_scope_groups (target_id, group_id, org_id)
SELECT id, scope_group_id, org_id FROM core.scim_targets WHERE scope_group_id IS NOT NULL;

ALTER TABLE core.scim_targets DROP COLUMN scope_group_id;

COMMENT ON TABLE core.scim_target_scope_groups IS
    'The groups a provisioning target is limited to: their members are provisioned to it, and with no row everybody is.';
