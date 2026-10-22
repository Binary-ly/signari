-- signari:compatible-with-previous
--
-- 0191_admin_role_bindings.sql
--
-- Administrative roles (6.01). A binding gives a person, or an application
-- acting as itself, one of the built-in roles in one organisation; what each
-- role may do is the engine's (adminapi.Roles), not a column, so a role means
-- the same thing in every deployment and a release can never widen one by a
-- migration nobody reads.
--
-- A user-manager binding may name a group, and then reaches only the group's
-- members: delegated administration of a department rather than of everyone.
-- No other role is delegated, because what the others reach (applications,
-- the organisation's settings, the trail) is not divided by group.
--
-- Read per request by the Admin API (ADR-007): removing a binding refuses the
-- next request, with no token to revoke and no cache to wait out.
--
-- Compatible with the release before, which never reads it.

CREATE TABLE core.admin_role_bindings (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id    uuid        REFERENCES core.users(id) ON DELETE CASCADE,
    client_id  text        REFERENCES core.clients(client_id) ON DELETE CASCADE,
    role       text        NOT NULL,
    group_id   uuid        REFERENCES core.groups(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admin_role_bindings_role_check
        CHECK (role IN ('org-owner', 'user-manager', 'app-manager', 'auditor')),
    CONSTRAINT admin_role_bindings_one_subject
        CHECK ((user_id IS NULL) <> (client_id IS NULL)),
    CONSTRAINT admin_role_bindings_only_user_manager_is_delegated
        CHECK (group_id IS NULL OR role = 'user-manager'),
    CONSTRAINT admin_role_bindings_once
        UNIQUE NULLS NOT DISTINCT (org_id, user_id, client_id, role, group_id)
);

-- The holder's and the group's: each request reads its holder's bindings, and
-- deleting a person, a client or a group removes theirs. The organisation's is
-- the unique constraint, which leads with it.
CREATE INDEX admin_role_bindings_user ON core.admin_role_bindings (user_id);
CREATE INDEX admin_role_bindings_client ON core.admin_role_bindings (client_id);
CREATE INDEX admin_role_bindings_group ON core.admin_role_bindings (group_id);

-- The subject and the group belong to the binding's organisation. Checked in
-- the database rather than by each writer, so the CLI, the Admin API and a
-- hand-written INSERT are held alike: a binding in one organisation naming a
-- person of another would hand that person a tenant they are not in.
CREATE FUNCTION core.admin_role_binding_same_org() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM core.users WHERE id = NEW.user_id AND org_id = NEW.org_id) THEN
        RAISE EXCEPTION 'admin role binding: the user is not in the binding''s organisation'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_role_bindings_subject_org';
    END IF;
    IF NEW.client_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM core.clients WHERE client_id = NEW.client_id AND org_id = NEW.org_id) THEN
        RAISE EXCEPTION 'admin role binding: the client is not in the binding''s organisation'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_role_bindings_subject_org';
    END IF;
    IF NEW.group_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM core.groups WHERE id = NEW.group_id AND org_id = NEW.org_id) THEN
        RAISE EXCEPTION 'admin role binding: the group is not in the binding''s organisation'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'admin_role_bindings_group_org';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER admin_role_bindings_same_org
    BEFORE INSERT OR UPDATE ON core.admin_role_bindings
    FOR EACH ROW EXECUTE FUNCTION core.admin_role_binding_same_org();

ALTER TABLE core.admin_role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.admin_role_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_role_bindings_org_isolation ON core.admin_role_bindings
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.admin_role_bindings TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER admin_role_bindings_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.admin_role_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.admin_role_bindings IS
    'An administrative role given to a person or an application in one organisation; a user-manager binding may be narrowed to one group''s members.';
