-- 0223_idp_group_map.sql
--
-- What a provider's groups grant here (8.14). Only a directory could say who is in a
-- group; somebody who comes through a provider, and is in `Engineering` there, was in
-- nothing here until an administrator added them, one at a time, for good.
--
-- Default deny, as 0118 is and for its reasons: a group here decides what its members
-- reach, so a remote name grants a local group only because somebody declared that it
-- does. Nothing is created and nothing is joined otherwise. And never a group that may
-- impersonate, in either direction, since whoever administers the provider decides who
-- is in the remote one.
--
-- group_claim is the claim the names arrive in: `groups` by convention, and the claim is
-- the provider's to choose.

CREATE TABLE core.idp_group_map (
    provider_id  uuid NOT NULL REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    org_id       uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    remote_group text NOT NULL CHECK (length(remote_group) BETWEEN 1 AND 512),
    group_id     uuid NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, remote_group, group_id)
);

CREATE INDEX idp_group_map_group ON core.idp_group_map (group_id);
CREATE INDEX idp_group_map_org ON core.idp_group_map (org_id);

ALTER TABLE core.identity_providers ADD COLUMN group_claim text NOT NULL DEFAULT 'groups';

CREATE OR REPLACE FUNCTION core.idp_group_map_refuses_impersonation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM core.groups WHERE id = NEW.group_id AND may_impersonate) THEN
        RAISE EXCEPTION 'group % grants impersonation and may not be granted by a provider: '
            'whoever administers it would be able to add themselves and act as any user', NEW.group_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER idp_group_map_no_impersonation
    BEFORE INSERT OR UPDATE ON core.idp_group_map
    FOR EACH ROW EXECUTE FUNCTION core.idp_group_map_refuses_impersonation();

-- The other direction, for all three kinds of sync. Replaces 0131's version, which knew
-- directories and SCIM sources.
CREATE OR REPLACE FUNCTION core.group_refuses_impersonation_while_synced()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.may_impersonate AND NOT COALESCE(OLD.may_impersonate, false) THEN
        IF EXISTS (SELECT 1 FROM core.directory_group_map WHERE group_id = NEW.id) THEN
            RAISE EXCEPTION 'group % is a directory sync target and may not be given '
                'impersonation: membership is decided by the directory, so this would '
                'let whoever administers it act as any user', NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM core.scim_source_group_links WHERE group_id = NEW.id) THEN
            RAISE EXCEPTION 'group % is managed by a SCIM source and may not be given '
                'impersonation: membership is decided by the upstream, so this would '
                'let whoever administers it act as any user', NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM core.idp_group_map WHERE group_id = NEW.id) THEN
            RAISE EXCEPTION 'group % is granted by an identity provider and may not be given '
                'impersonation: membership is decided by the provider, so this would '
                'let whoever administers it act as any user', NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE core.idp_group_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.idp_group_map FORCE ROW LEVEL SECURITY;
CREATE POLICY idp_group_map_org_isolation ON core.idp_group_map
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.idp_group_map TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER idp_group_map_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.idp_group_map
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
