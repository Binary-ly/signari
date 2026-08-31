-- Mapping a directory's groups onto this deployment's groups.
--
-- # Default deny, because a group decides application access
--
-- Group membership here is not a label. `core.groups` decides which
-- applications its members reach, which is why the admin API gives groups their
-- own scope pair rather than letting `users:write` edit them.
--
-- So a directory sync that could create local groups from remote names would be
-- an external system granting access by inventing a group. Nothing is created,
-- and nothing is joined, unless an operator declared the mapping: remote group
-- "Engineering" reaches local group X because somebody said so, once, and that
-- statement is this table.
--
-- # A synced group may never be one that grants impersonation
--
-- `groups.may_impersonate` lets members act as other users. The admin API
-- already refuses to set it — a `groups:write` token could otherwise grant
-- itself impersonation by flagging a group its operator belongs to, which is
-- the greater privilege obtained from the lesser credential.
--
-- The same reasoning applies harder here: the party choosing who is in the
-- remote group is the directory, not this deployment. If an impersonation group
-- could be synced, whoever administers the upstream directory could add
-- themselves to it and act as anybody. So the mapping refuses that target
-- outright, at declaration time, rather than at every sync.

CREATE TABLE core.directory_group_map (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id   uuid        NOT NULL REFERENCES core.directory_sources(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The group's name or DN as the directory reports it.
    remote_group text       NOT NULL CHECK (length(remote_group) BETWEEN 1 AND 512),

    -- The local group it grants. A foreign key, so a group cannot be deleted
    -- while a sync still points at it and silently starts creating nothing.
    group_id    uuid        NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,

    created_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (source_id, remote_group, group_id)
);

CREATE INDEX directory_group_map_by_source ON core.directory_group_map (source_id);

-- A synced group may never grant impersonation. Enforced by trigger rather than
-- CHECK because it depends on another table's row.
CREATE OR REPLACE FUNCTION core.directory_group_map_refuses_impersonation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM core.groups
               WHERE id = NEW.group_id AND may_impersonate) THEN
        RAISE EXCEPTION 'group % grants impersonation and may not be synced from a '
            'directory: whoever administers that directory would be able to add '
            'themselves and act as any user', NEW.group_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER directory_group_map_no_impersonation
    BEFORE INSERT OR UPDATE ON core.directory_group_map
    FOR EACH ROW EXECUTE FUNCTION core.directory_group_map_refuses_impersonation();

-- The other direction: a group that is a sync target must not later be given
-- impersonation. Without this the refusal above is a one-time check somebody
-- walks around by flipping the flag afterwards.
CREATE OR REPLACE FUNCTION core.group_refuses_impersonation_while_synced()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.may_impersonate AND NOT COALESCE(OLD.may_impersonate, false)
       AND EXISTS (SELECT 1 FROM core.directory_group_map WHERE group_id = NEW.id) THEN
        RAISE EXCEPTION 'group % is a directory sync target and may not be given '
            'impersonation: membership is decided by the directory, so this would '
            'let whoever administers it act as any user', NEW.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER group_no_impersonation_while_synced
    BEFORE UPDATE ON core.groups
    FOR EACH ROW EXECUTE FUNCTION core.group_refuses_impersonation_while_synced();

ALTER TABLE core.directory_group_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.directory_group_map FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_group_map_org_isolation ON core.directory_group_map
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
