-- Which of our groups is which group at a provisioning target.
--
-- # A group is matched by REMOTE ID, never by name
--
-- The tempting shortcut is to find the target's group whose displayName matches
-- ours. It is also how a sync takes over a group it did not create: a target's
-- own administrators may already maintain "Engineering", and the first
-- reconciliation would adopt it and start removing the members they put there.
--
-- So a group is only ever acted on when this table says we created it. A group
-- at the target with no row here is somebody else's and is left alone, however
-- similar its name.
--
-- # Mirrors scim_links, deliberately
--
-- `core.scim_links` does the same job for users and has the same shape. Two
-- tables rather than one polymorphic one, because a user link and a group link
-- are deleted by different cascades -- a user leaving must not take a group with
-- it -- and a `kind` column would have made that a WHERE clause somebody
-- forgets.

CREATE TABLE core.scim_group_links (
    target_id   uuid        NOT NULL REFERENCES core.scim_targets(id) ON DELETE CASCADE,
    group_id    uuid        NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The id the target assigned. Without it the group cannot be found again,
    -- so every reconciliation would create a duplicate.
    remote_id   text        NOT NULL CHECK (length(remote_id) BETWEEN 1 AND 512),

    last_synced_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (target_id, group_id),

    -- One local group per remote group. Two of ours pointing at one of theirs
    -- would make each reconciliation undo the other's membership changes, which
    -- presents as a group whose members flicker.
    UNIQUE (target_id, remote_id)
);

CREATE INDEX scim_group_links_by_group ON core.scim_group_links (group_id);

ALTER TABLE core.scim_group_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.scim_group_links FORCE ROW LEVEL SECURITY;
CREATE POLICY scim_group_links_org_isolation ON core.scim_group_links
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
