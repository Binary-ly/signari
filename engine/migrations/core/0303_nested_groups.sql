-- signari:compatible-with-previous
--
-- 0303_nested_groups.sql
--
-- A group may be a member of another (11.09): whoever is in `oncall-eu` is in `oncall`, and
-- whoever is in `oncall` is in `engineering`, so a person put in one group is in every group
-- above it, for every claim, directory answer and access decision. One edge per nesting,
-- with who made it, as a membership records who granted it.
--
-- Membership through nesting is read at the moment it is asked, never copied: removing an
-- edge takes everybody below it out of everything above it on the next request, as removing
-- a person does. core.groups_of(person) and core.groups_below(group) are the two ways to
-- ask, and a read of core.group_members alone answers only for direct membership.
--
-- A loop is refused when it is made, not tolerated when it is read: a group inside itself
-- through others would make every one of them a member of all the rest, which nobody meant.
-- The check walks up from the new parent with every other nesting in the organisation held
-- off, so two nestings that would close a loop together cannot both pass. Both groups must
-- be the edge's organisation's. The walks also use UNION, so a loop that somehow existed
-- would end the walk rather than the server.
--
-- An earlier binary reads membership as direct only, which grants less, never more; until
-- every node runs this release a nesting is honoured by some and not others, so make none
-- before the rollout is done.

CREATE TABLE core.group_parents (
    group_id  uuid        NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,
    parent_id uuid        NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,
    org_id    uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    added_at  timestamptz NOT NULL DEFAULT now(),
    added_by  uuid        REFERENCES core.users(id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, parent_id),
    CONSTRAINT group_parents_not_itself CHECK (group_id <> parent_id)
);

-- The primary key serves the walk up (a group's parents, in order); this one the walk
-- down and a group's member groups, in order.
CREATE INDEX group_parents_parent_idx ON core.group_parents (parent_id, group_id);
-- Erasing the person who made a nesting sets added_by to NULL, as for a membership (0222).
CREATE INDEX group_parents_added_by ON core.group_parents (added_by);

ALTER TABLE core.group_parents ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.group_parents FORCE ROW LEVEL SECURITY;
CREATE POLICY group_parents_org_isolation ON core.group_parents
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.group_parents TO signari_maintenance;

CREATE TRIGGER group_parents_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.group_parents
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

CREATE FUNCTION core.group_parents_refuse_loops() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('core.group_parents:' || NEW.org_id::text, 0));
    IF NOT EXISTS (SELECT 1 FROM core.groups WHERE id = NEW.group_id AND org_id = NEW.org_id)
       OR NOT EXISTS (SELECT 1 FROM core.groups WHERE id = NEW.parent_id AND org_id = NEW.org_id) THEN
        RAISE EXCEPTION 'a group can be nested only in a group of its own organisation'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'group_parents_same_organisation';
    END IF;
    IF EXISTS (
        WITH RECURSIVE up(id) AS (
            SELECT NEW.parent_id
            UNION
            SELECT p.parent_id FROM up JOIN core.group_parents p ON p.group_id = up.id
        )
        SELECT 1 FROM up WHERE id = NEW.group_id) THEN
        RAISE EXCEPTION 'the group is already above the one it would be nested in, so this would make a loop'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'group_parents_no_loop';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER group_parents_refuse_loops
    BEFORE INSERT OR UPDATE ON core.group_parents
    FOR EACH ROW EXECUTE FUNCTION core.group_parents_refuse_loops();

-- Every group a person is in, and whether directly: their own memberships and every group
-- above each of them.
CREATE FUNCTION core.groups_of(person uuid) RETURNS TABLE (group_id uuid, direct boolean)
    LANGUAGE sql STABLE AS $$
    WITH RECURSIVE g(id, direct) AS (
        SELECT m.group_id, true FROM core.group_members m WHERE m.user_id = person
        UNION
        SELECT p.parent_id, false FROM g JOIN core.group_parents p ON p.group_id = g.id
    )
    SELECT id, bool_or(direct) FROM g GROUP BY id
$$;

-- A group and every group inside it, at any depth: who is in the group is whoever is
-- directly in one of these. A set of groups rather than of people, so a caller asking
-- whether anybody is in it, or for one person, joins core.group_members on its own index
-- instead of collecting everybody first.
CREATE FUNCTION core.groups_below(grp uuid) RETURNS TABLE (group_id uuid)
    LANGUAGE sql STABLE AS $$
    WITH RECURSIVE d(id) AS (
        SELECT grp
        UNION
        SELECT p.group_id FROM d JOIN core.group_parents p ON p.parent_id = d.id
    )
    SELECT id FROM d
$$;

-- Whether a group's members may act as other people: it may, or a group it is inside may.
-- Adding somebody to a group inside one that may impersonate grants them that, so every
-- check that guards the flag -- a privileged target, an invitation, a sign-up default, a
-- configuration file -- asks this rather than the group's own column.
CREATE FUNCTION core.group_may_impersonate(grp uuid) RETURNS boolean
    LANGUAGE sql STABLE AS $$
    WITH RECURSIVE up(id) AS (
        SELECT grp
        UNION
        SELECT p.parent_id FROM up JOIN core.group_parents p ON p.group_id = up.id
    )
    SELECT EXISTS (SELECT 1 FROM up JOIN core.groups g ON g.id = up.id WHERE g.may_impersonate)
$$;

COMMENT ON TABLE core.group_parents IS
    'group_id is a member of parent_id, so everybody in it is in the parent and every group above that';

-- What the console reads (core_v1), under the same policy as membership.
CREATE VIEW core_v1.group_parents AS
SELECT p.group_id, p.parent_id, p.org_id
  FROM core.group_parents p;

GRANT SELECT ON core_v1.group_parents TO signari_admin;
