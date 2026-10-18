-- 0131_scim_group_ownership.sql
--
-- A SCIM source owns the groups it creates and no others. A group it owns can
-- never let its members impersonate.
--
-- # The defect
--
-- Creating a group through SCIM upserted core.groups on (org_id, name) and then
-- replaced the members. An upstream that sent a display name deriving to an
-- existing local group took that group over. It could be one whose members may
-- impersonate, one an operator manages, or one another source owns, since the
-- link index was unique per source and not per group. The upstream's users went
-- in, everybody else came out, and the group kept whatever it already reached.
-- The code now inserts and refuses a name that is taken. This migration makes
-- the same rules hold whatever writes the rows.
--
-- # Why the same rule as directory sync
--
-- 0118 refused to let a directory sync target a group that may impersonate,
-- because whoever administers the upstream decides who is in the group, and
-- could add themselves and act as anybody. A SCIM upstream is the same party in
-- the same position. Both directions are enforced: linking a flagged group, and
-- flagging a linked one.
--
-- # Why the migration refuses rather than repairs
--
-- As 0129 and 0130: a link to a flagged group, or one group owned by two
-- sources, is a state the upstream may already have used. Which side to keep is
-- the operator's decision, not this file's.

SET search_path = core, public;

DO $$
DECLARE
    flagged text;
    shared  text;
BEGIN
    SELECT string_agg(format('%s (group %s, source %s)', g.name, g.id, l.source_id), '; ')
      INTO flagged
      FROM core.scim_source_group_links l
      JOIN core.groups g ON g.id = l.group_id
     WHERE g.may_impersonate;
    IF flagged IS NOT NULL THEN
        RAISE EXCEPTION 'these groups may impersonate and are managed by a SCIM source, '
            'so whoever administers the upstream decides who can act as any user: %', flagged
            USING HINT = 'Revoke impersonation (signari group impersonation -org <uuid> '
                '-group <name>, without -grant), or delete the group from the upstream so '
                'the link goes, and run the migration again.';
    END IF;

    SELECT string_agg(format('%s (group %s)', g.name, g.id), '; ')
      INTO shared
      FROM (SELECT group_id FROM core.scim_source_group_links
             GROUP BY group_id HAVING count(*) > 1) d
      JOIN core.groups g ON g.id = d.group_id;
    IF shared IS NOT NULL THEN
        RAISE EXCEPTION 'these groups are managed by more than one SCIM source, and each '
            'replaces the members the other sets: %', shared
            USING HINT = 'Delete the group from all but one upstream, or remove the extra '
                'rows from core.scim_source_group_links, and run the migration again.';
    END IF;
END $$;

-- One owner per group. The per-source index stays; the provider's lookups use it.
CREATE UNIQUE INDEX scim_source_group_links_one_owner
    ON core.scim_source_group_links (group_id);

CREATE OR REPLACE FUNCTION core.scim_group_link_refuses_impersonation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM core.groups
               WHERE id = NEW.group_id AND may_impersonate) THEN
        RAISE EXCEPTION 'group % grants impersonation and may not be managed by a SCIM '
            'source: whoever administers the upstream would be able to add themselves '
            'and act as any user', NEW.group_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER scim_group_link_no_impersonation
    BEFORE INSERT OR UPDATE ON core.scim_source_group_links
    FOR EACH ROW EXECUTE FUNCTION core.scim_group_link_refuses_impersonation();

-- The other direction, for both kinds of sync. Replaces 0118's version, which
-- knew only directory sync.
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
    END IF;
    RETURN NEW;
END;
$$;
