-- 0213_relations_follow_a_changed_name.sql
--
-- A relation that names a person by address or username moves to their id when
-- that name changes, so the access stays with the person and not with the name.
--
-- # The defect
--
-- Migration 0179 made a deleted person take their tuples with them, because a
-- name a person gives up is one the next account can take. A change of name gives
-- it up just the same, and nothing moved: the grant stayed on the old address,
-- answering for it, so whoever took that address up next was allowed what the
-- person had been, and the person lost it. Erasure could not find the tuple
-- either, since by then the old address was no longer theirs to be matched by.
--
-- # Why to the id
--
-- A grant to an address means the person who held it when it was made. The id is
-- the one name of theirs that never changes hands, and the engine already resolves
-- a person by it, so nothing that reads relations has to change.
--
-- Matched as 0179 matches, without case. Inserted then deleted rather than updated:
-- the person may already hold the same grant by id, and two spellings of one address
-- can both exist, and an UPDATE would refuse a person's address change over either.
--
-- Not declared compatible with the release before, for 0179's reason: a trigger on
-- a table it already has is what the declaration refuses.

CREATE FUNCTION core.move_relations_of_renamed_user() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    names text[] := '{}';
BEGIN
    IF OLD.email IS NOT NULL AND lower(OLD.email) IS DISTINCT FROM lower(NEW.email) THEN
        names := names || lower(OLD.email);
    END IF;
    IF OLD.username IS NOT NULL AND lower(OLD.username) IS DISTINCT FROM lower(NEW.username) THEN
        names := names || lower(OLD.username);
    END IF;
    IF names = '{}' THEN
        RETURN NULL;
    END IF;

    INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id,
                                granted_by, granted_at, expires_at)
    SELECT org_id, subject_type, NEW.id::text, relation, object_type, object_id,
           granted_by, granted_at, expires_at
      FROM core.relations
     WHERE org_id = OLD.org_id AND subject_type = 'user' AND lower(subject_id) = ANY (names)
    ON CONFLICT (org_id, subject_type, subject_id, relation, object_type, object_id) DO NOTHING;
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND subject_type = 'user' AND lower(subject_id) = ANY (names);

    INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id,
                                granted_by, granted_at, expires_at)
    SELECT org_id, subject_type, subject_id, relation, object_type, NEW.id::text,
           granted_by, granted_at, expires_at
      FROM core.relations
     WHERE org_id = OLD.org_id AND object_type = 'user' AND lower(object_id) = ANY (names)
    ON CONFLICT (org_id, subject_type, subject_id, relation, object_type, object_id) DO NOTHING;
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND object_type = 'user' AND lower(object_id) = ANY (names);
    RETURN NULL;
END $$;

CREATE TRIGGER users_move_relations AFTER UPDATE OF email, username ON core.users
    FOR EACH ROW EXECUTE FUNCTION core.move_relations_of_renamed_user();
