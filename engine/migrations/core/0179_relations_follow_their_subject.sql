-- 0179_relations_follow_their_subject.sql
--
-- A deleted person or group takes its relation tuples with it.
--
-- # The defect
--
-- core.relations names its subject and its object by text: a person by id, by
-- address or by username, a group by name. Nothing references core.users or
-- core.groups, so no foreign key removes a tuple when either goes, and none of
-- the paths that delete them did: four for an account (the Admin API, an LDAP
-- write, a SCIM source, erasure), three for a group (the Admin API, `signari
-- apply`, a SCIM source). A group made later under a deleted group's name held
-- every grant the old one had, so its new members were allowed what nobody had
-- granted them. A deleted person's tuples went on answering for their id, and
-- for their address and username, which the next account to take either
-- inherits.
--
-- # Why a trigger
--
-- Seven deletion paths, and the next is a list it is missing from. A row
-- trigger on the table being deleted from cannot be left out, and it runs in
-- the deleting statement, so a deletion and its tuples go together or not at
-- all.
--
-- A person is matched as the engine resolves one: by id, or by address or
-- username without case, each unique without case within the organisation
-- (users_org_email_key, users_org_username_key), so the match names nobody
-- else. The two indexes keep that a lookup rather than a scan of the
-- organisation's tuples, once per person, when a directory removes thousands.
-- A group is matched by name exactly, as membership is.
--
-- # What it does not do
--
-- Tuples already left behind stay. A grant to a group that does not exist yet
-- is also how access is granted ahead of the sync that will create the group,
-- and nothing records which of the two such a tuple is; `signari doctor` names
-- them instead.
--
-- Not declared compatible with the release before. That release would work
-- against it, but its deletions would now remove tuples, and a trigger on a
-- table it already has is what the declaration refuses (docs/upgrading.md).

CREATE INDEX relations_subject_folded ON core.relations (org_id, subject_type, lower(subject_id));
CREATE INDEX relations_object_folded ON core.relations (org_id, object_type, lower(object_id));

CREATE FUNCTION core.forget_deleted_user_relations() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    names text[] := array_remove(ARRAY[OLD.id::text, lower(OLD.email), lower(OLD.username)], NULL);
BEGIN
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND subject_type = 'user' AND lower(subject_id) = ANY (names);
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND object_type = 'user' AND lower(object_id) = ANY (names);
    RETURN NULL;
END $$;

CREATE TRIGGER users_forget_relations AFTER DELETE ON core.users
    FOR EACH ROW EXECUTE FUNCTION core.forget_deleted_user_relations();

CREATE FUNCTION core.forget_deleted_group_relations() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND subject_type = 'group' AND subject_id = OLD.name;
    DELETE FROM core.relations
     WHERE org_id = OLD.org_id AND object_type = 'group' AND object_id IN (OLD.name, OLD.id::text);
    RETURN NULL;
END $$;

CREATE TRIGGER groups_forget_relations AFTER DELETE ON core.groups
    FOR EACH ROW EXECUTE FUNCTION core.forget_deleted_group_relations();
