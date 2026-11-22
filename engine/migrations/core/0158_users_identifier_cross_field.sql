-- 0158_users_identifier_cross_field.sql
--
-- One person's username may not be another's email in the same organisation
-- (2.59). Sign-in matches an identifier against either field and refuses when
-- two people match, so a username equal to somebody's address refused both of
-- them. Each field was unique on its own (0002); nothing compared the two, at
-- any of the writers -- the CLI, the Admin API, SCIM, LDAP, federation,
-- sign-up, directory sync and the importers -- so it is refused here, once.
--
-- Existing collisions are refused by name rather than resolved: which person
-- keeps the identifier is an operator's call.

SET search_path = core, public;

DO $$
DECLARE clash text;
BEGIN
    SELECT string_agg(format('%s in organisation %s', lower(a.email), a.org_id), ', ')
      INTO clash
      FROM core.users a
      JOIN core.users b ON b.org_id = a.org_id AND b.id <> a.id AND lower(b.username) = lower(a.email);
    IF clash IS NOT NULL THEN
        RAISE EXCEPTION 'these addresses are also another person''s username in the same organisation: %. '
            'Rename one of each pair, then migrate again.', clash;
    END IF;
END $$;

-- An advisory lock on the identifier, so two writers each adding one half of a
-- collision cannot both pass: the second waits for the first, and its check
-- then reads the first's committed row.
--
-- Raised in the words PostgreSQL uses for a unique index, because that is
-- what the writers recognise as a conflict and answer as one (409, an LDAP
-- entry that exists, a SCIM conflict); the detail says which collision it is.
CREATE FUNCTION core.refuse_identifier_cross_collision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.email IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('signari.identifier:' || NEW.org_id || ':' || lower(NEW.email), 0));
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE org_id = NEW.org_id AND id <> NEW.id AND lower(username) = lower(NEW.email)) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This address is another person''s username in the organisation.';
        END IF;
    END IF;
    IF NEW.username IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('signari.identifier:' || NEW.org_id || ':' || lower(NEW.username), 0));
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE org_id = NEW.org_id AND id <> NEW.id AND lower(email) = lower(NEW.username)) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This username is another person''s address in the organisation.';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER users_identifier_cross_field
    BEFORE INSERT OR UPDATE OF email, username ON core.users
    FOR EACH ROW EXECUTE FUNCTION core.refuse_identifier_cross_collision();
