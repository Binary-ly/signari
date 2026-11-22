-- 0197_identifier_lock_per_organisation.sql
--
-- A transaction writing many people no longer runs PostgreSQL out of locks
-- (7.16). Migration 0158 took an advisory lock per identifier, held until
-- commit, and the lock table holds about 6,400 at PostgreSQL's defaults, so a
-- first directory sync or an import failed with `out of shared memory` around
-- the twelve-thousandth person.
--
-- The lock is now the organisation's, one however many people are written, and
-- the guarantee is the same: two writers adding the two halves of a collision
-- are in one organisation, so the second still waits for the first and reads
-- its row. Hashing identifiers into a fixed number of locks would also have
-- bounded them, and two writers would then have met in different orders and
-- deadlocked. What it costs is that writers of identifiers in one organisation
-- wait for each other's commit; sign-in writes neither column, and every
-- audited write already waits on the audit chain's lock.

SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.refuse_identifier_cross_collision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.email IS NOT NULL OR NEW.username IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('signari.identifier:' || NEW.org_id, 0));
    END IF;
    IF NEW.email IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE org_id = NEW.org_id AND id <> NEW.id AND lower(username) = lower(NEW.email)) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This address is another person''s username in the organisation.';
        END IF;
    END IF;
    IF NEW.username IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE org_id = NEW.org_id AND id <> NEW.id AND lower(email) = lower(NEW.username)) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This username is another person''s address in the organisation.';
        END IF;
    END IF;
    RETURN NEW;
END $$;
