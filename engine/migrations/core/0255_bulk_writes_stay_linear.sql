-- 0255_bulk_writes_stay_linear.sql
--
-- Bringing many people in at once took time that grew with the square of how many (0.70), for
-- two reasons. The check that an address is nobody's username makes its plan once for a whole
-- statement, so a plan made on an empty or nearly empty table stays: with no statistics every
-- index starting with org_id cost the same as the identifier's and the planner took one that
-- reads the whole organisation for each row, so 20,000 people took 103 s, and a first directory
-- sync is one such statement. It now compares the organisation in a form no index can serve,
-- which leaves the identifier's, and has a sequential scan off, because a small table with
-- statistics plans one and keeps that too. The second is the operator CLI's version bump: every
-- statement updated the one row of core.config_version, a transaction cannot prune its own
-- versions of a row, and each update walked past all of them, which with the first had a realm
-- import of 16,000 people take 267 s. A transaction now moves the version once, which is all an
-- If-Match compares.

CREATE OR REPLACE FUNCTION core.refuse_identifier_cross_collision() RETURNS trigger
LANGUAGE plpgsql
SET enable_seqscan = off
AS $$
BEGIN
    IF NEW.email IS NOT NULL OR NEW.username IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('signari.identifier:' || NEW.org_id, 0));
    END IF;
    IF NEW.email IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE username_fold = lower(NEW.email) AND (org_id = NEW.org_id) IS TRUE AND id <> NEW.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This address is another person''s username in the organisation.';
        END IF;
    END IF;
    IF NEW.username IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE email_fold = lower(NEW.username) AND (org_id = NEW.org_id) IS TRUE AND id <> NEW.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This username is another person''s address in the organisation.';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- set_config with is_local is undone at the end of the transaction, and by a rollback to a
-- savepoint, which undoes the bump with it.
CREATE OR REPLACE FUNCTION core.bump_config_version_for_cli() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('signari.cli_write', true) = 'on'
       AND current_setting('signari.cli_bumped', true) IS DISTINCT FROM 'yes' THEN
        UPDATE core.config_version SET version = version + 1, bumped_at = now()
         WHERE id = true;
        PERFORM set_config('signari.cli_bumped', 'yes', true);
        PERFORM set_config('signari.cli_wrote', 'yes', false);
    END IF;
    RETURN NULL;
END $$;
