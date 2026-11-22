-- 0199_users_folded_identifiers.sql
--
-- Finding a person by address or name uses an index on the engine's own
-- connection, which it never did (0.52). core.users is under FORCE ROW LEVEL
-- SECURITY, and PostgreSQL will not run a function that is not leakproof on a
-- column ahead of a policy, so `lower(email) = lower($1)` could use no index at
-- all: every sign-in read every person, and the unique indexes on lower(email)
-- served only their uniqueness. Tests connect as a role that bypasses the
-- policy, so none of them saw it.
--
-- A stored fold of each identifier compares with texteq, which is leakproof,
-- and lower() then touches only the value being looked for. The generated
-- columns need no writer to remember them, and go NULL with the identifier
-- when a person is erased. text_pattern_ops serves both equality and a prefix;
-- 0189's indexes on lower() are dropped, since nothing as the engine could use
-- them.
--
-- The trigger's own lookups had the same scan, once per person written, so a
-- first sync of a large directory was quadratic.
--
-- Adding a stored column rewrites the table. Stop the release before migrating.

SET search_path = core, public;

ALTER TABLE core.users
    ADD COLUMN email_fold    text GENERATED ALWAYS AS (lower(email)) STORED,
    ADD COLUMN username_fold text GENERATED ALWAYS AS (lower(username)) STORED;

DROP INDEX core.users_lower_email_pattern_idx;
DROP INDEX core.users_lower_username_pattern_idx;

CREATE INDEX users_email_fold_idx    ON core.users (email_fold text_pattern_ops, org_id);
CREATE INDEX users_username_fold_idx ON core.users (username_fold text_pattern_ops, org_id);

CREATE OR REPLACE FUNCTION core.refuse_identifier_cross_collision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.email IS NOT NULL OR NEW.username IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('signari.identifier:' || NEW.org_id, 0));
    END IF;
    IF NEW.email IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE username_fold = lower(NEW.email) AND org_id = NEW.org_id AND id <> NEW.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This address is another person''s username in the organisation.';
        END IF;
    END IF;
    IF NEW.username IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM core.users
                    WHERE email_fold = lower(NEW.username) AND org_id = NEW.org_id AND id <> NEW.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'unique_violation', CONSTRAINT = 'users_identifier_cross_field',
                MESSAGE = 'duplicate key value violates unique constraint "users_identifier_cross_field"',
                DETAIL = 'This username is another person''s address in the organisation.';
        END IF;
    END IF;
    RETURN NEW;
END $$;
