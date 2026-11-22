-- 0139_cli_writes_bump_version.sql
--
-- A write the operator CLI makes moves core.config_version in the same
-- transaction, as an Admin API write does (ADR-008).
--
-- # The defect
--
-- The Admin API's mutate() and mutateIf() bump the version inside every
-- write's transaction, and that counter is what an RFC 7232 If-Match is
-- compared against: the console and the Terraform provider send back the
-- version they read, so a change made since is refused rather than
-- overwritten. The CLI writes the same tables and, in all but three of its
-- commands, moved nothing. A plan read at version V therefore applied over a
-- CLI change made after it -- a client disabled from the command line came
-- back enabled on the next stale apply -- which is the lost update the
-- precondition exists to refuse.
--
-- # Why a trigger, and why gated on the session
--
-- Sixty-odd CLI functions write, many of them through store functions shared
-- with the request path. Fixing each would be a list somebody's next command
-- is missing from. A statement-level trigger on every core table cannot be
-- left out by a new command, and it runs inside the statement's transaction.
--
-- It bumps only when the session has said it is the operator CLI
-- (`signari.cli_write`, set by cmd/signari for every command but `serve`).
-- The request path and the background jobs write these tables too -- a token
-- touch, a sync's status, a dynamic registration -- and those are not edits
-- an administrator made; bumping on them would refuse every conditional
-- write that happened to follow one.
--
-- Not on config_version (the trigger would fire on its own update),
-- audit_events (written alongside the change it records, never alone) or
-- schema_migrations (bookkeeping). TestEveryCoreTableBumpsTheVersionOnACLIWrite
-- fails when a table added later carries no trigger.

SET search_path = core, public;

CREATE FUNCTION core.bump_config_version_for_cli() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('signari.cli_write', true) = 'on' THEN
        UPDATE core.config_version SET version = version + 1, bumped_at = now()
         WHERE id = true;
    END IF;
    RETURN NULL;
END $$;

DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT tablename FROM pg_tables
         WHERE schemaname = 'core'
           AND tablename NOT IN ('config_version', 'audit_events', 'schema_migrations')
    LOOP
        EXECUTE format(
            'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON core.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli()',
            t || '_cli_bumps_version', t);
    END LOOP;
END $$;
