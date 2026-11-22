-- 0140_cli_writes_are_audited.sql
--
-- Every operator CLI command that changes something leaves an audit record,
-- without each of its hundred-odd commands having to remember to write one.
--
-- # The defect
--
-- About 115 CLI commands wrote core tables and wrote no audit record: granting
-- impersonation, rotating keys, creating admin tokens, applying a policy. The
-- trail said nothing about the most powerful changes anyone makes, because the
-- command line is where they are made.
--
-- # How
--
-- The same session marker as 0139. Its trigger now also notes, on the
-- session, that this CLI session wrote (`signari.cli_wrote`), and a new
-- statement trigger on audit_events notes that it audited
-- (`signari.cli_audited`). After a command succeeds, cmd/signari reads the two
-- and, for a command that wrote and audited nothing, writes one
-- `admin.cli_command` record naming the command, the flags it was given (never
-- their values, which may be secrets) and the operator. A command that writes
-- its own, more specific record is not recorded twice.
--
-- set_config inside a transaction is undone when it rolls back, so a command
-- whose write failed is not recorded as having written.

SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.bump_config_version_for_cli() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('signari.cli_write', true) = 'on' THEN
        UPDATE core.config_version SET version = version + 1, bumped_at = now()
         WHERE id = true;
        PERFORM set_config('signari.cli_wrote', 'yes', false);
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION core.note_cli_audit() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('signari.cli_write', true) = 'on' THEN
        PERFORM set_config('signari.cli_audited', 'yes', false);
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER audit_events_cli_noted AFTER INSERT ON core.audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION core.note_cli_audit();
