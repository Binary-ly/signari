-- 0307_cli_writes_take_the_version_first.sql
--
-- An operator CLI write takes core.config_version's row before anything else it locks, as every
-- other writer that moves the version does, so a CLI write and an Admin API write to the same
-- thing at once no longer deadlock. 0139's trigger ran after each statement, when the statement
-- already held the rows it wrote and, through core.users' identifier trigger, its organisation's
-- identifier lock; the Admin API, `signari apply` and a receiver changing its stream take the
-- version's row first. Each then held what the other was waiting for, and PostgreSQL ended one of
-- them a second later, as a 500 from the API or a failed command.
--
-- # What changes
--
-- The trigger on every core table runs before the statement, so the statement takes the row
-- before it reads, locks or writes anything. It still moves the version once a transaction
-- (0255), and a statement that fails takes its bump with it, as before.
--
-- core.audit_append and core.audit_append_many take the row too, in a CLI session, before the
-- audit chain's lock. A CLI transaction that recorded before it wrote took the chain's lock first
-- and the row at its write: the reverse of the Admin API, which takes the row and then records.
-- Outside a CLI session they are what they were.
--
-- A read fires no trigger, so a CLI transaction that locks a row with SELECT ... FOR UPDATE, or
-- takes an advisory lock, before its first write takes the row itself first
-- (store.LockConfigVersion, in cmd/signari).
--
-- Every core table but the three 0139 leaves out gets the trigger, whatever the migration that
-- made it called it: the triggers are found by the function they call, dropped, and made again
-- by name. TestEveryCoreTableBumpsTheVersionOnACLIWrite fails on a table whose trigger runs
-- after its statement, or that has none.

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT tg.tgname, c.relname
          FROM pg_trigger tg
          JOIN pg_proc p ON p.oid = tg.tgfoid
          JOIN pg_class c ON c.oid = tg.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'core' AND p.proname = 'bump_config_version_for_cli'
    LOOP
        EXECUTE format('DROP TRIGGER %I ON core.%I', r.tgname, r.relname);
    END LOOP;

    FOR r IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'core' AND c.relkind IN ('r', 'p')
           AND c.relname NOT IN ('config_version', 'audit_events', 'schema_migrations')
    LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON core.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli()',
            r.relname || '_cli_bumps_version', r.relname);
    END LOOP;
END $$;

-- 0239's function, with the row taken first in a CLI session.
CREATE OR REPLACE FUNCTION core.audit_append(
    lock_key bigint, p_org_id uuid, p_event_type text, p_subject_id uuid, p_actor_id uuid,
    p_client_id text, p_correlation_id uuid, p_retention_class text, p_detail jsonb,
    p_admin_token_id uuid, p_occurred_at timestamptz, p_hash_version smallint,
    body bytea, tail bytea)
RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    prev bytea;
    entry bytea;
BEGIN
    -- The order every writer that moves the version keeps: its row, then the chain's lock.
    IF current_setting('signari.cli_write', true) = 'on' THEN
        PERFORM 1 FROM core.config_version WHERE id = true FOR UPDATE;
    END IF;
    PERFORM pg_advisory_xact_lock(lock_key);
    SELECT entry_hash INTO prev FROM core.audit_events ORDER BY id DESC LIMIT 1;
    entry := sha256(COALESCE(prev, ''::bytea) || body);
    IF tail IS NOT NULL THEN
        entry := sha256(entry || tail);
    END IF;
    INSERT INTO core.audit_events
        (org_id, event_type, subject_id, actor_id, client_id, correlation_id,
         retention_class, detail, prev_hash, entry_hash, admin_token_id, occurred_at, hash_version)
    VALUES (p_org_id, p_event_type, p_subject_id, p_actor_id, p_client_id, p_correlation_id,
            p_retention_class, p_detail, prev, entry, p_admin_token_id, p_occurred_at, p_hash_version);
END
$$;

-- 0305's function, likewise.
CREATE OR REPLACE FUNCTION core.audit_append_many(
    lock_key bigint, p_org_id uuid[], p_event_type text[], p_subject_id uuid[], p_actor_id uuid[],
    p_client_id text[], p_correlation_id uuid[], p_retention_class text[], p_detail jsonb[],
    p_admin_token_id uuid[], p_occurred_at timestamptz[], p_hash_version smallint[],
    body bytea[], tail bytea[])
RETURNS void
LANGUAGE plpgsql VOLATILE
AS $$
DECLARE
    n int := cardinality(body);
    prev bytea;
    entry bytea;
BEGIN
    -- Each array is one field of every record; one of a different length is a record whose fields
    -- came apart, and appending it would hash one record's body beside another's columns.
    IF cardinality(p_org_id) <> n OR cardinality(p_event_type) <> n OR cardinality(p_subject_id) <> n
        OR cardinality(p_actor_id) <> n OR cardinality(p_client_id) <> n
        OR cardinality(p_correlation_id) <> n OR cardinality(p_retention_class) <> n
        OR cardinality(p_detail) <> n OR cardinality(p_admin_token_id) <> n
        OR cardinality(p_occurred_at) <> n OR cardinality(p_hash_version) <> n
        OR cardinality(tail) <> n THEN
        RAISE EXCEPTION 'audit_append_many: % records, and a field with a different number', n;
    END IF;
    -- The order every writer that moves the version keeps: its row, then the chain's lock.
    IF current_setting('signari.cli_write', true) = 'on' THEN
        PERFORM 1 FROM core.config_version WHERE id = true FOR UPDATE;
    END IF;
    PERFORM pg_advisory_xact_lock(lock_key);
    SELECT entry_hash INTO prev FROM core.audit_events ORDER BY id DESC LIMIT 1;
    -- One insert a record, in order, rather than one insert of them all: the chain is verified in
    -- id order, and only a row inserted after the one it follows is sure to have the larger id.
    FOR i IN 1 .. n LOOP
        entry := sha256(COALESCE(prev, ''::bytea) || body[i]);
        IF tail[i] IS NOT NULL THEN
            entry := sha256(entry || tail[i]);
        END IF;
        INSERT INTO core.audit_events
            (org_id, event_type, subject_id, actor_id, client_id, correlation_id,
             retention_class, detail, prev_hash, entry_hash, admin_token_id, occurred_at, hash_version)
        VALUES (p_org_id[i], p_event_type[i], p_subject_id[i], p_actor_id[i], p_client_id[i],
                p_correlation_id[i], p_retention_class[i], p_detail[i], prev, entry,
                p_admin_token_id[i], p_occurred_at[i], p_hash_version[i]);
        prev := entry;
    END LOOP;
END
$$;
