-- signari:compatible-with-previous
--
-- 0305_audit_append_many.sql
--
-- core.audit_append_many appends several audit records in one statement, under the same lock as
-- core.audit_append and to the same chain (E.32): the lock is taken once, the tail is read once,
-- and each record's hash follows from the one before it, exactly as the same records appended one
-- after another would. The engine writes a record that is not part of another transaction (a
-- revocation's, an exchange's, a backchannel request's) together with the others that arrive while
-- one is being written, so the lock and the commit it is held across are paid once for all of them.
-- One record a transaction let 2,190 a second through at 16 writers; sixteen in one statement let
-- 14,157 through, where sixteen calls of core.audit_append in one round trip let 8,029.
--
-- Nothing about the chain changes. The bytes hashed are still built by the engine, a binary from
-- before this one appends with core.audit_append under the same lock, and a verifier reads the rows
-- as it always has. Volatile for the reason core.audit_append is: the read of the tail sees what
-- committed while this statement waited for the lock.

CREATE FUNCTION core.audit_append_many(
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

GRANT EXECUTE ON FUNCTION core.audit_append_many(bigint, uuid[], text[], uuid[], uuid[], text[], uuid[],
    text[], jsonb[], uuid[], timestamptz[], smallint[], bytea[], bytea[]) TO signari_maintenance;
