-- signari:compatible-with-previous
--
-- 0239_audit_append.sql
--
-- core.audit_append takes the audit chain's lock, reads its tail, works out the entry's hash and
-- appends it in one statement (E.11). The lock is global and held until commit, so what it lets
-- through is one over the round trips made while holding it, and that was four and a half: the
-- lock's answer, the tail, the insert, the subscriptions, the commit. Now it is the answer and
-- the commit, and the engine builds the same bytes it always hashed, so nothing about the chain
-- changes and a version before this one, taking the same lock, appends to the same chain.
--
-- Volatile, which is the whole of why this works: a volatile function takes a new snapshot for
-- each statement in it, so the read of the tail sees what committed while this one waited. Read
-- in one statement with the lock, it would not, and the chain would fork.

CREATE FUNCTION core.audit_append(
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

GRANT EXECUTE ON FUNCTION core.audit_append(bigint, uuid, text, uuid, uuid, text, uuid, text, jsonb,
    uuid, timestamptz, smallint, bytea, bytea) TO signari_maintenance;
