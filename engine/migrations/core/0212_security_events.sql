-- 0212_security_events.sql
--
-- core.queue_security_event tells the streams that asked what happened to a
-- person, and a trigger on core.users makes every status change a RISC event.
--
-- # Who is told
--
-- A stream is not a licence to learn about every person in the directory, so
-- only a client that has met this one hears of them: a session, or a refresh
-- family. Whether that session is still live does not matter. Deactivating
-- somebody and changing their password both end every session in the same
-- transaction, and the applications those sessions reached are the ones that
-- need to know.
--
-- # Why status is a trigger and a credential change is not
--
-- Six places write core.users.status, one of them an ON CONFLICT clause that
-- brings a deactivated account back, and the change is the whole of the fact: a
-- list of them is a list the next writer is missing from. A credential is the
-- opposite. A sign-in that upgrades a hash writes the same column a new password
-- does, and only the caller knows which it was, so those are queued in Go.
--
-- 'locked' and 'pending' are left out: nothing is disabled by an account waiting
-- for approval, and no receiver has met it.

SET search_path = core, public;

CREATE FUNCTION core.queue_security_event(p_user uuid, p_event text, p_claims jsonb) RETURNS void
    LANGUAGE sql AS $$
    INSERT INTO core.outbox (topic, payload)
    SELECT 'ssf_event', jsonb_build_object(
               'stream_id', st.id::text,
               'client_id', st.client_id,
               'endpoint',  st.endpoint_url,
               'event',     p_event,
               'subject',   p_user::text,
               'claims',    p_claims)
      FROM core.ssf_streams st
     WHERE st.delivery_method = 'push'
       AND st.status IN ('enabled', 'paused')
       AND p_event = ANY(st.events_requested)
       AND (EXISTS (SELECT 1 FROM core.session_clients sc
                      JOIN core.sessions s ON s.sid = sc.sid
                     WHERE s.user_id = p_user AND sc.client_id = st.client_id)
            OR EXISTS (SELECT 1 FROM core.refresh_token_families f
                        WHERE f.user_id = p_user AND f.client_id = st.client_id));

    INSERT INTO core.ssf_poll_queue (stream_id, jti, event_type, payload)
    SELECT st.id, gen_random_uuid()::text, p_event, jsonb_build_object(
               'client_id', st.client_id,
               'subject',   p_user::text,
               'claims',    p_claims)
      FROM core.ssf_streams st
     WHERE st.delivery_method = 'poll'
       AND st.status IN ('enabled', 'paused')
       AND p_event = ANY(st.events_requested)
       AND (EXISTS (SELECT 1 FROM core.session_clients sc
                      JOIN core.sessions s ON s.sid = sc.sid
                     WHERE s.user_id = p_user AND sc.client_id = st.client_id)
            OR EXISTS (SELECT 1 FROM core.refresh_token_families f
                        WHERE f.user_id = p_user AND f.client_id = st.client_id));
$$;

CREATE FUNCTION core.tell_streams_of_account_status() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status = 'deactivated' THEN
        PERFORM core.queue_security_event(NEW.id,
            'https://schemas.openid.net/secevent/risc/event-type/account-disabled', '{}');
    ELSIF OLD.status = 'deactivated' AND NEW.status = 'active' THEN
        PERFORM core.queue_security_event(NEW.id,
            'https://schemas.openid.net/secevent/risc/event-type/account-enabled', '{}');
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER users_status_tells_streams
    AFTER UPDATE OF status ON core.users
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION core.tell_streams_of_account_status();
