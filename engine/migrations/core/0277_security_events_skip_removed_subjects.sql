-- 0277_security_events_skip_removed_subjects.sql
--
-- A subject a receiver removed from its stream stops being queued for it. Apart from
-- that this is the function 0212 made. Replacing it is what the compatibility
-- declaration refuses, so this is apart from 0276: the release before would go on
-- queuing them, which a receiver has to tolerate anyway (SSF 1.0 §9.3).

CREATE OR REPLACE FUNCTION core.queue_security_event(p_user uuid, p_event text, p_claims jsonb) RETURNS void
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
       AND NOT EXISTS (SELECT 1 FROM core.ssf_removed_subjects r
                        WHERE r.stream_id = st.id AND r.user_id = p_user)
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
       AND NOT EXISTS (SELECT 1 FROM core.ssf_removed_subjects r
                        WHERE r.stream_id = st.id AND r.user_id = p_user)
       AND (EXISTS (SELECT 1 FROM core.session_clients sc
                      JOIN core.sessions s ON s.sid = sc.sid
                     WHERE s.user_id = p_user AND sc.client_id = st.client_id)
            OR EXISTS (SELECT 1 FROM core.refresh_token_families f
                        WHERE f.user_id = p_user AND f.client_id = st.client_id));
$$;
