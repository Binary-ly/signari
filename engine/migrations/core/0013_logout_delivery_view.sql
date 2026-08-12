-- 0013_logout_delivery_view.sql
--
-- Makes back-channel logout DELIVERY visible to an operator.
--
-- Every OIDC provider queues logout notices. Almost none of them tell anyone
-- what happened to them, which is why "logout does not work" is the field's
-- worst-kept secret: the notice is queued, the endpoint 500s, the retry budget
-- runs out, and the relying party keeps the user signed in forever. The IdP
-- reports success because, from its point of view, it did its part.
--
-- An undelivered logout is not a background detail. It is a specific user who
-- believes they signed out of a specific application and did not. That is an
-- operational fact somebody must be able to see, so it gets a view rather than a
-- log line nobody greps for.
--
-- Exposed through core_v1 like every other admin read: the console still has no
-- access to `core` (ADR-004).

SET search_path = core, public;

CREATE VIEW core_v1.logout_deliveries AS
SELECT
    o.id,
    o.payload->>'client_id'                          AS client_id,
    o.payload->>'sid'                                AS sid,
    (o.payload->>'user_id')::uuid                    AS user_id,
    c.org_id,
    c.display_name                                   AS client_name,
    c.backchannel_logout_uri,
    o.created_at                                     AS queued_at,
    o.delivered_at,
    o.attempts,
    o.next_attempt_at,
    o.last_error,
    -- Three states an operator actually cares about, named rather than inferred
    -- from a combination of nullable columns at the call site.
    CASE
        WHEN o.delivered_at IS NOT NULL THEN 'delivered'
        WHEN o.attempts >= 8            THEN 'parked'
        ELSE 'pending'
    END                                              AS status,
    -- How long the relying party has been wrong about this user. The number that
    -- makes the problem concrete.
    CASE
        WHEN o.delivered_at IS NOT NULL THEN o.delivered_at - o.created_at
        ELSE now() - o.created_at
    END                                              AS age
FROM core.outbox o
LEFT JOIN core.clients c ON c.client_id = o.payload->>'client_id'
WHERE o.topic = 'backchannel_logout';

GRANT SELECT ON core_v1.logout_deliveries TO signari_admin;
