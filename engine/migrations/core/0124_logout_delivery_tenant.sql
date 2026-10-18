-- 0124_logout_delivery_tenant.sql
--
-- Stops core_v1.logout_deliveries showing every tenant's sign-outs to any console
-- session.
--
-- # The leak
--
-- core.outbox carries no org_id and no row-level security: it is the engine's
-- delivery queue, not tenant data in its own right. The view took its tenant
-- from the client named in the payload, through a LEFT JOIN to core.clients.
-- core.clients forces row-level security, so for another tenant's notice the
-- join found no visible client -- and a LEFT JOIN keeps the row anyway, with the
-- client's columns NULL. What came through was the client id, the session id,
-- the user id and the delivery error of a sign-out in somebody else's
-- organisation.
--
-- Measured before this migration, as signari_admin on the test database:
--
--   with no organisation selected          2 rows, org_id NULL
--   scoped to an organisation owning none  2 rows, org_id NULL
--
-- TestNoCoreV1ViewReturnsAnotherTenantsRow was green throughout: it counted
-- `org_id IS NOT NULL AND org_id <> $1`, which excludes exactly the rows a failed
-- outer join produces. It now counts a NULL tenant column as foreign, and asserts
-- that an unscoped session sees nothing.
--
-- # The fix
--
-- An inner join. A notice is visible only when its client is visible, which is
-- the tenant boundary core.clients already enforces. A notice whose client has
-- since been deleted is engine state with no tenant to show it to; the engine
-- still delivers or parks it, it simply has no console screen.

SET search_path = core, public;

CREATE OR REPLACE VIEW core_v1.logout_deliveries AS
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
    CASE
        WHEN o.delivered_at IS NOT NULL THEN 'delivered'
        WHEN o.attempts >= 8            THEN 'parked'
        ELSE 'pending'
    END                                              AS status,
    CASE
        WHEN o.delivered_at IS NOT NULL THEN o.delivered_at - o.created_at
        ELSE now() - o.created_at
    END                                              AS age
FROM core.outbox o
JOIN core.clients c ON c.client_id = o.payload->>'client_id'
WHERE o.topic = 'backchannel_logout';
