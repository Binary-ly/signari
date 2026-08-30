-- 0110_organizations_rls.sql
--
-- Stop the console enumerating every organisation on the instance.
--
-- # This one WAS a live hole, and it was measured rather than argued
--
-- 0092 closed the tenant boundary on fifty-eight tables and was careful to say
-- it was defence in depth rather than a live fix, because `signari_admin` has no
-- grants on `core` at all. That reasoning was right for the tables it covered
-- and did not reach this one, because the console does not need a grant on
-- `core.organizations` -- it reads `core_v1.organizations`, the view runs with
-- the owner's privileges, and the owner is only constrained where the base table
-- FORCEs row-level security. `core.organizations` did not.
--
-- Measured on a database with 6,896 organisations, as signari_admin with
-- app.org_id set to exactly one of them:
--
--     SELECT count(*) FROM core_v1.organizations;  -> 6896
--     SELECT count(*) FROM core_v1.users;          ->   16
--
-- `users` is correct: it FORCEs RLS, so the view returns one tenant's rows.
-- `organizations` returned every tenant's name, slug, status and creation date.
-- ADR-004 and ADR-006 both state that a query with no org context returns zero
-- rows rather than all rows; for this table the opposite was true.
--
-- # Why the completeness pass missed it
--
-- 0092 iterates the tables carrying an `org_id` column and applies
-- `org_id = core.current_org_id()`. An organisation's tenant key is its own `id`,
-- so it was not in the list -- not excluded on purpose, just not matched by the
-- shape the loop looks for. `core.instances` is absent for the same reason and
-- is deliberately left alone here: it is not exposed through any core_v1 view,
-- so nothing that authenticates can read it, and scoping it would need a
-- subquery through organizations for no reader that exists.
--
-- ASVS 5.0.0 V8.4.1, the same requirement 0092 cites.

SET search_path = core, public;

ALTER TABLE core.organizations ENABLE ROW LEVEL SECURITY;
-- Without FORCE this is a no-op for signari_engine, which owns the table -- and
-- the view runs as the owner, so without FORCE the console would still see
-- everything and this migration would look like it had worked.
ALTER TABLE core.organizations FORCE ROW LEVEL SECURITY;

CREATE POLICY organizations_org_isolation ON core.organizations
    -- `id`, not `org_id`: an organisation IS the tenant.
    --
    -- is_engine() reads session_user rather than current_user, so it stays false
    -- inside this view even though the view is owned by signari_engine. That
    -- distinction is what makes the policy bind on the console at all; see 0018.
    USING (core.is_engine() OR id = core.current_org_id())
    WITH CHECK (core.is_engine() OR id = core.current_org_id());

COMMENT ON POLICY organizations_org_isolation ON core.organizations IS
    'A console session scoped to one organisation sees one organisation. '
    'Before this policy it saw every organisation on the instance through '
    'core_v1.organizations, because the view runs as the table owner and the '
    'table did not FORCE row-level security.';
