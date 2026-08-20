-- 0092_rls_completeness.sql
--
-- Close the tenant boundary on every table that carries org_id.
--
-- ASVS 5.0.0 V8.4.1: "Verify that multi-tenant applications use cross-tenant
-- controls to ensure consumer operations will never affect tenants with which
-- they do not have permissions to interact."
--
-- # What the audit found
--
-- Forty-odd org-scoped tables enforce that boundary in the database, with the
-- same policy on each: `core.is_engine() OR org_id = core.current_org_id()`.
-- Eighteen did not, in two different ways: eleven had no row-level security at
-- all, and seven had a policy but no FORCE.
--
-- The FORCE distinction is the one worth understanding. Core tables are owned by
-- `signari_engine`, and PostgreSQL lets a table's owner bypass row-level
-- security unless FORCE is set. So on those seven the policy did nothing for the
-- engine -- not because anyone decided that, but because it is a PostgreSQL
-- default. With FORCE, the engine still passes, via the `is_engine()` clause
-- written in the policy where a reader can see it.
--
-- # This is NOT closing a live cross-tenant hole, and the first draft of this
-- # comment said it was
--
-- The claim was that the console could reach other tenants' rows in the eleven
-- unprotected tables. That was wrong, and checking the roles rather than
-- assuming would have caught it sooner:
--
--   signari_admin        the Laravel console. ZERO grants on core; it reads
--                        fifteen views in core_v1 and nothing else. It could not
--                        reach these tables with or without RLS.
--   signari_maintenance  NOLOGIN, BYPASSRLS, reachable only via SET ROLE. Its
--                        exemption is deliberate and documented in 0003: "Cross-
--                        org maintenance (key rotation, expiry sweeps, the
--                        bootstrap CLI) runs as signari_maintenance."
--   signari_engine       the owner, and every query it issues already filters by
--                        org_id.
--
-- So no role that connects today was crossing tenants, and none could have. What
-- this migration buys is uniformity: fifty-eight org-scoped tables now behave
-- identically, `is_engine()` is the single visible escape rather than one escape
-- plus a silent ownership default, and a role added later inherits the boundary
-- instead of inheriting eleven exceptions nobody remembers.
--
-- That is worth having on its own terms. It is defence in depth, and saying so
-- is more useful than the stronger claim, which was false.

SET search_path = core, public;

-- 1. The eleven with no policy at all.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'attestation_challenges','audit_events','authorization_detail_types',
        'client_attesters','client_authorization_detail_types',
        'credential_configurations','credential_nonces','duo_challenges',
        'duo_enrollments','preauthorized_codes','rac_sessions'
    ] LOOP
        EXECUTE format('ALTER TABLE core.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE core.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$
            CREATE POLICY %I ON core.%I
            USING (core.is_engine() OR org_id = core.current_org_id())
            WITH CHECK (core.is_engine() OR org_id = core.current_org_id())
        $p$, t || '_org_isolation', t);
    END LOOP;
END $$;

-- 2. The seven that had a policy the owner was silently bypassing.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'authorization_models','event_deliveries','event_subscriptions',
        'impersonations','relations','ssf_received','ssf_sources'
    ] LOOP
        EXECUTE format('ALTER TABLE core.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;

COMMENT ON FUNCTION core.is_engine() IS
    'The single deliberate escape from tenant isolation. Every org-scoped table '
    'now FORCEs row-level security, so this function is the only way past the '
    'boundary and it is visible in every policy rather than implied by table '
    'ownership.';
