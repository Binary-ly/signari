-- 0018_engine_rls_access.sql
--
-- THE ENGINE COULD NOT READ ITS OWN TABLES.
--
-- Every tenant table carries `USING (org_id = core.current_org_id())` under
-- FORCE ROW LEVEL SECURITY. That was written for the console (ADR-006): the
-- core_v1 views execute with the owner's privileges, so without FORCE the owner
-- would bypass its own policies and the console would see every tenant.
--
-- But the ENGINE connects as signari_engine and never sets app.org_id -- it
-- cannot, because it looks a client up BEFORE it knows which organisation the
-- client belongs to. So current_org_id() is NULL, `org_id = NULL` is NULL, and
-- every query returns nothing:
--
--     as signari_engine, no app.org_id:
--       core.users   0 rows
--       core.clients 0 rows
--
-- Nothing caught this because development connects with a superuser DSN, and
-- superusers bypass RLS entirely. The product worked in every test and would
-- have failed completely on the first correctly-configured deployment, with
-- "unknown client" for every request.
--
-- # The fix, and why it is session_user
--
-- The discriminator must be something the console CANNOT set. Three candidates:
--
--   * A session setting (app.engine = on) -- NO. The console runs SQL on its own
--     connection and could simply set it, which makes it a suggestion.
--   * current_user -- NO. Inside a core_v1 view it is already signari_engine,
--     because the view executes as its owner. It cannot tell the two apart.
--   * session_user -- YES. It is the role that AUTHENTICATED, it does not change
--     inside a view, and SET ROLE does not change it. Only SET SESSION
--     AUTHORIZATION does, and that needs superuser.
--
-- So the engine gets full access by virtue of having connected as itself, and
-- the console -- which authenticates as signari_admin and reads through views
-- that run as signari_engine -- stays filtered by app.org_id exactly as before.

SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.is_engine() RETURNS boolean
LANGUAGE sql STABLE AS $$
    -- session_user, NOT current_user: inside a view owned by signari_engine,
    -- current_user is already signari_engine and would grant the console
    -- everything. session_user remains whoever actually authenticated.
    SELECT session_user = 'signari_engine'
$$;

DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'projects','users','password_credentials','webauthn_credentials',
        'totp_credentials','clients','sessions','authorization_codes',
        'refresh_token_families','access_tokens','recovery_codes',
        'recovery_requests','migration_sources','proxy_hosts'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        IF to_regclass('core.'||t) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format('DROP POLICY IF EXISTS %I_org_isolation ON core.%I', t, t);
        EXECUTE format($f$
            CREATE POLICY %I_org_isolation ON core.%I
            USING (core.is_engine() OR org_id = core.current_org_id())
            WITH CHECK (core.is_engine() OR org_id = core.current_org_id())
        $f$, t, t);
    END LOOP;
END
$$;
