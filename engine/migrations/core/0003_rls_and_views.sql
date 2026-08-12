-- 0003_rls_and_views.sql
-- Row-level security as a backstop, and the versioned read-only view contract.

SET search_path = core, public;

-- ===========================================================================
-- Row-level security
-- ===========================================================================
-- Application-level `WHERE org_id = $1` is PRIMARY. RLS is defence in depth.
-- Writing the predicate explicitly means a missing RLS context fails closed
-- (no rows) rather than silently returning everything.
--
-- Two traps, both of which silently disable the protection you think you have:
--
--   1. FORCE. The table OWNER bypasses RLS by default, and signari_engine owns these
--      tables. Without FORCE, every policy below is decorative.
--
--   2. SET LOCAL, never SET. `SET` persists on the connection; with any pooled
--      connection the next tenant inherits the previous tenant's context. This
--      is the single most common RLS bug in pooled Go and PHP applications.
--      The engine must issue: SET LOCAL app.org_id = '<uuid>'; inside the txn.

CREATE OR REPLACE FUNCTION core.current_org_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('app.org_id', true), '')::uuid
$$;

DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'projects','users','password_credentials','webauthn_credentials',
        'totp_credentials','clients','sessions','authorization_codes',
        'refresh_token_families','access_tokens'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE core.%I ENABLE ROW LEVEL SECURITY', t);
        -- Without FORCE this is a no-op for the owning role.
        EXECUTE format('ALTER TABLE core.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY %I_org_isolation ON core.%I
            USING (org_id = core.current_org_id())
            WITH CHECK (org_id = core.current_org_id())
        $f$, t, t);
    END LOOP;
END
$$;

-- Cross-org maintenance (key rotation, expiry sweeps, the bootstrap CLI) runs as
-- signari_maintenance, which is BYPASSRLS. That role is created in 0001, because
-- CREATE ROLE requires superuser and this migration runs as signari_engine.

-- ===========================================================================
-- core_v1 -- the contract with the Laravel admin
-- ===========================================================================
-- Laravel gets Eloquent-shaped reads without ever touching a core table. The
-- views are versioned: core_v1 stays stable while the physical tables move
-- underneath, which is also what makes N/N-1 engine deploys survivable.
--
-- Rules for anything exposed here:
--   * No secrets. No hashes, no wrapped keys, no encrypted blobs, no tokens.
--   * Additive changes only within a version. A breaking change means core_v2.

CREATE OR REPLACE VIEW core_v1.organizations AS
SELECT id, instance_id, slug, display_name, status, created_at, updated_at
FROM core.organizations;

CREATE OR REPLACE VIEW core_v1.users AS
SELECT
    u.id,
    u.org_id,
    u.username,
    u.email,
    u.email_verified_at,
    u.status,
    u.migration_state,
    u.created_at,
    u.updated_at,
    (pc.user_id IS NOT NULL)                       AS has_password,
    COALESCE(pc.is_current, true)                  AS password_is_current,
    (SELECT count(*) FROM core.webauthn_credentials w WHERE w.user_id = u.id) AS passkey_count,
    (tc.confirmed_at IS NOT NULL)                  AS totp_enabled
FROM core.users u
LEFT JOIN core.password_credentials pc ON pc.user_id = u.id
LEFT JOIN core.totp_credentials     tc ON tc.user_id = u.id;

CREATE OR REPLACE VIEW core_v1.clients AS
SELECT
    c.client_id,
    c.org_id,
    c.project_id,
    c.display_name,
    c.client_type,
    c.enabled,
    c.grant_types,
    c.response_types,
    c.scopes,
    c.require_pkce,
    c.id_token_signed_alg,
    c.access_token_format,
    c.access_token_ttl_s,
    c.refresh_token_ttl_s,
    c.backchannel_logout_uri,
    c.created_at,
    c.updated_at,
    ARRAY(SELECT r.redirect_uri FROM core.client_redirect_uris r
          WHERE r.client_id = c.client_id ORDER BY r.redirect_uri) AS redirect_uris
FROM core.clients c;

CREATE OR REPLACE VIEW core_v1.sessions AS
SELECT
    s.sid, s.org_id, s.user_id, s.acr, s.amr, s.auth_time,
    s.revoked_at, s.revocation_reason, s.not_after, s.user_agent, s.created_at,
    (s.revoked_at IS NULL AND s.not_after > now()) AS is_live
FROM core.sessions s;

CREATE OR REPLACE VIEW core_v1.audit_events AS
SELECT id, org_id, occurred_at, event_type, subject_id, actor_id,
       client_id, correlation_id, retention_class, detail
FROM core.audit_events;

-- Operator-facing health: "3 of 3 nodes at version 4471". Surfacing config-version
-- lag per node in the admin UI is something no product in this field ships.
CREATE OR REPLACE VIEW core_v1.config_status AS
SELECT version, bumped_at FROM core.config_version;

GRANT USAGE ON SCHEMA core_v1 TO signari_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA core_v1 TO signari_admin;

-- The views read core tables, so the admin needs to reach through them. Views
-- run with the OWNER's privileges (security invoker is off by default), which is
-- exactly what we want: signari_admin gets the view, never the table.
--
-- VERIFIED CONSEQUENCE (measured, not assumed -- see ADR-006):
--   The owner is signari_engine, and signari_engine is subject to FORCE ROW LEVEL
--   SECURITY. So a SELECT from core_v1.* by signari_admin returns ZERO ROWS unless
--   the admin's transaction has also done:
--
--       SET LOCAL app.org_id = '<uuid>';
--
--   This is a feature, not a bug: the Laravel admin is subject to exactly the
--   same database-enforced tenant isolation as the engine. Laravel must set the
--   org context per request, in-transaction, from the authenticated admin's
--   selected org -- never as a connection-level SET.
--
--   Cross-org / instance-level reads (the "list every org" screen) deliberately
--   do NOT go through these views. They go through the Admin API, which runs as
--   signari_maintenance. That keeps "see all tenants" an explicit, audited API call
--   rather than an ambient property of a database role.
