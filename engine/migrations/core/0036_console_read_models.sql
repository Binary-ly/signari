-- Console visibility for everything built after the first week.
--
-- SAML service providers, external sign-in providers, groups, SCIM targets and
-- admin tokens all work and are all CLI-only. An operator who wants to know what
-- is configured has to SSH somewhere, which means in practice nobody looks --
-- and the half-configurations `signari doctor` reports are exactly the ones that
-- go unnoticed for months.
--
-- Read models only. Writes still go through the engine's Admin API (ADR-004);
-- the console has no privilege on schema `core` and this changes none of that.

SET search_path = core, public;

-- # Row-level security on admin_tokens
--
-- This table was added without it, while every other tenant table has RLS
-- FORCED. That was an oversight and it matters now that the console reads it: an
-- org-scoped token row is tenant data, and without a policy a console query
-- would return every tenant's tokens.
--
-- core.is_engine() is what keeps authentication working. The engine looks a
-- token up BEFORE it knows which organisation the caller belongs to -- that is
-- the whole point of the lookup -- so it has no org context to match against.
-- Without the bypass every admin request would 401, and the failure would look
-- like a credential problem rather than a policy one.
ALTER TABLE core.admin_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.admin_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY admin_tokens_org_isolation ON core.admin_tokens
    -- A NULL org_id means "every organisation", and such a token is deliberately
    -- NOT visible to a tenant console: it is a deployment-wide credential, and
    -- listing it for one tenant would disclose that another tenant's data is
    -- reachable with it.
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

-- SAML service providers.
CREATE VIEW core_v1.saml_providers AS
SELECT
    p.id,
    p.org_id,
    p.entity_id,
    p.display_name,
    p.name_id_format,
    p.enabled,
    p.want_authn_requests_signed,
    (p.sp_signing_cert IS NOT NULL)    AS has_signing_cert,
    (p.sp_encryption_cert IS NOT NULL) AS assertions_encrypted,
    p.lifetime_seconds,
    (SELECT count(*) FROM core.saml_acs_urls a WHERE a.provider_id = p.id) AS acs_url_count,
    (SELECT u.url FROM core.saml_slo_urls u WHERE u.provider_id = p.id ORDER BY u.url LIMIT 1)
        AS logout_url,
    -- The half-configurations, named here so the console can show them rather
    -- than making an operator infer them from three separate columns.
    CASE
        WHEN p.want_authn_requests_signed AND p.sp_signing_cert IS NULL
            THEN 'signing required, no certificate'
        WHEN EXISTS (SELECT 1 FROM core.saml_slo_urls u WHERE u.provider_id = p.id)
             AND p.sp_signing_cert IS NULL
            THEN 'logout configured, no certificate'
        WHEN NOT p.enabled THEN 'disabled'
        ELSE 'ok'
    END AS config_state,
    p.created_at
FROM core.saml_providers p;

-- External sign-in providers.
CREATE VIEW core_v1.identity_providers AS
SELECT
    i.id,
    i.org_id,
    i.slug,
    i.display_name,
    i.kind,
    i.enabled,
    i.allow_signup,
    i.allow_linking,
    i.trust_email_verification,
    i.issuer,
    CASE
        WHEN NOT i.enabled THEN 'disabled'
        WHEN i.allow_signup AND i.kind = 'oidc' AND NOT i.trust_email_verification
            THEN 'sign-up will refuse: email verification not trusted'
        ELSE 'ok'
    END AS config_state,
    i.created_at
FROM core.identity_providers i;

-- Groups, with membership counts. The count is what an operator actually looks
-- for, and computing it in the view keeps it out of an N+1 in the console.
CREATE VIEW core_v1.groups AS
SELECT
    g.id,
    g.org_id,
    g.name,
    g.display_name,
    g.description,
    (SELECT count(*) FROM core.group_members m WHERE m.group_id = g.id) AS member_count,
    -- Releases name groups by NAME, not by id, and there are two kinds: OIDC
    -- clients and SAML providers. Counted separately because "this group is
    -- visible somewhere" and "visible to whom" are different questions, and the
    -- second is the one that matters before renaming a group.
    (SELECT count(*) FROM core.client_group_release r
      WHERE r.org_id = g.org_id AND g.name = ANY(r.only_groups)) AS released_to_clients,
    (SELECT count(*) FROM core.saml_group_release r
      WHERE r.org_id = g.org_id AND g.name = ANY(r.only_groups)) AS released_to_saml,
    g.created_at
FROM core.groups g;

-- SCIM provisioning targets.
CREATE VIEW core_v1.scim_targets AS
SELECT
    t.id,
    t.org_id,
    t.slug,
    t.display_name,
    t.base_url,
    t.enabled,
    t.on_deactivate,
    t.dry_run,
    -- Sync state is not stored on the target; it lives per user in scim_links.
    -- Derived here so the console can answer "is this thing actually running"
    -- without a second query per row.
    (SELECT count(*) FROM core.scim_links l WHERE l.target_id = t.id) AS linked_users,
    (SELECT max(l.last_synced_at) FROM core.scim_links l WHERE l.target_id = t.id)
        AS last_synced_at,
    (SELECT count(*) FROM core.scim_links l
      WHERE l.target_id = t.id AND NOT l.should_be_active) AS pending_deactivations,
    CASE
        WHEN NOT t.enabled THEN 'disabled'
        WHEN t.dry_run     THEN 'dry run: nothing is written'
        WHEN NOT EXISTS (SELECT 1 FROM core.scim_links l WHERE l.target_id = t.id)
            THEN 'never synced'
        ELSE 'ok'
    END AS config_state,
    t.created_at
FROM core.scim_targets t;

-- Admin API tokens. The secret is a hash and is not exposed here, nor anywhere
-- else -- there is no path in this system that reveals a token after it is
-- minted.
CREATE VIEW core_v1.admin_tokens AS
SELECT
    t.id,
    t.org_id,
    t.name,
    t.scopes,
    t.created_at,
    t.expires_at,
    t.revoked_at,
    t.last_used_at,
    CASE
        WHEN t.revoked_at IS NOT NULL                     THEN 'revoked'
        WHEN t.expires_at IS NOT NULL AND t.expires_at <= now() THEN 'expired'
        WHEN t.expires_at IS NOT NULL AND t.expires_at < now() + interval '14 days'
            THEN 'expiring soon'
        WHEN t.last_used_at IS NULL AND t.created_at < now() - interval '30 days'
            THEN 'never used'
        ELSE 'active'
    END AS state
FROM core.admin_tokens t;

GRANT SELECT ON core_v1.saml_providers     TO signari_admin;
GRANT SELECT ON core_v1.identity_providers TO signari_admin;
GRANT SELECT ON core_v1.groups             TO signari_admin;
GRANT SELECT ON core_v1.scim_targets       TO signari_admin;
GRANT SELECT ON core_v1.admin_tokens       TO signari_admin;
