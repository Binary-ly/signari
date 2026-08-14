-- 0021_saml_logout_progress.sql
--
-- Front-channel single logout is a redirect CHAIN, and a chain needs state.
--
-- The browser visits each service provider's logout endpoint in turn, and each
-- one sends it back to us. Between hops we have to remember who is left. There
-- is nowhere else to put that:
--
--   * A cookie would be readable and editable by the user, and it names the
--     providers to contact -- an attacker could rewrite it to point at their own
--     endpoint and have a browser carrying our signature visit it.
--   * The URL would carry it through third-party redirects, into every referrer
--     header and access log along the way.
--
-- So it lives here, keyed by a token whose HASH is stored -- the same rule the
-- rest of this schema follows for anything a client holds.

SET search_path = core, public;

CREATE TABLE saml_logout_progress (
    -- SHA-256 of the token in the RelayState. Storing the token itself would
    -- mean a database read discloses a live credential.
    token_hash    bytea       PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- No foreign key to sessions: the session is ALREADY terminated before the
    -- chain starts. Signing out here does not wait on service providers, and a
    -- reference would either block that or dangle.
    sid           text        NOT NULL,
    user_id       uuid        REFERENCES users(id) ON DELETE SET NULL,

    -- Providers still to visit, and those already done, each entry carrying the
    -- NameID and SessionIndex the assertion used -- an SP matches on those, and
    -- a LogoutRequest with anything else ends nothing while reporting success.
    remaining     jsonb       NOT NULL DEFAULT '[]',
    notified      jsonb       NOT NULL DEFAULT '[]',
    failed        jsonb       NOT NULL DEFAULT '[]',

    -- Where the browser goes once the chain finishes. Validated when the chain
    -- STARTS, so the value stored here is already known-good and nothing can
    -- influence it in between.
    final_redirect text,

    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Short. A chain that has not finished in this long is not going to: the
    -- user closed the tab, or a provider never redirected back.
    expires_at    timestamptz NOT NULL DEFAULT now() + interval '5 minutes'
);

CREATE INDEX saml_logout_progress_expiry_idx ON saml_logout_progress (expires_at);

ALTER TABLE saml_logout_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_logout_progress FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_logout_progress_org_isolation ON saml_logout_progress
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON saml_logout_progress TO signari_maintenance;
