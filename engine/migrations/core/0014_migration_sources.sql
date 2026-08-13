
SET search_path = core, public;

CREATE TABLE migration_sources (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- 'oidc_password' is the resource-owner password grant against the old
    -- provider. We removed that grant from our OWN server because it is unsafe
    -- to OFFER; using it as a CLIENT against a system that offers it is the one
    -- legitimate remaining use, and it is temporary by construction.
    kind           text        NOT NULL CHECK (kind IN ('oidc_password')),

    display_name   text        NOT NULL,
    token_endpoint text        NOT NULL,
    client_id      text        NOT NULL,
    -- Encrypted with the root key. Never the bare secret.
    client_secret_enc bytea,
    scope          text        NOT NULL DEFAULT 'openid',

    -- Off by default. A misconfigured source that is live forwards every failed
    -- password in the deployment to a third party, so enabling it is a decision
    -- someone makes rather than a state it arrives in.
    enabled        boolean     NOT NULL DEFAULT false,

    -- Operational counters, so the cutover dashboard can show progress without
    -- scanning the audit log.
    delegated_successes bigint NOT NULL DEFAULT 0,
    delegated_failures  bigint NOT NULL DEFAULT 0,
    last_used_at   timestamptz,
    last_error     text,

    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- One source per organisation. Two would mean a password is tried against
-- several third parties on every login, which multiplies both the latency and
-- the number of systems learning a user's credential.
CREATE UNIQUE INDEX migration_sources_one_per_org ON migration_sources (org_id);

ALTER TABLE migration_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE migration_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_sources_org_isolation ON migration_sources
    USING (org_id = core.current_org_id())
    WITH CHECK (org_id = core.current_org_id());

-- Which source a user came from, so the dashboard can report progress per
-- system and so a delegated login knows where to ask.
ALTER TABLE users
    ADD COLUMN migration_source_id uuid REFERENCES migration_sources(id) ON DELETE SET NULL,
    ADD COLUMN migrated_at timestamptz;

-- The cutover view: the numbers a migration is actually run on.
CREATE VIEW core_v1.migration_progress AS
SELECT
    u.org_id,
    s.display_name                                     AS source,
    count(*)                                           AS total_users,
    count(*) FILTER (WHERE u.migration_state = 'complete') AS migrated,
    count(*) FILTER (WHERE u.migration_state = 'pending')  AS remaining,
    -- Users who have never signed in are the ones a cutover date depends on:
    -- they are the population that will be locked out on the day the old system
    -- is switched off.
    count(*) FILTER (WHERE u.migration_state = 'pending' AND u.migrated_at IS NULL) AS never_seen,
    max(u.migrated_at)                                 AS last_migration
FROM core.users u
LEFT JOIN core.migration_sources s ON s.id = u.migration_source_id
WHERE u.migration_state <> 'none'
GROUP BY u.org_id, s.display_name;

GRANT SELECT ON core_v1.migration_progress TO signari_admin;
