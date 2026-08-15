CREATE TABLE IF NOT EXISTS core.scim_sources (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    slug          text NOT NULL,
    display_name  text NOT NULL,

    -- SHA-256 of the bearer token. The token itself is shown once, at creation,
    -- and never stored: a provisioning credential sitting in a table is one
    -- database read away from being every account in the organisation.
    token_hash    bytea NOT NULL,

    on_delete     text NOT NULL DEFAULT 'deactivate',

    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz,

    CONSTRAINT scim_sources_slug_unique UNIQUE (org_id, slug),
    CONSTRAINT scim_sources_on_delete_known CHECK (on_delete IN ('deactivate', 'delete'))
);

CREATE INDEX IF NOT EXISTS scim_sources_token ON core.scim_sources (token_hash);

-- The link between an upstream's identifier and a local user.
--
-- externalId is the upstream's immutable id and is the ONLY thing matched on.
-- Not userName, not email: both change when somebody marries, and matching on
-- either turns a rename into a departure plus an arrival -- one account
-- deactivated, one created, and the person locked out of everything they owned.
CREATE TABLE IF NOT EXISTS core.scim_source_links (
    source_id    uuid NOT NULL REFERENCES core.scim_sources(id) ON DELETE CASCADE,
    external_id  text NOT NULL,
    user_id      uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    -- The SCIM resource id we hand back. Distinct from user_id so the two can
    -- diverge later without an upstream having to re-learn every id.
    resource_id  uuid NOT NULL DEFAULT gen_random_uuid(),
    user_name    text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (source_id, external_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS scim_source_links_resource
    ON core.scim_source_links (source_id, resource_id);
-- One upstream identity per local user per source. Without this, two upstream
-- records could both claim the same person and each would overwrite the other.
CREATE UNIQUE INDEX IF NOT EXISTS scim_source_links_user
    ON core.scim_source_links (source_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS scim_source_links_username
    ON core.scim_source_links (source_id, lower(user_name));

ALTER TABLE core.scim_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.scim_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_sources_org_isolation ON core.scim_sources;
CREATE POLICY scim_sources_org_isolation ON core.scim_sources
    USING (core.is_engine() OR org_id = core.current_org_id());

-- The display name lives on the LINK, not on core.users.
--
-- core.users has no display_name column, deliberately: a name is a fact one
-- upstream asserts, and two upstreams asserting different names about the same
-- person is a conflict with no correct resolution. core.directory_links already
-- keeps remote_name for exactly this reason, and inbound SCIM follows it rather
-- than inventing a second convention.
ALTER TABLE core.scim_source_links
    ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '';
