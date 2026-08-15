
SET search_path = core, public;

CREATE TABLE core.directory_sources (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    kind        text NOT NULL CHECK (kind IN ('google','entra')),
    slug        text NOT NULL,
    display_name text NOT NULL,

    -- Sealed with the root key. A service account key or client secret is a
    -- standing credential for somebody's entire directory, which makes this the
    -- single most valuable row in the database.
    credentials_enc bytea NOT NULL,

    -- Google: the Workspace domain, and the admin to impersonate (service
    -- accounts read nothing without domain-wide delegation and a subject).
    -- Entra: the tenant id.
    domain      text,
    impersonate text,
    tenant_id   text,

    -- Which people. Empty means everybody the credential can see, which is a
    -- decision rather than a default -- so it is recorded either way.
    user_filter text NOT NULL DEFAULT '',

    enabled     boolean NOT NULL DEFAULT true,

    -- TRUE by default. A source that writes nothing until somebody says so is
    -- the only safe way to introduce one.
    dry_run     boolean NOT NULL DEFAULT true,

    -- What to do about a local user the remote directory no longer returns.
    --
    -- 'report' is the default and does nothing but say so. 'deactivate' is what
    -- most people eventually want and is exactly the setting that turns a bad
    -- fetch into an outage, so it is never the starting point.
    on_missing  text NOT NULL DEFAULT 'report'
                CHECK (on_missing IN ('report','deactivate')),

    -- The ceiling. If a sync would deactivate more than this share of the
    -- organisation's active users, the WHOLE sync is refused -- not truncated,
    -- not partially applied.
    --
    -- Twenty percent because real attrition is a trickle and a cliff is almost
    -- always a bug. An organisation genuinely offboarding a third of its people
    -- can raise it for the day, which is a conversation somebody has rather than
    -- something a cron job decides alone.
    max_deactivate_percent int NOT NULL DEFAULT 20
                CHECK (max_deactivate_percent BETWEEN 0 AND 100),

    last_sync_at    timestamptz,
    last_error      text,
    -- Counts from the last run, so the console can show what a sync DID without
    -- re-reading a log.
    last_created    int NOT NULL DEFAULT 0,
    last_updated    int NOT NULL DEFAULT 0,
    last_deactivated int NOT NULL DEFAULT 0,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, slug)
);

CREATE INDEX directory_sources_org_idx ON core.directory_sources (org_id);

ALTER TABLE core.directory_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.directory_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_sources_org_isolation ON core.directory_sources
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

-- Which local user corresponds to which remote one.
--
-- Keyed on the remote's immutable id, never on email. People change their email
-- address; matching on it would make a rename look like a departure and an
-- arrival, deactivating one account and creating another.
CREATE TABLE core.directory_links (
    source_id   uuid NOT NULL REFERENCES core.directory_sources(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    remote_id   text NOT NULL,
    -- Last values seen remotely, so an update can be detected without a second
    -- round trip and so a diff can be shown before it is applied.
    remote_email text NOT NULL DEFAULT '',
    remote_name  text NOT NULL DEFAULT '',

    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (source_id, remote_id),
    UNIQUE (source_id, user_id)
);

CREATE INDEX directory_links_user_idx ON core.directory_links (user_id);

ALTER TABLE core.directory_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.directory_links FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_links_org_isolation ON core.directory_links
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.directory_links IS
    'Keyed on the remote immutable id, never on email: matching on email makes a '
    'rename look like a departure plus an arrival.';

COMMENT ON COLUMN core.directory_sources.max_deactivate_percent IS
    'If a sync would deactivate more than this share of active users, the whole '
    'sync is refused. A cliff in a directory feed is almost always a bad fetch, '
    'not a redundancy round.';
