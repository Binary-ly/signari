-- 0024_scim.sql
--
-- Outbound SCIM 2.0 provisioning: pushing users to downstream applications so
-- they exist there before first sign-in, and -- far more importantly -- stop
-- existing there when they leave.
--
-- # Which half actually matters
--
-- Provisioning failing is a support ticket: somebody cannot get into Slack and
-- says so within the hour. DEPROVISIONING failing is a security incident that
-- nobody reports, because the person it affects has left and the person who
-- deactivated them saw a success message.
--
-- That asymmetry shapes this schema. Every remote account we create is recorded
-- with the id the target gave it, so a later deprovision knows exactly what to
-- delete rather than searching by an attribute that may have changed. And the
-- record survives the deactivation, so `signari scim verify` can go and check
-- that the remote account is really gone.

SET search_path = core, public;

CREATE TABLE scim_targets (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    slug         text        NOT NULL,
    display_name text        NOT NULL,
    -- The SCIM base URL, e.g. https://api.slack.com/scim/v2. Endpoints are
    -- appended to it; the specification fixes their names.
    base_url     text        NOT NULL,
    -- Bearer token, sealed with the root key. This credential can usually create
    -- and delete accounts in the target system, which makes it considerably more
    -- valuable than most things in this database.
    token        bytea       NOT NULL,

    -- Whether to actually send. Off means "record what WOULD be sent" -- see
    -- the dry_run column, which exists because the first thing anybody wants to
    -- know is what a new integration is about to do to their production Slack.
    enabled      boolean     NOT NULL DEFAULT true,
    dry_run      boolean     NOT NULL DEFAULT false,

    -- What deactivating a user should do remotely.
    --
    -- `deactivate` (PATCH active=false) is the default and is almost always
    -- right: it keeps the account's history and is reversible. `delete` is
    -- offered because some targets bill per account and some compliance regimes
    -- require removal.
    on_deactivate text      NOT NULL DEFAULT 'deactivate'
                            CHECK (on_deactivate IN ('deactivate','delete','nothing')),

    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug),
    CONSTRAINT scim_targets_https CHECK (base_url LIKE 'https://%')
);

-- What we believe exists in each target.
--
-- The remote id is the load-bearing column. Deprovisioning by searching for a
-- username or email is how the wrong account gets deleted after somebody
-- changes their address -- or, worse, how the right one is missed and left
-- active.
CREATE TABLE scim_links (
    target_id    uuid        NOT NULL REFERENCES scim_targets(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    remote_id    text        NOT NULL,
    -- What we last successfully sent, so a verify can tell "never synced" from
    -- "synced and then drifted".
    last_synced_at timestamptz,
    -- Our intent for the remote account. Compared against reality by verify.
    should_be_active boolean NOT NULL DEFAULT true,

    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (target_id, user_id),
    UNIQUE (target_id, remote_id)
);

CREATE INDEX scim_links_user_idx ON scim_links (user_id);
-- The index that matters for the security question: which remote accounts are
-- supposed to be gone.
CREATE INDEX scim_links_should_be_inactive_idx ON scim_links (target_id)
    WHERE NOT should_be_active;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['scim_targets','scim_links'] LOOP
        EXECUTE format('ALTER TABLE core.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE core.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY %I_org_isolation ON core.%I
            USING (core.is_engine() OR org_id = core.current_org_id())
            WITH CHECK (core.is_engine() OR org_id = core.current_org_id())
        $f$, t, t);
    END LOOP;
END
$$;

GRANT SELECT ON scim_targets, scim_links TO signari_maintenance;
