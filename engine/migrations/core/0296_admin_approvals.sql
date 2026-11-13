-- signari:compatible-with-previous
--
-- 0296_admin_approvals.sql
--
-- A second person for the Admin API's highest-value changes (ASVS 5.0.0 V2.3.5): an
-- organisation names which of them need one in approvals_required, and such a request is kept
-- here, pending, until somebody else who may make it approves it, which replays it as theirs,
-- or it is rejected or expires. The kinds are an erasure, which cannot be undone, and granting
-- the org-owner role, which is every other permission at once; relaxing the setting itself
-- needs a second person too, or one token could turn the rule off and then act alone.
-- Compatible with the previous release, which ignores both: there every such request runs at
-- once, as it always did.

ALTER TABLE core.organizations
    ADD COLUMN approvals_required text[] NOT NULL DEFAULT '{}'
        CHECK (approvals_required <@ ARRAY['subject_erasure', 'owner_grant']::text[]);

COMMENT ON COLUMN core.organizations.approvals_required IS
    'the Admin API changes that wait for a second person: subject_erasure, owner_grant';

CREATE TABLE core.admin_approvals (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    kind           text        NOT NULL
                               CHECK (kind IN ('subject_erasure', 'owner_grant', 'approvals_relaxed')),
    -- The request as it came, replayed through the router on approval. The body is cleared
    -- once it is decided, so nothing waits here longer than the request did.
    method         text        NOT NULL,
    path           text        NOT NULL CHECK (path LIKE '/admin/%'),
    body           bytea       NOT NULL DEFAULT ''::bytea,
    summary        text        NOT NULL,
    -- Who asked and who decided: a token as token:<id>, a person as user:<id>, the
    -- environment token as break-glass. One may not decide what it asked for.
    requested_by   text        NOT NULL,
    requested_name text        NOT NULL,
    requested_at   timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    status         text        NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'approving', 'approved', 'rejected')),
    decided_by     text,
    decided_name   text,
    decided_at     timestamptz,
    result_status  integer,
    CHECK ((status IN ('pending', 'approving')) = (decided_at IS NULL))
);

CREATE INDEX admin_approvals_org ON core.admin_approvals (org_id, requested_at);

ALTER TABLE core.admin_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.admin_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_approvals_org_isolation ON core.admin_approvals
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.admin_approvals TO signari_maintenance;

CREATE TRIGGER admin_approvals_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.admin_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.admin_approvals IS
    'Admin API requests waiting for a second person (approvals_required), and how each was decided';
