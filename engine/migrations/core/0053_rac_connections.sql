-- Remote access: which hosts a person may reach through the browser.
--
-- guacd speaks RDP, VNC and SSH, and has no concept of a user. It connects to
-- whatever it is told to connect to, with whatever credentials it is given.
-- Everything that makes remote access safe lives here: who may reach what, and
-- what is recorded.
--
-- # Credentials are sealed
--
-- A row here can carry a password or a private key for a machine somebody
-- administers. Sealed with the root key like every other stored secret, so a
-- database read is not a set of working logins to the estate.
CREATE TABLE IF NOT EXISTS core.rac_connections (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    slug          text NOT NULL,
    display_name  text NOT NULL,

    protocol      text NOT NULL,
    hostname      text NOT NULL,
    port          integer NOT NULL,

    -- Parameters guacd accepts for this protocol, as JSON. Not columns,
    -- because the set differs per protocol and per guacd version -- and a
    -- column per parameter would need a migration every time guacd gains one,
    -- while silently dropping anything it did not know about.
    parameters    jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Sealed credentials, merged over parameters at connect time so they are
    -- never in a query result or a log line.
    secrets_enc   bytea,

    -- The group a user must be in. NULL means any authenticated user in the
    -- organisation, which is deliberately explicit rather than the default:
    -- a remote desktop nobody restricted is a remote desktop everybody has.
    require_group text,

    -- Where guacd writes a session recording. NULL records nothing.
    recording_path text,

    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT rac_connections_slug_unique UNIQUE (org_id, slug),
    CONSTRAINT rac_connections_protocol_known
        CHECK (protocol IN ('rdp', 'vnc', 'ssh')),
    CONSTRAINT rac_connections_port_sane CHECK (port BETWEEN 1 AND 65535)
);

COMMENT ON COLUMN core.rac_connections.require_group IS
    'Membership required to use this connection. Enforced in addition to the '
    'access policy, never instead of it.';

ALTER TABLE core.rac_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.rac_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rac_connections_org_isolation ON core.rac_connections;
CREATE POLICY rac_connections_org_isolation ON core.rac_connections
    USING (core.is_engine() OR org_id = core.current_org_id());

-- Who connected to what, and when it ended.
--
-- Separate from the audit chain: this is operational history with a duration
-- and an end time, updated when the session closes, and the audit chain is
-- append-only by construction. The audit log records that a session STARTED;
-- this records what happened to it.
CREATE TABLE IF NOT EXISTS core.rac_sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id uuid NOT NULL REFERENCES core.rac_connections(id) ON DELETE CASCADE,
    org_id        uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,

    guacd_id      text,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    ended_reason  text,
    recording_path text
);

CREATE INDEX IF NOT EXISTS rac_sessions_user ON core.rac_sessions (user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS rac_sessions_live ON core.rac_sessions (org_id)
    WHERE ended_at IS NULL;
