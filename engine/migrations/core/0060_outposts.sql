-- Protocol servers running somewhere the database must not be reachable from.
--
-- An outpost is a Signari binary running LDAP, RADIUS or forward auth in a DMZ,
-- a branch office, or an airgapped segment, holding NO database credentials. It
-- asks the core "is this password correct" over HTTPS and forwards the answer.
--
-- # Why this is cheap here
--
-- internal/ldapd and internal/radius were written against a narrow
-- Authenticator interface and have no database references at all. An outpost is
-- therefore a second implementation of that interface, not a second
-- architecture. The other products in this field needed a whole component for
-- this because their core is a different language from their protocol servers.
CREATE TABLE core.outposts (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id  uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    name    text NOT NULL,

    -- ldap, radius or proxy. Recorded so a token issued for an LDAP outpost
    -- cannot be used to stand up a RADIUS one: an outpost token is a
    -- password-verification oracle, and the blast radius of a leaked one should
    -- be the protocol it was issued for.
    kind    text NOT NULL CHECK (kind IN ('ldap', 'radius', 'proxy')),

    -- Hashed, like every other credential here.
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),

    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),

    -- When the core last heard from it. An outpost that stops calling is an
    -- outage nobody is told about otherwise -- the protocol it served simply
    -- stops answering, somewhere the operator is not looking.
    last_seen_at timestamptz,
    last_seen_ip text,

    UNIQUE (org_id, name)
);

CREATE INDEX outposts_live_idx ON core.outposts (token_hash) WHERE enabled;

ALTER TABLE core.outposts ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.outposts FORCE ROW LEVEL SECURITY;
-- The engine hatch, without which the engine reads nothing here. See 0018, and
-- 0058 for the time this was forgotten.
CREATE POLICY outposts_org_isolation ON core.outposts
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.outposts IS
    'Remote protocol servers that verify credentials through the core rather '
    'than against the database directly.';
