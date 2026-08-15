-- RADIUS clients: the network devices permitted to ask.
--
-- # Why this table exists at all
--
-- internal/radius has been complete and tested since it was written, and NOTHING
-- IMPORTED IT. There was no listener, no configuration and no way to start one:
-- a fully working package that could not be run, while the roadmap said "RADIUS
-- — DONE". That is exactly the pattern this project punishes elsewhere -- an
-- endpoint advertised in discovery before it works -- and it went unnoticed here
-- because every test passed. Tests prove a package behaves; they say nothing
-- about whether anything calls it.
--
-- # Why the secret is encrypted rather than hashed
--
-- Everywhere else a credential is stored, it is hashed. Not here, and the reason
-- is the protocol: RADIUS authenticates a request by computing HMAC-MD5 over it
-- with the shared secret, so the server needs the secret itself, not a
-- verifier. It is sealed with the ROOT key rather than a subject key, because
-- this is organisation configuration that must survive erasing any individual
-- user.
--
-- # Why a CIDR and not a hostname
--
-- RADIUS has no handshake and no certificate. The shared secret and the source
-- address are the only two things distinguishing a real switch from anybody who
-- can send a UDP packet, so the address range is part of the credential rather
-- than a convenience.

SET search_path = core, public;

CREATE TABLE core.radius_clients (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- What this device is, in words: "office wifi controller", not "client 2".
    name        text NOT NULL CHECK (length(trim(name)) > 0),

    -- The range the device may send from.
    network     cidr NOT NULL,

    -- Sealed with the root key. Never readable from a backup or a replica
    -- without it.
    secret_enc  bytea NOT NULL,

    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- One device, one entry per organisation. Two rows for the same range with
    -- different secrets is a configuration nobody can reason about: which one
    -- applies depends on row order.
    UNIQUE (org_id, network)
);

CREATE INDEX radius_clients_org_idx ON core.radius_clients (org_id);

ALTER TABLE core.radius_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.radius_clients FORCE ROW LEVEL SECURITY;

CREATE POLICY radius_clients_org_isolation ON core.radius_clients
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.radius_clients IS
    'Network devices permitted to send Access-Requests. The shared secret is '
    'encrypted rather than hashed because RADIUS requires the secret itself to '
    'verify a request Message-Authenticator (RFC 3579).';

-- The console read model. The secret is NOT exposed -- there is no screen, API or
-- view in this system that reveals it, and `network` is shown as text because a
-- cidr renders as a PostgreSQL-specific type otherwise.
CREATE VIEW core_v1.radius_clients AS
SELECT
    c.id,
    c.org_id,
    c.name,
    host(c.network) || '/' || masklen(c.network) AS network,
    c.enabled,
    c.created_at,
    c.updated_at,
    CASE
        WHEN NOT c.enabled                THEN 'disabled'
        -- A /0 accepts the entire internet, which turns the port into an
        -- authentication oracle for anybody who can reach it.
        WHEN masklen(c.network) = 0       THEN 'accepts any source address'
        ELSE 'ok'
    END AS config_state
FROM core.radius_clients c;

GRANT SELECT ON core_v1.radius_clients TO signari_admin;
