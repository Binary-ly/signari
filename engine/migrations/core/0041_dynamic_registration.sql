-- Dynamic client registration, RFC 7591 and RFC 7592.
--
-- # Why this is off by default
--
-- An open registration endpoint lets anybody create clients on your identity
-- provider. That is not a theoretical concern:
--
--   * unbounded rows, created by anyone who can reach the endpoint
--   * client_ids and display names of the attacker's choosing, which is a
--     phishing surface -- a consent screen saying "Microsoft 365 wants access"
--     is convincing, and the name came from whoever registered
--   * a way to enumerate what the deployment supports, by registering and
--     reading back what was accepted
--
-- So registration is opt-in per organisation, and even then it normally requires
-- an initial access token. Open registration exists because some ecosystems
-- (MCP, and other dynamic client environments) genuinely need it, but it is a
-- decision an operator makes deliberately with the limits below in front of them.

SET search_path = core, public;

CREATE TABLE core.registration_policies (
    org_id  uuid PRIMARY KEY REFERENCES core.organizations(id) ON DELETE CASCADE,

    enabled boolean NOT NULL DEFAULT false,

    -- When false, a caller must present an initial access token. When true,
    -- anybody who can reach the endpoint may register -- which is what RFC 7591
    -- calls "open registration" and what the caps below exist to survive.
    open    boolean NOT NULL DEFAULT false,

    -- Ceiling on dynamically registered clients for this organisation. Reached
    -- means refuse, not evict: silently deleting somebody's working client to
    -- make room for a stranger's is worse than refusing the stranger.
    max_clients int NOT NULL DEFAULT 100 CHECK (max_clients > 0),

    -- What a dynamically registered client may ask for. A registration cannot
    -- grant itself more than this, so opening the endpoint does not open the
    -- scope catalogue with it.
    allowed_scopes text[] NOT NULL DEFAULT '{openid,profile,email}',

    -- Registered clients are public by default: handing a secret to a caller who
    -- appeared thirty seconds ago and cannot be identified is not a credential,
    -- it is a formality.
    allow_confidential boolean NOT NULL DEFAULT false,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE core.registration_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.registration_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY registration_policies_org_isolation ON core.registration_policies
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

-- Initial access tokens: the credential that permits a registration when the
-- endpoint is not open. Hashed, like every other credential here.
CREATE TABLE core.registration_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (length(trim(name)) > 0),
    token_hash  bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),

    -- NULL means unlimited. A number means this token may create that many
    -- clients and then stops -- which is what makes handing one to a contractor
    -- or a CI job a bounded act.
    remaining   int CHECK (remaining IS NULL OR remaining >= 0),

    expires_at  timestamptz,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX registration_tokens_live_idx ON core.registration_tokens (token_hash)
    WHERE revoked_at IS NULL;

ALTER TABLE core.registration_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.registration_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY registration_tokens_org_isolation ON core.registration_tokens
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

-- What a dynamically registered client needs beyond an ordinary one: the
-- credential that lets its owner manage it afterwards (RFC 7592), and the fact
-- that it was self-registered at all.
ALTER TABLE core.clients
    ADD COLUMN dynamically_registered boolean NOT NULL DEFAULT false,
    ADD COLUMN registration_token_hash bytea
        CHECK (registration_token_hash IS NULL OR length(registration_token_hash) = 32),
    ADD COLUMN registered_at timestamptz;

CREATE INDEX clients_dynamic_idx ON core.clients (org_id)
    WHERE dynamically_registered;

COMMENT ON COLUMN core.clients.dynamically_registered IS
    'Self-registered through RFC 7591 rather than created by an operator. Kept '
    'so these can be listed, capped and revoked as a class -- an operator should '
    'be able to answer "what registered itself last night" in one query.';

COMMENT ON COLUMN core.clients.registration_token_hash IS
    'SHA-256 of the RFC 7592 registration access token. Whoever registered the '
    'client uses it to read, update or delete that client, and nothing else.';
