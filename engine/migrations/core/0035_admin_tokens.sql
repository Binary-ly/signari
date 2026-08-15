-- Admin API tokens with scopes and an organisation boundary.
--
-- # What this replaces
--
-- One token in an environment variable, granting everything, to every
-- organisation, forever. Three separate problems:
--
--   revocation   changing it means restarting every node, so in practice nobody
--                rotates it and a leaked token stays valid indefinitely
--   attribution  every change in the audit trail is attributed to "the admin
--                token", which is the same as no attribution
--   blast radius the console needs to write users and clients; a monitoring
--                script needs to read a version number. Both get the same
--                unlimited credential, and either one leaking loses everything
--                in every tenant
--
-- The environment token is kept as a break-glass path (see the engine's auth
-- middleware) precisely because it needs no database: if the database is the
-- thing that is broken, a credential stored in it cannot help you.
--
-- # Why the hash and not the token
--
-- Same reason as passwords. A database backup, a replica, or a support dump of
-- this table would otherwise hand over live administrative credentials for every
-- tenant. SHA-256 is right here where Argon2 is right for passwords: this is a
-- 256-bit random value, not a human-chosen one, so there is nothing to brute
-- force and stretching would only add per-request cost to the hottest path.
CREATE TABLE core.admin_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NULL means every organisation. Set means this token may only act on that
    -- one, which is the whole point of the column: a per-tenant console token
    -- that cannot reach another tenant even if it leaks.
    org_id      uuid REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- Who this is for, in words. Shown in the audit trail, so it should say
    -- "laravel console (production)" rather than "token 3".
    name        text NOT NULL CHECK (length(trim(name)) > 0),

    token_hash  bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),

    -- What it may do. Empty is refused: a token with no scopes can do nothing,
    -- and creating one is a mistake rather than an intention.
    scopes      text[] NOT NULL CHECK (cardinality(scopes) > 0),

    created_at   timestamptz NOT NULL DEFAULT now(),
    -- NULL means it does not expire. Allowed, because a console token that stops
    -- working at 3am is its own kind of outage -- but `signari doctor` says so.
    expires_at   timestamptz,
    revoked_at   timestamptz,
    -- Updated opportunistically, outside the request transaction. Its purpose is
    -- answering "is this token still in use" before revoking it, and that does
    -- not need to be exact.
    last_used_at timestamptz
);

-- The lookup on every admin request: by hash, among tokens still valid.
CREATE INDEX admin_tokens_live_idx ON core.admin_tokens (token_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX admin_tokens_org_idx ON core.admin_tokens (org_id);

COMMENT ON TABLE core.admin_tokens IS
    'Scoped, revocable credentials for the admin write API. org_id NULL means all '
    'organisations. The SIGNARI_ADMIN_TOKEN environment variable remains as a '
    'break-glass path that works when the database does not.';

-- Attribution. Which token made each change, so the audit trail names a
-- credential somebody can revoke rather than a role everybody shares.
ALTER TABLE core.audit_events
    ADD COLUMN admin_token_id uuid REFERENCES core.admin_tokens(id) ON DELETE SET NULL;

COMMENT ON COLUMN core.audit_events.admin_token_id IS
    'The admin token that caused this change, when one did. NULL for actions taken '
    'by a user, by the engine itself, or through the break-glass environment token.';
