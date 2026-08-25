-- Extension providers: a service the operator runs, which this engine calls to
-- extend a decision it makes (ADR-011).
--
-- Go has no usable dynamic plugin story -- `plugin` is Linux-only, demands the
-- identical toolchain, cannot unload, and shares an address space with the
-- signing keys. An embedded expression language is remote code execution with a
-- configuration screen in front of it. So an extension is a separate process,
-- reached over HTTP, through the SSRF-safe dialer that already refuses private
-- destinations.
--
-- The column that makes this safe is `mode`, and it is deliberately NOT
-- nullable and has NO default. Every provider must state what happens when it
-- cannot be reached, because the safe answer differs per hook and both mistakes
-- are silent:
--
--   an authorization hook that fails OPEN stops enforcing exactly when
--   something is wrong, which is when it mattered;
--
--   a claims hook that fails CLOSED locks every user out of a deployment
--   because a directory was slow.
--
-- A default would pick one of those for somebody who did not think about it.

CREATE TABLE core.providers (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- name identifies the provider in logs, audit events and `signari doctor`.
    name        text NOT NULL,

    -- hook is which decision this extends. A closed set, checked here as well as
    -- in Go: a hook name that only the application validates is one a direct
    -- INSERT can bypass, and this table is reachable by the maintenance role.
    hook        text NOT NULL CHECK (hook IN ('authorize')),

    -- url must be https. Plaintext would carry the subject of an authorization
    -- decision across the network in the clear, and the decision back.
    url         text NOT NULL CHECK (url LIKE 'https://%'),

    -- token is an optional bearer credential, stored wrapped like every other
    -- secret in this schema. NULL means the operator authenticates the call some
    -- other way (mutual TLS at the network layer, or an allow-listed source).
    token_wrapped bytea,
    wrap_key_ref  text,

    -- mode: what happens when the provider does not answer. No default, on
    -- purpose -- see the comment above.
    mode        text NOT NULL CHECK (mode IN ('fail_closed', 'fail_open')),

    -- timeout_ms bounds the call. Capped here as well as in Go, because a
    -- provider registered with a ten-minute timeout is a way to exhaust this
    -- server's connections from the outside.
    timeout_ms  integer NOT NULL CHECK (timeout_ms > 0 AND timeout_ms <= 5000),

    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- One provider per hook per organisation. Two providers answering the same
    -- question is a policy question (which wins? both? in what order?) that this
    -- engine does not answer, so it is refused at the schema rather than
    -- resolved by whichever row sorts first.
    UNIQUE (org_id, hook)
);

CREATE INDEX providers_org_hook ON core.providers (org_id, hook) WHERE enabled;

ALTER TABLE core.providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.providers FORCE ROW LEVEL SECURITY;

-- `core.is_engine() OR ...`, and the first half is not optional.
--
-- The engine reads this table on the authorization path WITHOUT an org context
-- set -- it is answering for whichever organisation the request named, not
-- operating inside one. A policy of `org_id = core.current_org_id()` alone
-- therefore matches nothing for the engine, so LoadProvider would return no rows
-- in every deployment that does not connect as a superuser, and the hook would
-- silently never fire. That is the "registered and governs nothing" failure the
-- whole predicate machinery exists to prevent, arriving through row-level
-- security instead.
--
-- Caught by TestEveryPolicyLetsTheEngineIn, which exists for exactly this.
CREATE POLICY providers_org_isolation ON core.providers
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.providers TO signari_engine;
GRANT INSERT, UPDATE, DELETE ON core.providers TO signari_engine;
