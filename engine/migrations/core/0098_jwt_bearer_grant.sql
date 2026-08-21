SET search_path = core, public;

-- RFC 7523 section 2.1: a JWT issued by a trusted party, presented as an
-- authorization grant.
--
-- # Why this is opt-in per provider rather than implied by trust
--
-- The obvious implementation reuses `identity_providers` as-is: the issuer, the
-- JWKS URL and the enabled flag are already there, and `federated_identities`
-- already maps an external subject to a local user. That is what the most
-- deployed competitor does.
--
-- It is wrong, and the reason is a capability difference the shared table hides.
-- Registering a provider for interactive sign-in says "a person may prove who
-- they are by going to this provider in a browser and coming back". This grant
-- says something much stronger: "any JWT this provider signs, presented by a
-- client with no user present, mints our tokens for the linked account". An
-- operator who enabled Google sign-in did not ask for the second, and adding it
-- to their deployment because the row already existed is a silent privilege
-- upgrade to every provider they ever configured.
--
-- So it defaults to false. An existing deployment gains nothing until somebody
-- decides it should, which is the same rule the concurrent-session limits
-- followed: a migration must never start permitting something on its own.
ALTER TABLE identity_providers
    ADD COLUMN allow_jwt_bearer boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN identity_providers.allow_jwt_bearer IS
    'Whether assertions signed by this provider may be exchanged for our tokens '
    'via urn:ietf:params:oauth:grant-type:jwt-bearer (RFC 7523 section 2.1). '
    'Separate from `enabled` because interactive sign-in and non-interactive '
    'token minting are different powers.';

-- Replay protection for assertion `jti` values.
--
-- RFC 7523 section 6 is explicit that this is optional: "The specification does
-- not mandate replay protection for the JWT usage for either the authorization
-- grant or for client authentication. It is an optional feature, which
-- implementations may employ at their own discretion."
--
-- We employ it. A bearer assertion with a five-minute life is, without this, a
-- five-minute password: anything that observes it once -- a proxy log, an error
-- report, a misrouted request -- can replay it until it expires. The RFC's own
-- section 3 item 7 describes exactly this remedy, "maintaining the set of used
-- `jti` values for the length of time for which the JWT would be considered
-- valid based on the applicable `exp` instant", which is why the row carries the
-- assertion's own expiry rather than a fixed window.
--
-- Keyed by (provider, jti) rather than by jti alone. Two providers are two
-- namespaces, and a shared key would let one issuer invalidate another's
-- assertions by choosing colliding identifiers.
CREATE TABLE jwt_bearer_replay (
    provider_id uuid        NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    jti         text        NOT NULL,
    -- The assertion's own `exp`. The janitor deletes rows past it; keeping them
    -- longer protects nothing, because the assertion is refused for being
    -- expired before it is ever looked up here.
    expires_at  timestamptz NOT NULL,
    seen_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, jti)
);

CREATE INDEX jwt_bearer_replay_expiry_idx ON jwt_bearer_replay (expires_at);

ALTER TABLE jwt_bearer_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE jwt_bearer_replay FORCE ROW LEVEL SECURITY;

-- Explicit and permissive, matching core.revoked_jtis, which is the same kind of
-- table: an opaque replay record consulted on the request path before any
-- organisation context exists.
--
-- Written without a role restriction on purpose. The first version said
-- `FOR ALL TO signari_engine`, which silently excluded every other role -- and
-- because a filtered INSERT reports zero rows affected rather than an error, the
-- grant read that as "this assertion was already used" and refused every FIRST
-- use. Fail-closed, so nothing was unsafe, and completely broken.
--
-- Row-level isolation would buy nothing here anyway: the row is (provider_id,
-- jti), and a caller who could guess one would learn only that an assertion they
-- already hold has been spent.
CREATE POLICY jwt_bearer_replay_all ON jwt_bearer_replay
    USING (true) WITH CHECK (true);
