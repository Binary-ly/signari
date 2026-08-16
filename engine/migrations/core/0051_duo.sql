-- Duo Universal Prompt as a second factor.
--
-- One integration per organisation. Duo's model is an "application" with an
-- integration key, a secret key and an API host; the secret key signs every
-- assertion we send and verifies every token we receive, so it is the entire
-- security of the integration and is sealed with the root key like any other.
CREATE TABLE IF NOT EXISTS core.duo_integrations (
    org_id        uuid PRIMARY KEY REFERENCES core.organizations(id) ON DELETE CASCADE,
    client_id     text NOT NULL,
    -- Sealed, never stored in the clear.
    secret_enc    bytea NOT NULL,
    api_host      text NOT NULL,

    -- What happens when Duo is UNREACHABLE.
    --
    -- false (fail closed) is the default and it has a real cost: a Duo outage
    -- stops every enrolled user signing in. The alternative is worse in a way
    -- that is easy to miss -- an attacker who can stop one victim's traffic
    -- reaching Duo has removed their second factor, and blocking one host is
    -- not a high bar.
    fail_open     boolean NOT NULL DEFAULT false,

    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT duo_client_id_length CHECK (length(client_id) = 20),
    CONSTRAINT duo_api_host_is_duo CHECK (
        api_host LIKE '%.duosecurity.com' OR api_host LIKE '%.duofederal.com')
);

COMMENT ON CONSTRAINT duo_api_host_is_duo ON core.duo_integrations IS
    'Enforced in the database as well as in code: every call to this host carries '
    'a signed assertion naming this integration, so a host somewhere else is a '
    'way to hand that assertion to whoever runs it.';

-- Which users are enrolled, and under what Duo username.
--
-- Duo identifies people by its own username, which is frequently NOT the email
-- address this engine knows them by. Storing the mapping explicitly is what
-- makes the identity check in VerifyIDToken possible: without it there would be
-- nothing to compare Duo's answer against.
CREATE TABLE IF NOT EXISTS core.duo_enrollments (
    user_id      uuid PRIMARY KEY REFERENCES core.users(id) ON DELETE CASCADE,
    org_id       uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    duo_username text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- In-flight Duo challenges.
--
-- The state is what ties Duo's answer to the browser that started the flow, and
-- it is single-use: an answer that could be presented twice is an answer that
-- could be presented by somebody else.
CREATE TABLE IF NOT EXISTS core.duo_challenges (
    state        text PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    org_id       uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    duo_username text NOT NULL,
    -- The parked authorization query, so the sign-in can resume where it left
    -- off. A path on this origin only -- never a URL.
    authz        text NOT NULL DEFAULT '',
    -- The AMR proven so far (a password, usually), carried across the redirect
    -- so the completed session records every factor rather than only the last.
    amr_so_far   text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz
);

CREATE INDEX IF NOT EXISTS duo_challenges_expiry ON core.duo_challenges (expires_at);

ALTER TABLE core.duo_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.duo_integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS duo_integrations_org_isolation ON core.duo_integrations;
CREATE POLICY duo_integrations_org_isolation ON core.duo_integrations
    USING (core.is_engine() OR org_id = core.current_org_id());
