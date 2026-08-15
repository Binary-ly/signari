
ALTER TABLE core.identity_providers
    DROP CONSTRAINT IF EXISTS identity_providers_kind_check;

ALTER TABLE core.identity_providers
    ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind IN ('oidc', 'google', 'github', 'microsoft', 'saml'));

-- client_id is an OAuth concept and a SAML source has none. Empty is allowed
-- for SAML only, so an OAuth provider still cannot be registered without one.
ALTER TABLE core.identity_providers
    DROP CONSTRAINT IF EXISTS identity_providers_client_id_present;

ALTER TABLE core.identity_providers
    ADD CONSTRAINT identity_providers_client_id_present
    CHECK (kind = 'saml' OR client_id <> '');

CREATE TABLE IF NOT EXISTS core.saml_sources (
    -- Not a separate identity: the same provider, seen from the SAML side.
    provider_id       uuid PRIMARY KEY
                          REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    org_id            uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The upstream's entity ID, matched exactly against <Issuer>.
    entity_id         text NOT NULL,
    sso_url           text NOT NULL,
    -- The certificate assertions are verified against. Never read from the
    -- response itself: a document must not vouch for its own signature.
    cert_pem          text NOT NULL,

    name_id_format    text NOT NULL DEFAULT 'persistent',
    force_authn       boolean NOT NULL DEFAULT false,

    -- IdP-initiated sign-in. Off, and it should stay off: an unsolicited
    -- assertion cannot be tied to a request this browser made, so a valid
    -- assertion captured anywhere can be posted into a victim's session and
    -- signs them in as somebody else.
    allow_unsolicited boolean NOT NULL DEFAULT false,

    -- Clock tolerance. Clamped to five minutes in code however this is set,
    -- because a large skew quietly extends how long a captured assertion stays
    -- replayable.
    skew_seconds      integer NOT NULL DEFAULT 30,

    created_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT saml_sources_skew_sane CHECK (skew_seconds BETWEEN 0 AND 300),
    CONSTRAINT saml_sources_nameid_known
        CHECK (name_id_format IN ('persistent', 'emailAddress', 'unspecified'))
);

COMMENT ON COLUMN core.saml_sources.name_id_format IS
    'transient is deliberately absent: it is a different value on every sign-in, '
    'so linking accounts to it would create a new orphaned account each time.';

-- Requests sent and not yet answered.
--
-- This table IS the InResponseTo check. Without a record that this browser
-- asked, an assertion is a claim by whoever posted it, and the most important
-- check after the signature has nothing to compare against.
CREATE TABLE IF NOT EXISTS core.saml_source_requests (
    id           text PRIMARY KEY,                 -- the AuthnRequest ID
    provider_id  uuid NOT NULL
                     REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    relay_state  text NOT NULL UNIQUE,
    -- Where to continue after sign-in: a path on this origin, never a URL.
    -- Putting a destination in RelayState is how SAML deployments grow open
    -- redirects, because RelayState is echoed back by the upstream and is
    -- therefore chosen by whoever starts the flow.
    return_path  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz
);

CREATE INDEX IF NOT EXISTS saml_source_requests_expiry
    ON core.saml_source_requests (expires_at);

-- Assertions already spent.
--
-- A valid assertion works exactly once. The signature says the upstream minted
-- it; only this says it has not already been used.
CREATE TABLE IF NOT EXISTS core.saml_source_assertions (
    provider_id  uuid NOT NULL
                     REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    assertion_id text NOT NULL,
    consumed_at  timestamptz NOT NULL DEFAULT now(),
    -- Kept only until the assertion could no longer be replayed anyway.
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (provider_id, assertion_id)
);

CREATE INDEX IF NOT EXISTS saml_source_assertions_expiry
    ON core.saml_source_assertions (expires_at);

ALTER TABLE core.saml_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.saml_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS saml_sources_org_isolation ON core.saml_sources;
CREATE POLICY saml_sources_org_isolation ON core.saml_sources
    USING (core.is_engine() OR org_id = core.current_org_id());
