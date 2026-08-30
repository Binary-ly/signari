
SET search_path = core, public;

CREATE TABLE saml_providers (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The SP's EntityID. Opaque, compared exactly, and the primary key of the
    -- relationship as far as the protocol is concerned.
    entity_id    text        NOT NULL,
    display_name text        NOT NULL,

    -- # Signing policy
    --
    -- At least one of these must be true, enforced below. An assertion that is
    -- neither signed itself nor carried in a signed response is a bearer
    -- credential anybody can write, and "the SP will check TLS" is not a
    -- substitute -- the assertion arrives via the user's browser, from the
    -- user's machine.
    --
    -- Assertion signing is the default because it survives the response being
    -- re-wrapped, which response signing alone does not.
    sign_assertions boolean   NOT NULL DEFAULT true,
    sign_responses  boolean   NOT NULL DEFAULT false,

    -- Whether we require the SP to sign its AuthnRequests. Off by default
    -- because most SPs do not sign, and requiring it would break them -- but
    -- when it is on, an unsigned request is refused rather than warned about.
    want_authn_requests_signed boolean NOT NULL DEFAULT false,

    -- The SP's signing certificate, PEM. Needed to verify signed AuthnRequests
    -- and -- far more importantly -- LogoutRequests. gosaml2 GHSA-pcgw-qcv5-h8ch
    -- was accepting an UNSIGNED LogoutRequest: anyone could sign anyone out.
    -- Without a certificate on file we cannot verify, so logout from this SP is
    -- refused rather than trusted.
    sp_signing_cert text,

    -- # NameID
    --
    -- `persistent` is the default and it is PAIRWISE (see saml_name_ids): each
    -- SP gets a different opaque identifier for the same person. `emailAddress`
    -- is available because some SPs cannot do anything else, but it makes the
    -- user correlatable across every SP and breaks when the address changes.
    name_id_format text     NOT NULL DEFAULT 'persistent'
                            CHECK (name_id_format IN ('persistent','emailAddress','transient')),

    -- Extra attributes to release, as {"saml attribute name": "claim source"}.
    -- Empty by default: attribute release is a disclosure decision, so it is
    -- made explicitly per SP rather than inherited.
    --
    -- RESERVED AND UNUSED. Nothing reads this column and nothing writes it, so
    -- setting it releases no attribute -- an assertion carries the fixed set the
    -- minting code emits, whatever is stored here. Recorded because a
    -- disclosure control that silently does nothing is the worst kind to be
    -- wrong about: an operator would configure a release, see the column hold
    -- what they asked for, and reasonably believe it applied.
    attributes   jsonb       NOT NULL DEFAULT '{}',

    -- How long an assertion is valid for. Short by design: the assertion is
    -- replayable within its window by anyone who obtains it, and five minutes
    -- is the interoperable floor that still tolerates clock skew.
    lifetime_seconds integer NOT NULL DEFAULT 300
                            CHECK (lifetime_seconds BETWEEN 30 AND 3600),

    enabled      boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, entity_id),

    CONSTRAINT saml_providers_something_is_signed
        CHECK (sign_assertions OR sign_responses)
);

-- The URLs an assertion may be POSTed to.
--
-- This is the SAML equivalent of redirect_uri, and it is where assertions get
-- stolen: an attacker who can influence the AssertionConsumerServiceURL gets a
-- valid assertion for a real user delivered to a server they control. Exact
-- match, no wildcards, no prefix matching, registered ahead of time.
CREATE TABLE saml_acs_urls (
    provider_id uuid        NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    url         text        NOT NULL,
    binding     text        NOT NULL DEFAULT 'HTTP-POST'
                            CHECK (binding IN ('HTTP-POST','HTTP-Artifact')),
    -- Used when the AuthnRequest names no ACS URL at all.
    is_default  boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (provider_id, url),

    -- https only. An assertion crossing the network in the clear is a
    -- credential crossing the network in the clear.
    CONSTRAINT saml_acs_https CHECK (url LIKE 'https://%')
);

-- Exactly one default ACS per provider.
CREATE UNIQUE INDEX saml_acs_one_default ON saml_acs_urls (provider_id)
    WHERE is_default;

-- Single logout endpoints, kept separate because their trust requirements
-- differ: we SEND to these, and we verify signatures on what comes back.
CREATE TABLE saml_slo_urls (
    provider_id uuid    NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    url         text    NOT NULL,
    binding     text    NOT NULL DEFAULT 'HTTP-Redirect'
                        CHECK (binding IN ('HTTP-Redirect','HTTP-POST')),
    PRIMARY KEY (provider_id, url),
    CONSTRAINT saml_slo_https CHECK (url LIKE 'https://%')
);

-- # Pairwise NameIDs
--
-- A random, stable identifier per (user, provider). Two SPs comparing notes
-- cannot tell that their users are the same person, and the identifier survives
-- an email change -- which the email-as-NameID deployments do not.
--
-- Generated once and stored, because it must not change: an SP treats the
-- NameID as the account key, and a new one means a new account.
CREATE TABLE saml_name_ids (
    provider_id uuid        NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name_id     text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, user_id),
    UNIQUE (provider_id, name_id)
);

-- Which SPs saw this session, so single logout can enumerate them.
--
-- The SessionIndex and NameID are stored because a LogoutRequest must carry
-- back exactly what we sent -- an SP matches on them, and a logout that does
-- not match is a logout that silently does nothing.
CREATE TABLE saml_session_participants (
    sid           text        NOT NULL REFERENCES sessions(sid) ON DELETE CASCADE,
    provider_id   uuid        NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_index text        NOT NULL,
    name_id       text        NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sid, provider_id)
);

-- Replay protection for inbound requests we have acted on.
--
-- A signed LogoutRequest stays valid forever otherwise: capture one, replay it
-- whenever you want that person signed out. The same table covers signed
-- AuthnRequests.
CREATE TABLE saml_seen_requests (
    request_id  text        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id uuid        REFERENCES saml_providers(id) ON DELETE CASCADE,
    seen_at     timestamptz NOT NULL DEFAULT now(),
    -- Swept by the janitor; retained past the assertion window so a replay
    -- cannot simply wait out the record.
    expires_at  timestamptz NOT NULL
);

CREATE INDEX saml_seen_requests_expiry_idx ON saml_seen_requests (expires_at);
CREATE INDEX saml_participants_sid_idx     ON saml_session_participants (sid);

-- ---------------------------------------------------------------------------
-- Row-level security, matching 0018: the engine sees everything, a console
-- session sees only its own organisation.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'saml_providers','saml_name_ids','saml_session_participants','saml_seen_requests'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE core.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE core.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY %I_org_isolation ON core.%I
            USING (core.is_engine() OR org_id = core.current_org_id())
            WITH CHECK (core.is_engine() OR org_id = core.current_org_id())
        $f$, t, t);
    END LOOP;
END
$$;

-- The URL tables have no org_id of their own; they inherit it through the
-- provider, exactly as client_redirect_uris does through clients.
ALTER TABLE saml_acs_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_acs_urls FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_acs_urls_org_isolation ON saml_acs_urls
    USING (core.is_engine() OR EXISTS (
        SELECT 1 FROM core.saml_providers p
        WHERE p.id = provider_id AND p.org_id = core.current_org_id()))
    WITH CHECK (core.is_engine() OR EXISTS (
        SELECT 1 FROM core.saml_providers p
        WHERE p.id = provider_id AND p.org_id = core.current_org_id()));

ALTER TABLE saml_slo_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_slo_urls FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_slo_urls_org_isolation ON saml_slo_urls
    USING (core.is_engine() OR EXISTS (
        SELECT 1 FROM core.saml_providers p
        WHERE p.id = provider_id AND p.org_id = core.current_org_id()))
    WITH CHECK (core.is_engine() OR EXISTS (
        SELECT 1 FROM core.saml_providers p
        WHERE p.id = provider_id AND p.org_id = core.current_org_id()));

GRANT SELECT ON saml_providers, saml_acs_urls, saml_slo_urls, saml_name_ids,
                saml_session_participants, saml_seen_requests
    TO signari_maintenance;
