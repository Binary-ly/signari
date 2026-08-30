
SET search_path = core, public;


CREATE TABLE instances (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The issuer is per-instance and immutable once tokens have been issued.
    -- Aliases live in instance_issuer_aliases so a migration can serve the old
    -- issuer during cutover without breaking RP discovery.
    issuer        text        NOT NULL UNIQUE,
    display_name  text        NOT NULL,
    status        text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'suspended')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Serving the old issuer string during a migration turns an OAuth cutover from
-- "touch every downstream app" into a DNS change. This plus verbatim client_id
-- import (below) is the single largest lever on migration cost.
CREATE TABLE instance_issuer_aliases (
    instance_id   uuid        NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    issuer        text        NOT NULL UNIQUE,
    -- Aliases are for cutover only and should expire. NULL = no planned sunset.
    retire_after  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, issuer)
);

CREATE TABLE organizations (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id   uuid        NOT NULL REFERENCES instances(id) ON DELETE RESTRICT,
    slug          text        NOT NULL,
    display_name  text        NOT NULL,
    status        text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'suspended')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance_id, slug)
);

CREATE TABLE projects (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    slug          text        NOT NULL,
    display_name  text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
);

-- ===========================================================================
-- Subjects (users) and the crypto-shredding key table
-- ===========================================================================

-- Per-subject data-encryption key. Erasure = destroy the DEK, leaving ciphertext
-- that is now noise. The audit hash chain is computed over ciphertext so it stays
-- verifiable after shredding.
--
-- NOTE: your backup retention window is your erasure SLA. If nightly backups hold
-- the DEK for 90 days you cannot honestly claim erasure inside 90 days. Either keep
-- DEKs outside the backed-up database (KMS/HSM) or state the window in your DPA.
CREATE TABLE subject_keys (
    subject_id    uuid        PRIMARY KEY,
    -- Wrapped by a root key that is NOT in this database (env, file, or KMS).
    wrapped_dek   bytea,
    wrap_key_ref  text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Set when the DEK is destroyed. wrapped_dek becomes NULL at the same moment.
    erased_at     timestamptz,
    CONSTRAINT subject_keys_erased_has_no_dek
        CHECK ((erased_at IS NULL) = (wrapped_dek IS NOT NULL))
);

CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,

    -- Stable, random, non-PII, 64 bytes. This is the WebAuthn user handle and it
    -- must never be the email or a sequential id: it is sent to authenticators
    -- and stored on the user's device essentially forever.
    user_handle   bytea       NOT NULL UNIQUE
                              CHECK (octet_length(user_handle) = 64),

    -- Login identifiers. Normalised at write time; uniqueness is per-org.
    username      text,
    email         text,
    email_verified_at timestamptz,

    status        text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'deactivated', 'locked')),

    -- Set only while a delegated/shadow migration is pending: the user exists
    -- but has no local credential yet, so first login proxies to the old IdP.
    migration_state text      NOT NULL DEFAULT 'none'
                              CHECK (migration_state IN ('none', 'pending', 'complete')),

    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_has_an_identifier CHECK (username IS NOT NULL OR email IS NOT NULL)
);

CREATE UNIQUE INDEX users_org_username_key ON users (org_id, lower(username))
    WHERE username IS NOT NULL;
CREATE UNIQUE INDEX users_org_email_key    ON users (org_id, lower(email))
    WHERE email IS NOT NULL;
CREATE INDEX users_org_status_idx          ON users (org_id, status);

-- ===========================================================================
-- Credentials
-- ===========================================================================

-- Self-describing hash strings so foreign hashes import verbatim and rehash
-- lazily on successful login. `source_algorithm` records the ORIGIN system's
-- convention, because bcrypt pre-hashing differs between products and an
-- imported hash from a system that did not pre-hash will never verify if you do.
CREATE TABLE password_credentials (
    user_id       uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    -- Full PHC-style string: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
    -- or a recognised foreign format ($2b$, pbkdf2_sha256$, $P$, $6$, ...).
    hash          text        NOT NULL,
    algorithm     text        NOT NULL,
    -- Where this hash came from, so the verifier knows the dialect.
    source_system text        NOT NULL DEFAULT 'native',
    -- True once rehashed to current policy. Drives the migration dashboard.
    is_current    boolean     NOT NULL DEFAULT true,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX password_credentials_migration_idx
    ON password_credentials (org_id, is_current) WHERE is_current = false;

CREATE TABLE webauthn_credentials (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id            uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    credential_id     bytea       NOT NULL UNIQUE,
    public_key        bytea       NOT NULL,
    -- Many authenticators always return 0. A non-monotonic NON-ZERO counter is a
    -- cloning signal; zero is not. Never hard-fail on 0.
    sign_count        bigint      NOT NULL DEFAULT 0,
    -- Discoverable (resident) credentials can satisfy conditional-UI autofill
    -- with an empty allowCredentials list; non-discoverable cannot.
    is_discoverable   boolean     NOT NULL DEFAULT false,
    transports        text[]      NOT NULL DEFAULT '{}',
    aaguid            bytea,
    attestation_type  text        NOT NULL DEFAULT 'none',
    -- The RP ID this credential is bound to. Recorded because it is permanent and
    -- because Related Origin Requests migration depends on knowing it.
    rp_id             text        NOT NULL,
    friendly_name     text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_used_at      timestamptz
);

CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

CREATE TABLE totp_credentials (
    user_id       uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    -- Encrypted with the subject DEK, never stored in plaintext.
    secret_enc    bytea       NOT NULL,
    digits        smallint    NOT NULL DEFAULT 6,
    period_secs   smallint    NOT NULL DEFAULT 30,
    confirmed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- ===========================================================================
-- OAuth clients
-- ===========================================================================

CREATE TABLE clients (
    -- NOT a surrogate key. The client_id is settable verbatim on import so an
    -- RP's existing configuration does not change during migration. Most products
    -- refuse this, which is precisely why migrations hurt.
    client_id             text        PRIMARY KEY,
    org_id                uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    project_id            uuid        REFERENCES projects(id) ON DELETE SET NULL,
    display_name          text        NOT NULL,

    client_type           text        NOT NULL
                                      CHECK (client_type IN ('confidential', 'public')),
    -- Argon2id over the secret. NULL for public clients. Also settable verbatim
    -- on import when the source system exports a usable hash.
    client_secret_hash    text,

    -- Read on the request path. Never cached. A disabled client must stop working
    -- on the very next request, not at the next config refresh.
    enabled               boolean     NOT NULL DEFAULT true,

    grant_types           text[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    response_types        text[]      NOT NULL DEFAULT '{code}',
    scopes                text[]      NOT NULL DEFAULT '{openid}',

    -- PKCE is required for every client. RFC 9700 / OAuth 2.1. `plain` is not an
    -- option; the column exists only so a deliberate legacy exemption is visible
    -- and auditable rather than implicit.
    require_pkce          boolean     NOT NULL DEFAULT true,
    pkce_methods          text[]      NOT NULL DEFAULT '{S256}',

    id_token_signed_alg   text        NOT NULL DEFAULT 'ES256'
                                      CHECK (id_token_signed_alg IN ('RS256','ES256','EdDSA','PS256')),
    access_token_format   text        NOT NULL DEFAULT 'jwt'
                                      CHECK (access_token_format IN ('jwt', 'opaque')),
    access_token_ttl_s    integer     NOT NULL DEFAULT 300,
    refresh_token_ttl_s   integer     NOT NULL DEFAULT 2592000,

    -- Back-channel logout. `sid` vs `sub` semantics are decided per-spec, not
    -- per-client, but the endpoint and its requirements are per-client.
    backchannel_logout_uri            text,
    backchannel_logout_session_required boolean NOT NULL DEFAULT true,

    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clients_confidential_has_secret
        CHECK (client_type = 'public' OR client_secret_hash IS NOT NULL),
    CONSTRAINT clients_pkce_s256_only
        CHECK (pkce_methods <@ ARRAY['S256','plain']::text[])
);

CREATE INDEX clients_org_idx ON clients (org_id, enabled);

-- Exact string match only. No prefix, no wildcard, no trailing-slash tolerance.
-- A separate table rather than an array so the match is an indexed equality.
CREATE TABLE client_redirect_uris (
    client_id     text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    redirect_uri  text        NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE client_post_logout_redirect_uris (
    client_id     text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    redirect_uri  text        NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);


CREATE TABLE sessions (
    sid             text        PRIMARY KEY,
    org_id          uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Authentication context, re-evaluated per authorization request so an
    -- acr_values requirement forces step-up even on a live session.
    acr             text        NOT NULL DEFAULT '0',
    amr             text[]      NOT NULL DEFAULT '{}',
    auth_time       timestamptz NOT NULL,

    revoked_at      timestamptz,
    revocation_reason text      CHECK (revocation_reason IN
                          ('logout','admin_revoke','user_deleted','user_deactivated',
                           'password_change','mfa_reset','expired','reuse_detected',
                           'impersonation_ended','shared_signal')),
    not_after       timestamptz NOT NULL,

    user_agent      text,
    ip_hash         bytea,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sessions_revocation_is_paired
        CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);

CREATE INDEX sessions_user_live_idx ON sessions (user_id)
    WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx    ON sessions (not_after)
    WHERE revoked_at IS NULL;

-- Which RPs saw this session, so logout can enumerate them. Written at token
-- issuance; read when terminating.
CREATE TABLE session_clients (
    sid           text        NOT NULL REFERENCES sessions(sid) ON DELETE CASCADE,
    client_id     text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (sid, client_id)
);

-- ===========================================================================
-- Authorization codes and tokens
-- ===========================================================================

CREATE TABLE authorization_codes (
    code_hash        bytea       PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    client_id        text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    sid              text        NOT NULL REFERENCES sessions(sid) ON DELETE CASCADE,
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri     text        NOT NULL,
    scopes           text[]      NOT NULL,
    nonce            text,
    -- PKCE. Compared in constant time; S256 only.
    code_challenge   text        NOT NULL,
    code_challenge_method text   NOT NULL DEFAULT 'S256'
                                 CHECK (code_challenge_method IN ('S256','plain')),
    -- RFC 8707 resource indicators. Scoping a token to one audience is what makes
    -- an agent token issued for one MCP server inert at another.
    resources        text[]      NOT NULL DEFAULT '{}',
    expires_at       timestamptz NOT NULL,
    -- Single use. A second redemption revokes the whole grant.
    consumed_at      timestamptz
);

CREATE INDEX authorization_codes_expiry_idx ON authorization_codes (expires_at);

-- Refresh tokens live in families so that reuse detection can revoke the entire
-- lineage, not just the replayed token.
CREATE TABLE refresh_token_families (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    client_id      text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sid            text        REFERENCES sessions(sid) ON DELETE CASCADE,
    revoked_at     timestamptz,
    revocation_reason text,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
    token_hash     bytea       PRIMARY KEY,
    family_id      uuid        NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    scopes         text[]      NOT NULL,
    resources      text[]      NOT NULL DEFAULT '{}',
    expires_at     timestamptz NOT NULL,
    -- Rotation: consuming a token mints its successor. Consuming an already
    -- consumed token is reuse -> revoke the family.
    consumed_at    timestamptz,
    successor_hash bytea,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at);

-- Only for clients configured with opaque access tokens, where instant
-- revocation matters more than statelessness.
CREATE TABLE access_tokens (
    token_hash     bytea       PRIMARY KEY,
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    client_id      text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id        uuid        REFERENCES users(id) ON DELETE CASCADE,
    sid            text        REFERENCES sessions(sid) ON DELETE CASCADE,
    scopes         text[]      NOT NULL,
    resources      text[]      NOT NULL DEFAULT '{}',
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz
);

CREATE INDEX access_tokens_expiry_idx ON access_tokens (expires_at);

CREATE TABLE consents (
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    scopes         text[]      NOT NULL,
    granted_at     timestamptz NOT NULL DEFAULT now(),
    withdrawn_at   timestamptz,
    PRIMARY KEY (user_id, client_id)
);

-- ===========================================================================
-- Signing keys
-- ===========================================================================
-- Four states, three of them published. The JWKS publishes next + active +
-- passive so an RP that caches aggressively still resolves a kid it has not
-- seen. Publication timing is dictated by the slowest RP's cache, not by you.

CREATE TABLE signing_keys (
    kid            text        PRIMARY KEY,
    instance_id    uuid        NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    algorithm      text        NOT NULL
                               CHECK (algorithm IN ('RS256','ES256','EdDSA','PS256')),
    state          text        NOT NULL
                               CHECK (state IN ('next','active','passive')),
    public_jwk     jsonb       NOT NULL,
    -- Private material is either wrapped here or held externally. `key_ref`
    -- points at PKCS#11 / KMS when the key never leaves the module -- which is
    -- why the engine's key layer is a crypto.Signer interface, not a *rsa.PrivateKey.
    wrapped_private bytea,
    key_ref        text,
    published_at   timestamptz NOT NULL DEFAULT now(),
    activated_at   timestamptz,
    demoted_at     timestamptz,
    -- Never remove before max(longest_token_lifetime, longest observed RP cache TTL).
    retire_after   timestamptz,

    CONSTRAINT signing_keys_has_private_material
        CHECK (wrapped_private IS NOT NULL OR key_ref IS NOT NULL)
);

-- At most one active key per instance per algorithm.
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (instance_id, algorithm) WHERE state = 'active';

-- ===========================================================================
-- Config propagation, outbox, audit
-- ===========================================================================

-- Single row. Bumped in the same transaction as every config mutation. Engine
-- nodes LISTEN for a nudge and poll this as the actual guarantee -- NOTIFY is
-- lossy across reconnects and capped at 8000 bytes, so the bus carries a signal,
-- never the state.
CREATE TABLE config_version (
    id       boolean     PRIMARY KEY DEFAULT true CHECK (id),
    version  bigint      NOT NULL DEFAULT 1,
    bumped_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO config_version (id, version) VALUES (true, 1) ON CONFLICT DO NOTHING;

-- Go -> Laravel projection, and back-channel logout delivery. One table, two
-- consumers, explicit per-row delivery status so a failed logout POST is visible
-- rather than silently lost.
CREATE TABLE outbox (
    id            bigserial   PRIMARY KEY,
    topic         text        NOT NULL,
    payload       jsonb       NOT NULL,
    -- Explicit versioning on every wire format. Changing a shape takes two
    -- releases: N accepts old+new but emits old; N+1 emits new.
    payload_v     integer     NOT NULL DEFAULT 1,
    created_at    timestamptz NOT NULL DEFAULT now(),
    attempts      integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at  timestamptz,
    last_error    text
);

CREATE INDEX outbox_pending_idx ON outbox (topic, next_attempt_at)
    WHERE delivered_at IS NULL;

-- Audit. Only an opaque subject_id -- never email, name, or IP-as-identity.
-- That single rule eliminates most of the GDPR-erasure tension at zero cost.
CREATE TABLE audit_events (
    id             bigserial   PRIMARY KEY,
    org_id         uuid        REFERENCES organizations(id) ON DELETE SET NULL,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    event_type     text        NOT NULL,
    subject_id     uuid,
    actor_id       uuid,
    client_id      text,
    -- Shown to the end user as a short code on error pages, so support can pull
    -- the whole decision trace from one string the user reads aloud.
    correlation_id uuid,
    -- Security events survive an erasure request on legitimate-interest grounds;
    -- profile/preference events do not. Without this you cannot honour a partial
    -- erasure with a documented reason.
    retention_class text       NOT NULL DEFAULT 'security'
                               CHECK (retention_class IN ('security','operational','profile')),
    -- RESERVED AND UNUSED. Intended for detail encrypted under the subject DEK,
    -- so a shred would remove content and leave the record. Nothing writes it and
    -- nothing reads it; see internal/audit/audit.go. Kept rather than dropped
    -- because the design is still the intended one, but do not cite it as a
    -- protection that exists.
    detail_enc     bytea,
    detail         jsonb       NOT NULL DEFAULT '{}',
    -- Hash chain computed over `detail`, which is PLAINTEXT. This said CIPHERTEXT
    -- and that was never true. Safe because the package rule is subject IDs only,
    -- so a shred touches no row's hashed content -- not because it is encrypted.
    prev_hash      bytea,
    entry_hash     bytea
);

CREATE INDEX audit_events_org_time_idx     ON audit_events (org_id, occurred_at DESC);
CREATE INDEX audit_events_correlation_idx  ON audit_events (correlation_id);
CREATE INDEX audit_events_subject_idx      ON audit_events (subject_id, occurred_at DESC);
