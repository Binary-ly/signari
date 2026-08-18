
CREATE TABLE core.ssf_sources (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    display_name text       NOT NULL,
    -- The transmitter's issuer. Every SET must carry exactly this in `iss`.
    issuer      text        NOT NULL,
    -- Where its signing keys live. Fetched and cached; NEVER taken from the
    -- token, which is the whole of the alg-confusion family in one line.
    jwks_uri    text        NOT NULL,
    CONSTRAINT ssf_source_jwks_is_https CHECK (jwks_uri LIKE 'https://%'),

    -- What we will accept in `aud`. A SET addressed to somebody else is not
    -- ours to act on, however valid its signature.
    audience    text        NOT NULL,

    -- Which event types this source may act on. A source that can revoke
    -- sessions need not also be able to say a device is compliant, and the
    -- narrower grant is the one to give.
    allowed_events text[]   NOT NULL DEFAULT '{}',

    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_event_at timestamptz,

    UNIQUE (org_id, issuer)
);

CREATE INDEX ssf_sources_live ON core.ssf_sources (issuer) WHERE enabled;

ALTER TABLE core.ssf_sources ENABLE ROW LEVEL SECURITY;

-- The engine hatch; see 0058. Without core.is_engine() the engine reads zero
-- rows, and a superuser development DSN hides it until deployment.
CREATE POLICY ssf_sources_org ON core.ssf_sources
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON core.ssf_sources TO signari_engine;

-- Every event received, whether acted on or not.
--
-- Kept because "why did four hundred people get signed out at 3am" is a question
-- somebody asks later, and the answer is in here. Also the replay guard: a SET
-- is single-use, and a replayed session-revoked is a way to sign somebody out
-- repeatedly with one captured token.
CREATE TABLE core.ssf_received (
    id          bigserial   PRIMARY KEY,
    source_id   uuid        NOT NULL REFERENCES core.ssf_sources(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    jti         text        NOT NULL,
    event_type  text        NOT NULL,
    -- The subject as the transmitter described it, kept verbatim. Resolving it
    -- to one of our users may fail, and when it does this is the only record of
    -- who the event was about.
    subject     jsonb       NOT NULL,
    -- Our user, when the subject could be resolved. NULL is normal: a
    -- transmitter sends events about people we have never seen.
    user_id     uuid        REFERENCES core.users(id) ON DELETE SET NULL,

    -- What we did. Recorded even when that was nothing.
    action      text        NOT NULL,
    detail      text,

    event_time  timestamptz,
    received_at timestamptz NOT NULL DEFAULT now(),

    -- One event, once. The transmitter's jti scoped to the source that sent it.
    UNIQUE (source_id, jti)
);

CREATE INDEX ssf_received_recent ON core.ssf_received (org_id, received_at DESC);
CREATE INDEX ssf_received_subject ON core.ssf_received (user_id, received_at DESC)
    WHERE user_id IS NOT NULL;

ALTER TABLE core.ssf_received ENABLE ROW LEVEL SECURITY;
CREATE POLICY ssf_received_org ON core.ssf_received
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT ON core.ssf_received TO signari_engine;
GRANT USAGE, SELECT ON SEQUENCE core.ssf_received_id_seq TO signari_engine;

ALTER TABLE core.sessions DROP CONSTRAINT sessions_revocation_reason_check;
ALTER TABLE core.sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revocation_reason IN
        ('logout','admin_revoke','user_deleted','user_deactivated',
         'password_change','mfa_reset','expired','reuse_detected',
         'impersonation_ended','shared_signal'));
