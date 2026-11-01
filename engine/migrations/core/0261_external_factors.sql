-- signari:compatible-with-previous
-- 0261_external_factors.sql
--
-- A sign-in stage an operator plugs a service of their own into (10.03). The service is registered
-- with where to send the browser, the issuer it signs as, its public keys and the amr it may claim,
-- and a challenge is one nonce waiting to come back, spent once. The keys are held by value rather
-- than fetched, so that an answer is believed because of a key an operator put here and a change
-- of keys is a change to the configuration. An older binary reads none of this: it refuses a stored
-- flow naming a stage it does not know and keeps the flow it had.

CREATE TABLE core.external_factors (
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    name       text        NOT NULL,
    url        text        NOT NULL,
    issuer     text        NOT NULL,
    jwks       jsonb       NOT NULL,
    amr        text[]      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, name)
);

CREATE TABLE core.external_factor_challenges (
    nonce_hash bytea       PRIMARY KEY,
    org_id     uuid        NOT NULL,
    factor     text        NOT NULL,
    user_id    uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, factor) REFERENCES core.external_factors (org_id, name) ON DELETE CASCADE
);

CREATE INDEX external_factor_challenges_expiry ON core.external_factor_challenges (expires_at);
CREATE INDEX external_factor_challenges_factor ON core.external_factor_challenges (org_id, factor);
CREATE INDEX external_factor_challenges_user ON core.external_factor_challenges (user_id);

ALTER TABLE core.external_factors ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.external_factors FORCE ROW LEVEL SECURITY;
CREATE POLICY external_factors_org_isolation ON core.external_factors
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

ALTER TABLE core.external_factor_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.external_factor_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY external_factor_challenges_org_isolation ON core.external_factor_challenges
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.external_factors, core.external_factor_challenges TO signari_maintenance;

CREATE TRIGGER external_factors_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.external_factors
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

CREATE TRIGGER external_factor_challenges_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.external_factor_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
