-- signari:compatible-with-previous
-- 0253_credential_deferred.sql
--
-- A credential somebody has to look at first (12.08). Some are not issued on the strength of a
-- code alone: a staff card, a licence, whatever a person signs off. So a configuration can defer,
-- and a wallet's request waits here for a decision. What waits is the keys the wallet proved it
-- holds, which are public, so that the proof does not have to be made again, and the hash of the
-- transaction id, which with the token is what fetches the result. An older binary ignores the
-- column and issues at once, so a deferred configuration wants the newer binary everywhere.

ALTER TABLE core.credential_configurations ADD COLUMN deferred boolean NOT NULL DEFAULT false;

CREATE TABLE core.credential_requests (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id          uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    configuration    text        NOT NULL,
    token_jti        text        NOT NULL,
    transaction_hash bytea       NOT NULL UNIQUE,
    holder_keys      jsonb       NOT NULL,
    state            text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied')),
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_requests_org ON core.credential_requests (org_id, created_at);
CREATE INDEX credential_requests_user ON core.credential_requests (user_id);
CREATE INDEX credential_requests_age ON core.credential_requests (created_at);

ALTER TABLE core.credential_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.credential_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_requests_org_isolation ON core.credential_requests
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.credential_requests TO signari_maintenance;

CREATE TRIGGER credential_requests_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.credential_requests
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
