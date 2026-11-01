-- signari:compatible-with-previous
-- 0260_uma_persisted_claims.sql
--
-- A persisted claims token (11.12): UMA's way of not asking a person who they are twice. It works
-- as a refresh token works, with no interaction behind the next token, so it is kept the same way:
-- by hash, bound to the client it was issued to, and read on every use, so that somebody
-- deactivated has nothing left to be persisted. It is issued only to a person who ticked the box
-- at the claims interaction, which §6.2 recommends, and that choice travels on the ticket. It holds
-- no claims, only who they were about, because the claims are this server's own records and those
-- are read when the token is used. An older binary refuses `pct`, as it always did.

ALTER TABLE core.uma_permission_tickets ADD COLUMN persist_claims boolean NOT NULL DEFAULT false;

CREATE TABLE core.uma_persisted_claims (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    client_id  text        NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX uma_persisted_claims_expiry ON core.uma_persisted_claims (expires_at);
CREATE INDEX uma_persisted_claims_org ON core.uma_persisted_claims (org_id);
CREATE INDEX uma_persisted_claims_client ON core.uma_persisted_claims (client_id);
CREATE INDEX uma_persisted_claims_user ON core.uma_persisted_claims (user_id);

ALTER TABLE core.uma_persisted_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.uma_persisted_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY uma_persisted_claims_org_isolation ON core.uma_persisted_claims
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.uma_persisted_claims TO signari_maintenance;

CREATE TRIGGER uma_persisted_claims_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.uma_persisted_claims
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
