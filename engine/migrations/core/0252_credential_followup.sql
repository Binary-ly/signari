-- signari:compatible-with-previous
-- 0252_credential_followup.sql
--
-- An offer too big for a QR code, and word of what became of a credential (12.08). An offer by
-- value carries everything in the code a person scans, which is more than a phone will read off a
-- screen across a counter; by reference it is a short address, and the offer waits here, sealed,
-- because it holds a pre-authorized code. A notification is the wallet saying a credential was
-- stored, failed or deleted, the only way an issuer ever learns any of that: the row here is what
-- lets the one token that asked say so, and what it said goes to the audit trail.

CREATE TABLE core.credential_offers (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    handle_hash  bytea       NOT NULL UNIQUE,
    offer_sealed bytea       NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_offers_expiry ON core.credential_offers (expires_at);
CREATE INDEX credential_offers_org ON core.credential_offers (org_id);

ALTER TABLE core.credential_offers ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.credential_offers FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_offers_org_isolation ON core.credential_offers
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.credential_offers TO signari_maintenance;

CREATE TRIGGER credential_offers_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.credential_offers
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

CREATE TABLE core.credential_notifications (
    notification_id text        PRIMARY KEY,
    org_id          uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id         uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    token_jti       text        NOT NULL,
    configuration   text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_notifications_age ON core.credential_notifications (created_at);
CREATE INDEX credential_notifications_org ON core.credential_notifications (org_id);
CREATE INDEX credential_notifications_user ON core.credential_notifications (user_id);

ALTER TABLE core.credential_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.credential_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_notifications_org_isolation ON core.credential_notifications
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.credential_notifications TO signari_maintenance;

CREATE TRIGGER credential_notifications_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.credential_notifications
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
