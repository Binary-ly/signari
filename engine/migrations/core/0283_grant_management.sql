-- signari:compatible-with-previous
-- 0283_grant_management.sql
--
-- Grant Management: a client that asks can hold on to what a person authorized under an
-- identifier, add to it or replace it later, read it back and revoke it. A grant is made
-- when the tokens are claimed, as the draft has it, so a code nobody redeems leaves none.

CREATE TABLE core.client_grants (
    -- Public, the draft says, and not a secret: what it names is reached with a token.
    grant_id              text        PRIMARY KEY,
    org_id                uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    client_id             text        NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    user_id               uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    scopes                text[]      NOT NULL DEFAULT '{}',
    resources             text[]      NOT NULL DEFAULT '{}',
    authorization_details jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX client_grants_org ON core.client_grants (org_id);
CREATE INDEX client_grants_client ON core.client_grants (client_id);
CREATE INDEX client_grants_user ON core.client_grants (user_id, client_id);
CREATE INDEX client_grants_age ON core.client_grants (updated_at);

ALTER TABLE core.client_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.client_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY client_grants_org_isolation ON core.client_grants
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.client_grants TO signari_maintenance;

CREATE TRIGGER client_grants_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.client_grants
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- What an authorization request asked of a grant, carried on its code to the redemption.
ALTER TABLE core.authorization_codes ADD COLUMN grant_action text;
ALTER TABLE core.authorization_codes ADD COLUMN client_grant text;

-- The lineage a grant's tokens belong to, which is how revoking it reaches them. No
-- foreign key: a family outlives a revoked grant, as the record of why it ended.
ALTER TABLE core.refresh_token_families ADD COLUMN client_grant text;

CREATE INDEX refresh_token_families_client_grant ON core.refresh_token_families (client_grant)
    WHERE client_grant IS NOT NULL;
