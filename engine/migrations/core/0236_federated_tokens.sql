-- signari:compatible-with-previous
--
-- 0236_federated_tokens.sql
--
-- What an upstream provider handed over at sign-in, kept when the operator says to (8.17),
-- for an application that needs to call that provider's own API as the person. Off until a
-- provider says otherwise: these are credentials at somebody else's service, and the safest
-- one to hold is the one not held. Sealed under the root key, one row a person a provider,
-- and gone with the person, the provider or the link.

ALTER TABLE core.identity_providers ADD COLUMN store_tokens boolean NOT NULL DEFAULT false;

CREATE TABLE core.federated_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id uuid        NOT NULL REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    sealed      bytea       NOT NULL,
    expires_at  timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, user_id)
);

CREATE INDEX federated_tokens_user ON core.federated_tokens (user_id);
CREATE INDEX federated_tokens_org ON core.federated_tokens (org_id);

ALTER TABLE core.federated_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.federated_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY federated_tokens_org_isolation ON core.federated_tokens
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.federated_tokens TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER federated_tokens_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.federated_tokens
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
