-- signari:compatible-with-previous
--
-- 0231_opaque_access_tokens.sql
--
-- Access tokens that say nothing to whoever holds them (9.16). A client set to opaque gets a
-- random handle, which a resource server takes to the introspection endpoint, instead of a
-- JWT anybody can read. The handle is a reference: this table holds the signed token it
-- stands for, sealed under a key only the handle gives, so every path that verifies a token
-- goes on verifying the same one, revocation by jti holds, and a read of the row gives
-- nobody a working token. token_hash is the handle's, which is not stored either.

ALTER TABLE core.clients ADD COLUMN access_token_format text NOT NULL DEFAULT 'jwt'
    CHECK (access_token_format IN ('jwt', 'opaque'));

CREATE TABLE core.opaque_access_tokens (
    token_hash bytea       PRIMARY KEY CHECK (length(token_hash) = 32),
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    client_id  text        NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    sealed     bytea       NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX opaque_access_tokens_expiry ON core.opaque_access_tokens (expires_at);
CREATE INDEX opaque_access_tokens_client ON core.opaque_access_tokens (client_id);
CREATE INDEX opaque_access_tokens_org ON core.opaque_access_tokens (org_id);

ALTER TABLE core.opaque_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.opaque_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY opaque_access_tokens_org_isolation ON core.opaque_access_tokens
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.opaque_access_tokens TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER opaque_access_tokens_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.opaque_access_tokens
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
