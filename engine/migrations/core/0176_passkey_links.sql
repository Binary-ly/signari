-- signari:compatible-with-previous
--
-- 0176_passkey_links.sql
--
-- An emailed link that lets a person register a passkey without a session
-- (4.24): a new starter with no password, or somebody whose only way in is
-- lost. An administrator issues it; it reaches the account's own email.
--
-- The link is a credential while it lives, so its token is never at rest:
-- the row is created with none, and the outbox worker mints the token when it
-- sends the email, keeping only its hash. Nothing here, in the outbox or in a
-- log holds it. Single use (used_at), short-lived (expires_at), and a new one
-- for the same person ends the one before.
--
-- Compatible with the release before, which never reads it.

CREATE TABLE core.passkey_links (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    -- SHA-256 of the emailed token, set when it is sent. NULL until then.
    token_hash  bytea       UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days')
);

CREATE INDEX passkey_links_user ON core.passkey_links (user_id);
CREATE INDEX passkey_links_org ON core.passkey_links (org_id);

ALTER TABLE core.passkey_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.passkey_links FORCE ROW LEVEL SECURITY;
CREATE POLICY passkey_links_org_isolation ON core.passkey_links
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.passkey_links TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER passkey_links_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.passkey_links
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.passkey_links IS
    'Emailed links to register a passkey without a session. Issued with `signari user passkey-link` '
    'or POST /admin/users/{userID}/passkey-link; single use, at most seven days.';
