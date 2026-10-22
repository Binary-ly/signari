-- signari:compatible-with-previous
--
-- 0184_email_sign_in_codes.sql
--
-- A code emailed to the account's address as the first factor (5.16), where
-- an organisation's sign-in flow takes one.
--
-- One live code per person: asking again replaces it. The row is made when the
-- code is asked for and the code itself only when the mail goes out, by the
-- outbox's account-notice delivery, so the page that asked answers the same
-- whether or not the account exists -- no mail is sent while it waits. Only the
-- code's hash is kept. attempts counts wrong codes against this one, and five
-- end it.
--
-- Compatible with the release before, which never reads it.

CREATE TABLE core.email_sign_in_codes (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL UNIQUE REFERENCES core.users(id) ON DELETE CASCADE,
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    code_hash  bytea,
    attempts   integer     NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX email_sign_in_codes_org ON core.email_sign_in_codes (org_id);

ALTER TABLE core.email_sign_in_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.email_sign_in_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY email_sign_in_codes_org_isolation ON core.email_sign_in_codes
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.email_sign_in_codes TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER email_sign_in_codes_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.email_sign_in_codes
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.email_sign_in_codes IS
    'A sign-in code emailed to the account''s address as the first factor, where the sign-in flow takes one.';
