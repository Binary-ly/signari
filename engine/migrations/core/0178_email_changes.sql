-- signari:compatible-with-previous
--
-- 0178_email_changes.sql
--
-- A person changing their own address (5.06). The account keeps its address
-- until a code sent to the new one comes back, so a typo, or somebody holding a
-- session who names a mailbox of theirs and cannot read the code, changes
-- nothing; when it does come back the new address is verified by that proof and
-- the old one is told.
--
-- One pending change per person. The code is never stored, only its hash;
-- failed_attempts counts wrong codes across codes for the same new address, so
-- asking for another does not reset the guessing.
--
-- Compatible with the release before, which never reads it.

CREATE TABLE core.email_changes (
    user_id          uuid        PRIMARY KEY REFERENCES core.users(id) ON DELETE CASCADE,
    org_id           uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    new_address      text        NOT NULL,
    code_hash        bytea       NOT NULL,
    code_expires_at  timestamptz NOT NULL,
    attempts         integer     NOT NULL DEFAULT 0,
    failed_attempts  integer     NOT NULL DEFAULT 0,
    last_sent_at     timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_changes_org ON core.email_changes (org_id);

ALTER TABLE core.email_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.email_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY email_changes_org_isolation ON core.email_changes
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.email_changes TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER email_changes_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.email_changes
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.email_changes IS
    'An address a person asked to move their account to, at /account/email, held until a code sent '
    'to it comes back.';
