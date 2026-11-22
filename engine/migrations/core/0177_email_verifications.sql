-- signari:compatible-with-previous
--
-- 0177_email_verifications.sql
--
-- An address a person must prove before they are signed in (5.01). A row is
-- written when self-sign-up creates an account under a rule with
-- require_verified_email, which defaulted to true and was consulted by nothing,
-- so a rule naming @example.com let anybody claim any address there. While the
-- row exists the sign-in flow's verify_email stage holds the sign-in and sends a
-- code to the address; the right code sets users.email_verified_at and deletes
-- the row. Accounts an administrator made have none and are not held.
--
-- The code is never stored, only its hash, and it proves the address it was
-- sent to: a changed address refuses it. failed_attempts counts wrong codes
-- across codes, so asking for another does not reset the guessing.
--
-- Compatible with the release before, which never reads it.

CREATE TABLE core.email_verifications (
    user_id          uuid        PRIMARY KEY REFERENCES core.users(id) ON DELETE CASCADE,
    org_id           uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- The address the outstanding code was sent to. NULL until one is sent.
    address          text,
    -- SHA-256 of the outstanding code.
    code_hash        bytea,
    code_expires_at  timestamptz,
    -- Wrong guesses at the outstanding code.
    attempts         integer     NOT NULL DEFAULT 0,
    -- Wrong guesses since the row was written, across codes.
    failed_attempts  integer     NOT NULL DEFAULT 0,
    last_sent_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_verifications_org ON core.email_verifications (org_id);

ALTER TABLE core.email_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.email_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY email_verifications_org_isolation ON core.email_verifications
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.email_verifications TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER email_verifications_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.email_verifications
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.email_verifications IS
    'An address a person must prove with a code before the sign-in flow signs them in: written '
    'by self-sign-up under a rule with require_verified_email (`signari signup enable '
    '-verify-email`), deleted when the code comes back.';

-- A completed password reset proves the address its link was sent to, and so
-- ends a verification (the way back for one past its ceiling). Only if the
-- address is still that one: the link went to the address at the time, and an
-- administrator may have changed it since.
ALTER TABLE core.recovery_requests ADD COLUMN sent_to text;

COMMENT ON COLUMN core.recovery_requests.sent_to IS
    'The address the reset link was sent to. A completed reset proves it, if the account still has it.';
