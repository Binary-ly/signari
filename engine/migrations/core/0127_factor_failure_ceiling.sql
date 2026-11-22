-- 0127_factor_failure_ceiling.sql
--
-- A second factor that keeps being guessed at is switched off, not just paused.
--
-- # The defect
--
-- Five wrong TOTP codes locked the credential for five minutes, and every
-- failure after the fifth locked it again for five more. That is a pause, and
-- it re-arms forever: about 288 guesses a day, every day, against a code space
-- of a million, from somebody who already holds the password -- the only person
-- who can reach the second-factor step at all. Recovery codes were not counted
-- in any way, so an account whose second factor was not an authenticator app
-- had no ceiling at the code step.
--
-- NIST SP 800-63B §3.2.2: "The verifier SHALL limit consecutive failed
-- authentication attempts using a specific authenticator on a single subscriber
-- account to no more than 100 by disabling that authenticator".
--
-- # The fix
--
-- totp_credentials.disabled_at is set by the failure that reaches the ceiling.
-- A disabled credential is never tried again and still counts as the account's
-- second factor -- switching it off must not downgrade the account to a
-- password -- so the way back is another factor, a recovery code, re-enrolment
-- once signed in, or an operator removing it.
--
-- recovery_code_failures is the same counter for the recovery-code set, which
-- has one row per code and so no single row to carry it. Cleared when a code is
-- accepted (the count is of CONSECUTIVE failures) and when the set is
-- regenerated or removed.

SET search_path = core, public;

ALTER TABLE core.totp_credentials ADD COLUMN disabled_at timestamptz;

COMMENT ON COLUMN core.totp_credentials.disabled_at IS
    'Set when consecutive failures reached the ceiling (NIST SP 800-63B §3.2.2). A disabled credential is never tried, and still counts as a second factor so that disabling it cannot downgrade the account.';

CREATE TABLE core.recovery_code_failures (
    user_id         uuid        PRIMARY KEY REFERENCES core.users(id) ON DELETE CASCADE,
    org_id          uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE RESTRICT,
    failed_attempts integer     NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    disabled_at     timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.recovery_code_failures IS
    'Consecutive failed recovery codes for one account, and when the set was disabled for reaching the ceiling.';

ALTER TABLE core.recovery_code_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.recovery_code_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_code_failures_org_isolation ON core.recovery_code_failures
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
