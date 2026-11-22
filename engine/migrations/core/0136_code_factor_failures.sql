-- 0136_code_factor_failures.sql
--
-- Email and SMS codes stop after a run of wrong guesses, as TOTP and recovery
-- codes do.
--
-- # The defect
--
-- Each code allowed five guesses and a new one could be had every minute or
-- so, with nothing counting across codes. Within the sign-in budgets that came
-- to about 960 guesses a day at a six-digit code, every day, indefinitely --
-- while an authenticator app was switched off after MaxConsecutiveFactorFailures
-- in a row and its holder told.
--
-- # The shape
--
-- failed_attempts counts consecutive wrong guesses against live sign-in codes
-- and a right one resets it. At the ceiling disabled_at is set: no code is sent
-- or accepted until the person proves an address or number again, which clears
-- both. A disabled factor still counts as enrolled, so the sign-in still asks
-- for a second factor; the person uses another one or a recovery code.

SET search_path = core, public;

ALTER TABLE core.email_otp_credentials
    ADD COLUMN failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    ADD COLUMN disabled_at     timestamptz;

ALTER TABLE core.sms_otp_credentials
    ADD COLUMN failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    ADD COLUMN disabled_at     timestamptz;

COMMENT ON COLUMN core.email_otp_credentials.failed_attempts IS
    'Consecutive wrong guesses against live sign-in codes; a right one resets it.';
COMMENT ON COLUMN core.email_otp_credentials.disabled_at IS
    'Set at the consecutive-failure ceiling: no code is sent or accepted until an address is proved again.';
COMMENT ON COLUMN core.sms_otp_credentials.failed_attempts IS
    'Consecutive wrong guesses against live sign-in codes; a right one resets it.';
COMMENT ON COLUMN core.sms_otp_credentials.disabled_at IS
    'Set at the consecutive-failure ceiling: no code is sent or accepted until a number is proved again.';
