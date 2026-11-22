-- signari:compatible-with-previous
--
-- 0171_otp_parameters.sql
--
-- One-time-code authenticators beyond SHA-1, six digits and thirty seconds
-- (4.12). An organisation chooses what new authenticator apps are enrolled
-- with, and every credential keeps what it was enrolled with, so changing the
-- choice never breaks a phone that already works. A credential is time-based
-- (an app, or a hardware TOTP token) or counter-based (a hardware HOTP token,
-- whose last accepted press is last_used_counter).
--
-- SHA256 is what lets a FIPS 140-only deployment, whose module refuses
-- HMAC-SHA1, enrol authenticator apps at all.
--
-- Compatible with the release before, which reads every credential as SHA-1
-- and time-based: a SHA-256 or counter-based credential is refused there, not
-- accepted, until it is upgraded.
ALTER TABLE core.totp_credentials ADD COLUMN algorithm text NOT NULL DEFAULT 'SHA1'
    CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512'));
ALTER TABLE core.totp_credentials ADD COLUMN kind text NOT NULL DEFAULT 'totp'
    CHECK (kind IN ('totp', 'hotp'));
ALTER TABLE core.totp_enrolments ADD COLUMN algorithm text NOT NULL DEFAULT 'SHA1'
    CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512'));

ALTER TABLE core.organizations ADD COLUMN totp_algorithm text NOT NULL DEFAULT 'SHA1'
    CHECK (totp_algorithm IN ('SHA1', 'SHA256', 'SHA512'));
ALTER TABLE core.organizations ADD COLUMN totp_digits smallint NOT NULL DEFAULT 6
    CHECK (totp_digits IN (6, 8));
ALTER TABLE core.organizations ADD COLUMN totp_period_s smallint NOT NULL DEFAULT 30
    CHECK (totp_period_s IN (30, 60));

COMMENT ON COLUMN core.totp_credentials.algorithm IS
    'The HMAC hash this authenticator computes codes with: SHA1, SHA256 or SHA512.';
COMMENT ON COLUMN core.totp_credentials.kind IS
    'totp (time-based: an app or a hardware TOTP token) or hotp (counter-based: a hardware '
    'token; last_used_counter is its last accepted press). Tokens are assigned with '
    '`signari user assign-otp`.';
COMMENT ON COLUMN core.totp_enrolments.algorithm IS
    'The hash of the authenticator being enrolled, from the organisation''s choice when it began.';
COMMENT ON COLUMN core.organizations.totp_algorithm IS
    'The hash new authenticator apps are enrolled with: SHA1 (the default; every app), SHA256 '
    'or SHA512. Set with `signari instance totp-policy`.';
COMMENT ON COLUMN core.organizations.totp_digits IS
    'Digits in a newly enrolled app''s codes, 6 or 8. Set with `signari instance totp-policy`.';
COMMENT ON COLUMN core.organizations.totp_period_s IS
    'Seconds each newly enrolled app''s code lasts, 30 or 60. Set with `signari instance totp-policy`.';
