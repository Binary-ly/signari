-- signari:compatible-with-previous
--
-- 0169_org_login_throttle.sql
--
-- The password step's backoff, per organisation (4.06): how many wrong
-- passwords are free before a delay, and the longest the delay grows to. They
-- were constants of three and fifteen minutes. It stays a decaying delay, not
-- a lockout (0011): a lockout is a button that disables any account somebody
-- can name.
--
-- Compatible with the release before, which uses its constants, the defaults
-- here.
ALTER TABLE core.organizations ADD COLUMN login_free_attempts integer NOT NULL DEFAULT 3
    CHECK (login_free_attempts BETWEEN 1 AND 20);
ALTER TABLE core.organizations ADD COLUMN login_max_delay_s integer NOT NULL DEFAULT 900
    CHECK (login_max_delay_s BETWEEN 60 AND 86400);

COMMENT ON COLUMN core.organizations.login_free_attempts IS
    'Wrong passwords for one account before the sign-in delay begins, 1 to 20. Set with '
    '`signari instance login-throttle`.';
COMMENT ON COLUMN core.organizations.login_max_delay_s IS
    'The longest the sign-in delay grows to, in seconds, 60 to 86400. Set with '
    '`signari instance login-throttle`.';
