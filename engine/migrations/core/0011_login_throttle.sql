-- 0011_login_throttle.sql
--
-- Per-account login throttling, replacing a single global bucket.
--
-- The bucket that exists today is one 5/second limiter shared by every user of
-- the deployment, and it fails in both directions at once:
--
--   * ONE attacker exhausts it and nobody can sign in. The rate limiter becomes
--     the denial of service it was meant to prevent.
--   * Guessing spread across many accounts stays under it forever. A thousand
--     accounts tried once each per minute is invisible to a global limit and is
--     exactly what credential stuffing looks like.
--
-- # Why a DELAY and not a lockout
--
-- Hard lockout after N failures hands an attacker a button that disables any
-- account they can name. That is a worse vulnerability than the guessing it
-- prevents, and it is why "your account has been locked" emails are so often the
-- attack rather than the defence.
--
-- So this records failures and imposes an EXPONENTIAL DELAY that decays with
-- time: 4 failures costs seconds, 10 costs minutes, and it clears itself. An
-- attacker gets an unusable guess rate; a real user who mistyped waits once and
-- is never locked out of anything.
--
-- The delay is capped. Uncapped exponential backoff is a permanent lockout with
-- extra steps.

SET search_path = core, public;

ALTER TABLE password_credentials
    ADD COLUMN failed_attempts  integer     NOT NULL DEFAULT 0,
    -- When the counter last moved, so a quiet account decays back to zero
    -- instead of carrying last year's typos forever.
    ADD COLUMN last_failure_at  timestamptz,
    -- Set only when the account is inside a backoff window. Never a flag an
    -- operator has to clear by hand.
    ADD COLUMN throttled_until  timestamptz;

CREATE INDEX password_credentials_throttled_idx
    ON password_credentials (throttled_until)
    WHERE throttled_until IS NOT NULL;
