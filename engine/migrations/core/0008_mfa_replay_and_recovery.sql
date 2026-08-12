-- 0008_mfa_replay_and_recovery.sql
--
-- Two things TOTP needs that the original schema did not model.
--
-- 1. last_used_counter
--
-- A TOTP code is valid for its entire 30-second window. Without recording the
-- counter that was accepted, a code stays spendable for the rest of that window
-- -- so anyone who observes one (over a shoulder, through a phishing proxy, in a
-- screenshot posted to a support ticket) can reuse it. The second factor stops
-- being a second factor at precisely the moment it matters.
--
-- Most implementations skip this. It costs one column and one comparison.
--
-- 2. Recovery codes
--
-- Without them, a lost phone is an unrecoverable account, and the pressure that
-- creates is what produces the real vulnerability: a help desk that resets MFA
-- on request becomes the weakest authentication path in the system.
--
-- Stored as hashes, single-use, and shown exactly once at generation.

SET search_path = core, public;

ALTER TABLE totp_credentials
    -- Strictly advancing. Verification must refuse any counter <= this value.
    ADD COLUMN last_used_counter bigint NOT NULL DEFAULT 0,
    -- Failed attempts since the last success, for per-credential lockout. A
    -- 6-digit code is a million guesses; only rate limiting makes that a real
    -- number, and a global limiter cannot protect one account from a slow,
    -- targeted attack.
    ADD COLUMN failed_attempts   integer NOT NULL DEFAULT 0,
    ADD COLUMN locked_until      timestamptz;

CREATE TABLE recovery_codes (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,

    -- A HASH, never the code. These are password-equivalent: one of them alone
    -- gets you past the second factor. Storing them recoverably would mean a
    -- database read defeats MFA for every user at once.
    --
    -- Argon2id would be the right choice for a user-chosen secret; these are
    -- 128 bits of our own randomness, so a fast hash is sufficient -- there is
    -- no dictionary to attack and no user to protect from their own reuse.
    code_hash    bytea       NOT NULL UNIQUE,

    -- Single use. Recorded rather than deleted so "you have 3 codes left" and
    -- "a recovery code was used at 03:14" are both answerable; a deleted row
    -- can say neither.
    used_at      timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_codes_org_isolation ON recovery_codes
    USING (org_id = core.current_org_id())
    WITH CHECK (org_id = core.current_org_id());
