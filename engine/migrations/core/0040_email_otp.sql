-- Email as a second factor.
--
-- # What this is honestly worth
--
-- Weaker than TOTP and much weaker than a passkey, and it is worth writing that
-- down rather than presenting three factors as equivalent in a dropdown.
--
-- The reason is channel overlap: account recovery here already goes to email, so
-- for most people an attacker with the mailbox can reset the password anyway.
-- Email as a second factor therefore adds little against a compromised mailbox
-- and a great deal against a leaked password alone -- which is the common case,
-- and why it is offered.
--
-- It exists because people ask for it, because it needs no app and no phone, and
-- because the alternative many deployments choose is no second factor at all.
--
-- # Why the code is hashed
--
-- It is a live credential for its lifetime. A table of pending codes in
-- plaintext is a table of ways into accounts, readable from any backup or
-- replica -- the same argument as every other credential here.
--
-- # Why one row per user
--
-- Requesting a new code REPLACES the pending one. Without that, "send another
-- code" would leave every previously issued code valid, and a patient attacker
-- could accumulate guesses against a widening set. One row, one live code.

SET search_path = core, public;

CREATE TABLE core.email_otp_credentials (
    user_id      uuid PRIMARY KEY REFERENCES core.users(id) ON DELETE CASCADE,
    org_id       uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- Enrolment is separate from having a pending code: a user opts in once,
    -- and codes come and go.
    enrolled_at  timestamptz NOT NULL DEFAULT now(),

    -- The address the code goes to, captured at enrolment. NOT read live from
    -- core.users at send time: if an attacker who has stolen a session can
    -- change the account email, reading it live would let them redirect the
    -- second factor to themselves. Changing this address re-enrols.
    address      text NOT NULL CHECK (position('@' in address) > 1),

    -- SHA-256 of the pending code, or NULL when none is outstanding.
    code_hash    bytea CHECK (code_hash IS NULL OR length(code_hash) = 32),
    code_expires_at timestamptz,
    -- Wrong guesses against THIS code. Unlike a device user code, there is
    -- exactly one live code per user here, so an attempt names the record it is
    -- guessing and the counter is meaningful.
    attempts     int NOT NULL DEFAULT 0,
    -- When the last code was sent, so "send me another" cannot be used to flood
    -- somebody's inbox.
    last_sent_at timestamptz,

    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    -- A pending code must have an expiry. Without this a row could carry a code
    -- that never dies, and nothing in the verify path would notice.
    CONSTRAINT email_otp_code_has_expiry
        CHECK ((code_hash IS NULL) = (code_expires_at IS NULL))
);

CREATE INDEX email_otp_org_idx ON core.email_otp_credentials (org_id);

ALTER TABLE core.email_otp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.email_otp_credentials FORCE ROW LEVEL SECURITY;

CREATE POLICY email_otp_org_isolation ON core.email_otp_credentials
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.email_otp_credentials IS
    'Email as a second factor. Codes are stored hashed and there is at most one '
    'live code per user: requesting another replaces it, so "resend" cannot '
    'accumulate valid codes.';

COMMENT ON COLUMN core.email_otp_credentials.address IS
    'Captured at enrolment, not read live from core.users -- otherwise somebody '
    'who could change the account email could redirect the second factor.';
