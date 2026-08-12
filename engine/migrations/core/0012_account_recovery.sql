-- 0012_account_recovery.sql
--
-- Account recovery, built as delay-and-notify.
--
-- # Why not the normal design
--
-- The usual password reset is: prove you can read an email, choose a new
-- password, you are in. That makes the email account a master key -- anyone who
-- controls it, or can read one message in transit, owns every account that trusts
-- it. Recovery is the single most attacked path in any identity system precisely
-- because it is designed to bypass the credential.
--
-- # What this does instead
--
--   1. A request NOTIFIES every channel on the account immediately, including
--      ones the requester did not use. An attacker who took the mailbox cannot
--      stop the user's other addresses from being told.
--   2. It carries a CANCEL link that works instantly and kills the request. The
--      real owner needs one click, no sign-in.
--   3. The reset itself only becomes usable after a DELAY. That window is the
--      whole defence: it converts a silent takeover into something the owner has
--      a chance to notice and stop.
--
-- # The exception, and why it is not a loophole
--
-- Completing a SECOND FACTOR waives the delay. Someone holding the user's
-- authenticator or a recovery code has proven possession of something the
-- mailbox thief does not have, so the delay protects against nothing and only
-- punishes the legitimate user. The waiver is recorded, so "this reset skipped
-- the delay, and here is what was proven" stays answerable.

SET search_path = core, public;

CREATE TABLE recovery_requests (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,

    -- Hashes, never the tokens. These are bearer credentials that reset a
    -- password; storing them recoverably would make a database read equivalent
    -- to owning every account with a pending request.
    token_hash     bytea       NOT NULL UNIQUE,
    -- A SEPARATE token for cancelling. Reusing one value would mean the
    -- notification email -- which must reach an address that may be attacker
    -- controlled -- carries the reset credential itself.
    cancel_hash    bytea       NOT NULL UNIQUE,

    requested_at   timestamptz NOT NULL DEFAULT now(),
    -- When the reset becomes usable. now() for a request that proved a second
    -- factor; requested_at + delay otherwise.
    effective_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,

    cancelled_at   timestamptz,
    consumed_at    timestamptz,
    -- What waived the delay, if anything: 'totp', 'recovery_code', 'passkey'.
    -- Recorded so an investigation can tell a fast reset from a suspicious one.
    waived_by      text,

    CONSTRAINT recovery_effective_within_expiry CHECK (effective_at <= expires_at)
);

-- One live request per user at a time. A second request must supersede the
-- first rather than run alongside it: two pending resets means two live tokens
-- and two independent chances for an attacker.
CREATE UNIQUE INDEX recovery_requests_one_live
    ON recovery_requests (user_id)
    WHERE cancelled_at IS NULL AND consumed_at IS NULL;

CREATE INDEX recovery_requests_expiry_idx ON recovery_requests (expires_at);

ALTER TABLE recovery_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY recovery_requests_org_isolation ON recovery_requests
    USING (org_id = core.current_org_id())
    WITH CHECK (org_id = core.current_org_id());
