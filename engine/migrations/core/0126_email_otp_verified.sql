-- 0126_email_otp_verified.sql
--
-- An email second factor counts only once its address has been proved, and a
-- new address never displaces a proved one until it is proved too.
--
-- # The defect
--
-- Enrolment had two steps -- send a code to the address, then enter it -- and
-- the first one wrote the row. HasSecondFactor counted any row. So:
--
--   * a typo in the address, abandoned at the code screen, became the account's
--     second factor, and the owner was then challenged for codes sent to an
--     address they do not have;
--   * re-enrolling OVERWROTE the proved address on the send step, so anybody
--     holding a session could point the account's sign-in codes at their own
--     mailbox with one POST, without ever entering a code;
--   * one code slot served both purposes, so a code sent to an address being
--     enrolled could also satisfy a sign-in challenge.
--
-- The comment above HasSecondFactor said email "has no such half state: the row
-- exists only after a code sent to that address was entered". It did not.
--
-- # The fix
--
--   verified_at      set when an enrolment code comes back; only then a factor
--   pending_address  where an enrolment code goes; the proved address is left
--                    alone until the new one is proved
--   code_purpose     a code issued for enrolment cannot sign anybody in, and a
--                    sign-in code cannot complete an enrolment
--
-- Rows that exist today are marked verified. Nothing recorded whether they
-- were, and marking them unverified would silently drop the second factor of
-- everyone who did complete enrolment; the half-enrolled rows keep the status
-- they already had, and no new one can be made.

SET search_path = core, public;

ALTER TABLE core.email_otp_credentials
    ADD COLUMN verified_at     timestamptz,
    ADD COLUMN pending_address text
        CHECK (pending_address IS NULL OR position('@' in pending_address) > 1),
    ADD COLUMN code_purpose    text
        CHECK (code_purpose IN ('signin', 'enrol'));

UPDATE core.email_otp_credentials SET verified_at = created_at;
UPDATE core.email_otp_credentials SET code_purpose = 'signin' WHERE code_hash IS NOT NULL;

ALTER TABLE core.email_otp_credentials
    ADD CONSTRAINT email_otp_code_has_purpose
        CHECK ((code_hash IS NULL) = (code_purpose IS NULL));

COMMENT ON COLUMN core.email_otp_credentials.verified_at IS
    'When a code sent to address was entered. NULL means not yet a second factor; HasSecondFactor requires it.';
COMMENT ON COLUMN core.email_otp_credentials.pending_address IS
    'An address being enrolled. Enrolment codes go here; it replaces address only when one comes back.';
COMMENT ON COLUMN core.email_otp_credentials.code_purpose IS
    'What the outstanding code is for. A sign-in check accepts only signin codes; enrolment accepts only enrol codes.';
