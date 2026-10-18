-- 0135_sms_pending_number.sql
--
-- A new SMS number is held apart from the one that works, as 0126 did for
-- email.
--
-- # The defect
--
-- Sending an enrolment code to another number rewrote `number` and cleared
-- `verified_at` in the same statement. One POST from any live session
-- therefore switched the person's SMS factor off -- HasSecondFactor stopped
-- counting it -- and pointed the account at a number the session's holder
-- chose, without a code being entered anywhere. And one function verified
-- every code, so a code sent for enrolment completed a sign-in and the
-- reverse.
--
-- # The shape
--
-- `number` is the proved number and stays the factor. `pending_number` is the
-- one being enrolled; enrolment codes go to it, and it replaces `number` only
-- when one comes back. `code_purpose` says which kind the outstanding code is,
-- and each check accepts only its own.

SET search_path = core, public;

ALTER TABLE core.sms_otp_credentials
    ADD COLUMN pending_number text,
    ADD COLUMN code_purpose   text
        CHECK (code_purpose IN ('signin', 'enrol'));

-- An unverified row is an enrolment in progress, and its number is the one
-- being proved.
UPDATE core.sms_otp_credentials SET pending_number = number WHERE verified_at IS NULL;

-- A code already out was issued by the one function there was: for an
-- unverified number it can only have been an enrolment code.
UPDATE core.sms_otp_credentials
   SET code_purpose = CASE WHEN verified_at IS NULL THEN 'enrol' ELSE 'signin' END
 WHERE code_hash IS NOT NULL;

ALTER TABLE core.sms_otp_credentials
    ADD CONSTRAINT sms_otp_code_has_purpose
        CHECK ((code_hash IS NULL) = (code_purpose IS NULL));

COMMENT ON COLUMN core.sms_otp_credentials.pending_number IS
    'A number being enrolled. Enrolment codes go here; it replaces number only when one comes back.';
COMMENT ON COLUMN core.sms_otp_credentials.code_purpose IS
    'What the outstanding code is for. A sign-in check accepts only signin codes; enrolment accepts only enrol codes.';
